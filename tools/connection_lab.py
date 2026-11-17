#!/usr/bin/env python3
"""Private, reproducible bProto connection lab. Python 3.11+, no extra packages."""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def endpoint(value):
    try:
        host, port = value.rsplit(":", 1)
        host = str(ipaddress.ip_address(host.strip("[]")))
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError()
        return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    except ValueError as error:
        raise argparse.ArgumentTypeError("Use an IP literal and port 1..65535, e.g. 127.0.0.1:4443") from error


def server_config(psk, tag, listen, nat=None):
    network = '\n'.join(['[tun]', 'name = "bplab0"', 'address = "10.66.0.1"', 'netmask = "255.255.255.0"', 'mtu = 1280'])
    if nat:
        network += '\nnat_interface = ' + json.dumps(nat)
    return f'''listen_addr = {json.dumps(listen)}
tag_key = "{tag}"
[donor]
sni = "localhost"
{network}
[admin]
listen_addr = "127.0.0.1:0"
token = "{secrets.token_hex(32)}"
[[users]]
id = 1
psk = "{psk}"
'''


def client_config(psk, tag, address, timeout="3s"):
    return f'''server = {json.dumps(address)}
user_id = 1
psk = "{psk}"
tag_key = "{tag}"
mtu = 1280
handshake_timeout = "{timeout}"
[donor]
sni = "localhost"
'''


def initialize(directory, listen, address, nat=None):
    # A new directory prevents accidental key rotation or clobbering existing files.
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    psk, tag = secrets.token_hex(32), secrets.token_hex(32)
    write_private(directory / "server.toml", server_config(psk, tag, listen, nat))
    write_private(directory / "client.toml", client_config(psk, tag, address))
    write_private(directory / "lab.json", json.dumps({"schema": 1, "listen": listen, "endpoint": address, "mode": "handshake unless server --datapath is used"}, indent=2))


def write_private(path, text):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(text)


def binary(directory, name):
    path = directory / name
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"Missing executable {path}; run the lab build command first")
    return str(path)


def run_client(args, config, seconds=1):
    return subprocess.run([binary(args.bin_dir, "bproto"), "--config", str(config), "connect", "--seconds", str(seconds)], capture_output=True, text=True, timeout=seconds + 12)


def smoke(args):
    server = binary(args.bin_dir, "vpn-server")
    client = binary(args.bin_dir, "bproto")
    with tempfile.TemporaryDirectory(prefix="bproto-smoke-") as parent:
        directory = Path(parent) / "state"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            address = f"127.0.0.1:{sock.getsockname()[1]}"
        initialize(directory, address, address)
        logfile = directory / "server.log"
        results = {"mode": "native-loopback-no-tun", "endpoint": address, "checks": {}}
        with logfile.open("w") as log:
            process = subprocess.Popen([server, "--config", str(directory / "server.toml")], stdout=log, stderr=subprocess.STDOUT, env=dict(os.environ, RUST_LOG="info"))
            try:
                deadline = time.monotonic() + 10
                while "listener up" not in logfile.read_text():
                    if process.poll() is not None:
                        raise RuntimeError("Server exited before readiness: " + logfile.read_text()[-2000:])
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Server readiness timeout")
                    time.sleep(.05)
                for name in ["server", "client"]:
                    command = [server, "--check-config", "--config"] if name == "server" else [client, "--config"]
                    command.append(str(directory / f"{name}.toml"))
                    if name == "client": command.append("check")
                    subprocess.run(command, capture_output=True, check=True, timeout=10)
                good = run_client(args, directory / "client.toml")
                if good.returncode != 0 or "tunnel up:" not in good.stdout or "10.66.0.2" not in good.stdout:
                    raise RuntimeError("Positive handshake failed: " + good.stdout + good.stderr)
                results["checks"]["authenticated_handshake_and_lease"] = "passed"
                data = tomllib.loads((directory / "client.toml").read_text())
                wrong = directory / "wrong.toml"
                altered = ("00" if data["psk"][:2] != "00" else "ff") + data["psk"][2:]
                write_private(wrong, client_config(altered, data["tag_key"], address, "1s"))
                subprocess.run([client, "--config", str(wrong), "check"], capture_output=True, check=True, timeout=10)
                rejected = run_client(args, wrong)
                if rejected.returncode == 0 or "handshake" not in (rejected.stdout + rejected.stderr).lower() or process.poll() is not None:
                    raise RuntimeError("Wrong-PSK negative check did not produce the expected live-server handshake failure")
                results["checks"]["wrong_psk_handshake_failure"] = "passed"
                results["limitations"] = ["No kernel TUN or NAT tested", "No Android device tested", "No Internet forwarding tested"]
            finally:
                process.send_signal(signal.SIGTERM) if process.poll() is None else None
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
        print(json.dumps(results, indent=2))


def doctor():
    capability = 0
    if Path('/proc/self/status').exists():
        for line in Path('/proc/self/status').read_text().splitlines():
            if line.startswith('CapEff:'): capability = int(line.split()[1], 16)
    print(json.dumps({"tun_device": Path('/dev/net/tun').exists(), "cap_net_admin": bool(capability & (1 << 12)), "docker": bool(shutil.which('docker')), "iproute2": bool(shutil.which('ip')), "python": sys.version.split()[0], "note": "Handshake mode does not require TUN. Datapath requires TUN plus network capabilities in its own isolated namespace."}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / '.connection-lab')
    parser.add_argument('--bin-dir', type=Path, default=ROOT / 'target/debug')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('doctor')
    commands.add_parser('build')
    commands.add_parser('smoke')
    init = commands.add_parser('init')
    init.add_argument('--listen', type=endpoint, default='127.0.0.1:4443')
    init.add_argument('--endpoint', type=endpoint, default='127.0.0.1:4443')
    init.add_argument('--nat-interface')
    serve = commands.add_parser('server')
    serve.add_argument('--datapath', action='store_true')
    check = commands.add_parser('check')
    check.add_argument('--seconds', type=int, default=5, choices=range(1, 61), metavar='1..60')
    uri = commands.add_parser('uri', help='Print SECRET Android key to your private terminal')
    uri.add_argument('--endpoint', type=endpoint, help='Override endpoint for an emulator or phone; does not rebind the server')
    args = parser.parse_args()
    args.directory = args.directory.resolve()
    args.bin_dir = args.bin_dir.resolve()
    if args.command == 'doctor': doctor()
    elif args.command == 'build':
        subprocess.run(['cargo', 'build', '--locked', '--target-dir', str(ROOT / 'target'), '-p', 'vpn-server', '-p', 'vpn-cli'], cwd=ROOT, check=True)
    elif args.command == 'init':
        if args.nat_interface and (len(args.nat_interface) > 15 or not all(c.isascii() and (c.isalnum() or c in '_.-') for c in args.nat_interface)):
            parser.error('Invalid Linux interface name')
        initialize(args.directory, args.listen, args.endpoint, args.nat_interface)
        print(f'Created private lab at {args.directory}; keys were not printed. Default mode checks handshake, not Internet forwarding.')
    elif args.command == 'server':
        if args.datapath and not Path('/dev/net/tun').exists():
            raise RuntimeError('Datapath unavailable: /dev/net/tun is missing; use an isolated TUN-capable VM/container')
        command = [binary(args.bin_dir, 'vpn-server'), '--config', str(args.directory / 'server.toml')]
        if args.datapath: command.append('--datapath')
        os.execve(command[0], command, dict(os.environ, RUST_LOG='info'))
    elif args.command == 'check':
        result = run_client(args, args.directory / 'client.toml', args.seconds)
        print(result.stdout, end=''); print(result.stderr, end='', file=sys.stderr)
        return result.returncode
    elif args.command == 'uri':
        config = tomllib.loads((args.directory / 'client.toml').read_text())
        body = dict(v=1, server=args.endpoint or config['server'], uid=config['user_id'], sni=config['donor']['sni'], psk=config['psk'], tag_key=config['tag_key'], fp='chrome112', label='Connection lab')
        print('bproto://import/' + base64.urlsafe_b64encode(json.dumps(body).encode()).decode().rstrip('='))
    elif args.command == 'smoke': smoke(args)
    return 0


if __name__ == '__main__':
    try: sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f'connection-lab: {error}', file=sys.stderr); sys.exit(1)
