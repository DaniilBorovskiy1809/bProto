"""Runs networking only inside the Compose service's own network namespace."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import tomllib

from connection_lab import client_config, server_config


def main():
    config = tomllib.loads(Path('/lab/client.toml').read_text())
    if sys.argv[1] == 'server':
        data = server_config(config['psk'], config['tag_key'], '0.0.0.0:4443', 'eth0')
        Path('/tmp/lab-server.toml').write_text(data)
        os.chmod('/tmp/lab-server.toml', 0o600)
        os.execv('/usr/local/bin/vpn-server', ['vpn-server', '--config', '/tmp/lab-server.toml', '--datapath'])
    address = socket.gethostbyname('server') + ':4443'
    Path('/tmp/lab-client.toml').write_text(client_config(config['psk'], config['tag_key'], address, '3s'))
    os.chmod('/tmp/lab-client.toml', 0o600)
    # Server initialization can take longer than container creation.
    for attempt in range(5):
        result = subprocess.run(['bproto', '--config', '/tmp/lab-client.toml', 'connect', '--seconds', '1'], capture_output=True, timeout=15)
        if result.returncode == 0: break
        time.sleep(1)
    else: raise RuntimeError('Server never completed a readiness handshake')
    with tempfile.TemporaryFile(mode='w+') as log:
        process = subprocess.Popen(['bproto', '--config', '/tmp/lab-client.toml', 'up', '--iface', 'bplabc0'], stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    log.seek(0); raise RuntimeError('Client exited: ' + log.read()[-2000:])
                link = subprocess.run(['ip', '-j', 'address', 'show', 'dev', 'bplabc0'], capture_output=True, text=True)
                if link.returncode == 0 and any(entry.get('addr_info') for entry in json.loads(link.stdout)): break
                time.sleep(.1)
            else: raise RuntimeError('Client TUN readiness timed out')
            result = subprocess.run(['ping', '-n', '-I', 'bplabc0', '-c', '3', '-W', '3', '10.66.0.1'], capture_output=True, text=True, timeout=15, env=dict(os.environ, LC_ALL='C'))
            if result.returncode != 0 or '3 received' not in result.stdout:
                raise RuntimeError('Tunnel ping failed: ' + result.stdout + result.stderr)
            print(json.dumps({'mode': 'isolated-kernel-tun', 'ping_target': '10.66.0.1', 'received': 3, 'result': 'passed', 'internet_forwarding': 'not tested'}, indent=2))
        finally:
            if process.poll() is None: process.send_signal(signal.SIGINT)
            try: process.wait(timeout=8)
            except subprocess.TimeoutExpired: process.kill(); process.wait()


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(f'connection-lab container: {error}', file=sys.stderr); sys.exit(1)
