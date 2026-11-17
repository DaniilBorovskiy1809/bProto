"""Runs networking only inside the Compose service's own network namespace."""
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
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


MARKER = b"BPROTO_LAB_PROBE"


def main():
    if sys.argv[1] == 'http':
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != '/probe': self.send_error(404); return
                body = MARKER + b": synthetic test response\n"
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args): pass
        HTTPServer(('0.0.0.0', 8088), Handler).serve_forever()
        return
    if sys.argv[1] == 'capture':
        destination = Path('/captures')
        ready = destination / 'ready'
        ready.unlink(missing_ok=True)
        deadline = time.monotonic() + 20
        while subprocess.run(['ip', 'link', 'show', 'bplab0'], capture_output=True).returncode != 0:
            if time.monotonic() > deadline: raise RuntimeError('Server TUN unavailable for capture')
            time.sleep(.1)
        interfaces = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show']))
        (destination / 'interfaces.json').write_text(json.dumps({str(item['ifindex']): item['ifname'] for item in interfaces}))
        process = subprocess.Popen(['tcpdump', '--immediate-mode', '-Z', 'root', '-i', 'any', '-U', '-p', '-n', '-s', '0', '-w', '/captures/server.pcap', 'udp port 4443 or icmp or tcp port 8088'], stderr=subprocess.PIPE, text=True)
        signal.signal(signal.SIGTERM, lambda *_: process.terminate())
        signal.signal(signal.SIGINT, lambda *_: process.terminate())
        diagnostics = []
        for line in process.stderr:
            diagnostics.append(line)
            if 'listening on' in line:
                ready.write_text('ready')
                break
        if not ready.exists(): raise RuntimeError('tcpdump failed to start: ' + ''.join(diagnostics)[-2000:])
        process.wait()
        return
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
            result = subprocess.run(['ping', '-n', '-I', 'bplabc0', '-c', '3', '-W', '3', '-s', '96', '-p', MARKER.hex(), '10.66.0.1'], capture_output=True, text=True, timeout=15, env=dict(os.environ, LC_ALL='C'))
            if result.returncode != 0 or '3 received' not in result.stdout:
                raise RuntimeError('Tunnel ping failed: ' + result.stdout + result.stderr)
            connection = http.client.HTTPConnection('10.66.0.1', 8088, timeout=5)
            connection.request('GET', '/probe', headers={'X-Lab-Marker': MARKER.decode()})
            response = connection.getresponse()
            body = response.read(4096)
            connection.close()
            if response.status != 200 or MARKER not in body: raise RuntimeError('HTTP through tunnel did not return the expected synthetic response')
            # Allow the capture sidecar to consume final packets before Compose stops it.
            time.sleep(1)
            print(json.dumps({'http_through_tun': 'passed', 'mode': 'isolated-kernel-tun', 'ping_target': '10.66.0.1', 'received': 3, 'result': 'passed', 'internet_forwarding': 'not tested'}, indent=2))
        finally:
            if process.poll() is None: process.send_signal(signal.SIGINT)
            try: process.wait(timeout=8)
            except subprocess.TimeoutExpired: process.kill(); process.wait()


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(f'connection-lab container: {error}', file=sys.stderr); sys.exit(1)
