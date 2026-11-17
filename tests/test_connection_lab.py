"""Connection-lab contracts that never modify host networking."""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('connection_lab', ROOT / 'tools/connection_lab.py')
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


class ConnectionLabTests(unittest.TestCase):
    def test_matching_private_configurations(self):
        with tempfile.TemporaryDirectory() as parent:
            path = Path(parent) / 'lab'
            LAB.initialize(path, '127.0.0.1:4443', '127.0.0.1:4443')
            server = tomllib.loads((path / 'server.toml').read_text())
            client = tomllib.loads((path / 'client.toml').read_text())
            self.assertEqual(server['users'][0]['psk'], client['psk'])
            self.assertEqual(server['tag_key'], client['tag_key'])
            self.assertEqual(len(client['psk']), 64)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            for file in path.iterdir(): self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)

    def test_initialization_does_not_rotate_existing_keys(self):
        with tempfile.TemporaryDirectory() as parent:
            path = Path(parent) / 'lab'
            LAB.initialize(path, '127.0.0.1:4443', '127.0.0.1:4443')
            before = (path / 'client.toml').read_bytes()
            with self.assertRaises(FileExistsError): LAB.initialize(path, '127.0.0.1:4443', '127.0.0.1:4443')
            self.assertEqual(before, (path / 'client.toml').read_bytes())

    def test_endpoints_require_ip_literals_and_valid_ports(self):
        self.assertEqual(LAB.endpoint('[::1]:4443'), '[::1]:4443')
        for value in ['example.org:443', '127.0.0.1:0', '127.0.0.1:65536', '127.0.0.1', 'https://example.org']:
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError): LAB.endpoint(value)

    def test_android_uri_has_matching_credentials_and_explicit_endpoint(self):
        with tempfile.TemporaryDirectory() as parent:
            path = Path(parent) / 'lab'
            LAB.initialize(path, '127.0.0.1:4443', '127.0.0.1:4443')
            result = subprocess.run([sys.executable, str(ROOT / 'tools/connection_lab.py'), '--directory', str(path), 'uri', '--endpoint', '10.0.2.2:4443'], check=True, capture_output=True, text=True)
            value = result.stdout.strip().removeprefix('bproto://import/')
            decoded = json.loads(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)))
            client = tomllib.loads((path / 'client.toml').read_text())
            self.assertEqual(decoded['psk'], client['psk'])
            self.assertEqual(decoded['tag_key'], client['tag_key'])
            self.assertEqual(decoded['server'], '10.0.2.2:4443')


if __name__ == '__main__': unittest.main()
