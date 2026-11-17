import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("agent", Path(__file__).resolve().parents[1] / "tools/config-agent/agent.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.target = Path(self.tmp.name) / "config.json"
        self.target.write_text('{"old":true}')
        self.agent = module.Agent({"target": str(self.target)})
        self.calls = []
        self.agent.command = lambda name, candidate=None: self.calls.append(name)

    def test_applies_and_preserves_previous(self):
        self.assertEqual(self.agent.apply({"version": 1, "config": {"new": True}})["status"], "applied")
        self.assertEqual(json.loads(self.target.read_text()), {"new": True})
        self.assertEqual(json.loads(self.agent.backup.read_text()), {"old": True})
        self.assertEqual(self.calls, ["validate", "reload", "health"])
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)

    def test_failed_health_restores_previous(self):
        def command(name, candidate=None):
            if name == "health" and "new" in self.target.read_text():
                raise subprocess.CalledProcessError(1, ["health"])
        self.agent.command = command
        result = self.agent.apply({"version": 1, "config": {"new": True}})
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(json.loads(self.target.read_text()), {"old": True})

    def test_invalid_version_leaves_file_untouched(self):
        with self.assertRaises(ValueError):
            self.agent.apply({"version": 2, "config": {}})
        self.assertEqual(self.calls, [])
        self.assertEqual(json.loads(self.target.read_text()), {"old": True})

    def test_validation_failure_leaves_file_untouched(self):
        def fail(*args):
            raise subprocess.CalledProcessError(1, ["validate"])
        self.agent.command = fail
        with self.assertRaises(subprocess.CalledProcessError):
            self.agent.apply({"version": 1, "config": {}})
        self.assertEqual(json.loads(self.target.read_text()), {"old": True})

    def test_explicit_rollback(self):
        self.agent.apply({"version": 1, "config": {"new": True}})
        self.assertEqual(self.agent.rollback()["status"], "applied")
        self.assertEqual(json.loads(self.target.read_text()), {"old": True})

    def test_reports_failed_recovery(self):
        def fail(name, candidate=None):
            if name == "health":
                raise subprocess.CalledProcessError(1, ["health"])
        self.agent.command = fail
        self.assertEqual(self.agent.apply({"version": 1, "config": {}})["status"], "rollback_failed")

class MutualTlsTests(unittest.TestCase):
    def test_client_certificate_required_and_authenticated_apply(self):
        import ssl
        import threading
        import http.client
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                check=True, capture_output=True)
            target = root / "service.json"
            target.write_text("{}")
            settings = dict(target=str(target), cert=str(cert), key=str(key), client_ca=str(cert))
            agent = module.Agent(settings)
            agent.command = lambda *args: None
            server = module.HTTPServer(("127.0.0.1", 0), module.handler(agent))
            server.socket = module.tls_context(settings).wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                context = ssl.create_default_context(cafile=str(cert))
                client = http.client.HTTPSConnection("localhost", server.server_port, context=context, timeout=3)
                try:
                    with self.assertRaises((ssl.SSLError, OSError)):
                        client.request("POST", "/health", body="{}")
                        client.getresponse().read()
                finally:
                    client.close()
                context.load_cert_chain(str(cert), str(key))
                client = http.client.HTTPSConnection("localhost", server.server_port, context=context, timeout=3)
                try:
                    client.request("POST", "/apply", body=json.dumps({"version": 1, "config": {"test": True}}),
                                   headers={"Content-Type": "application/json"})
                    response = client.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(response.read())["status"], "applied")
                    self.assertEqual(json.loads(target.read_text()), {"test": True})
                finally:
                    client.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
