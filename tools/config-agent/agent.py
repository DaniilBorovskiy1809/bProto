#!/usr/bin/env python3
"""Single-service configuration agent. Operator-defined commands, mTLS only."""
import argparse
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer


def atomic_write(path, data):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".bproto-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Agent:
    def __init__(self, settings):
        self.settings = settings
        self.target = Path(settings["target"])
        self.backup = self.target.with_name(self.target.name + ".previous")

    def command(self, name, candidate=None):
        command = self.settings[name]
        if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
            raise ValueError("operator command must be an argument array")
        env = dict(os.environ)
        if candidate:
            env["BPROTO_CANDIDATE_CONFIG"] = str(candidate)
        subprocess.run(command, check=True, timeout=15, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, env=env)

    def apply(self, document):
        if not isinstance(document, dict) or document.get("version") != 1 or set(document) != {"version", "config"}:
            raise ValueError("expected schema version 1 and config")
        config = document["config"]
        if not isinstance(config, dict):
            raise ValueError("config must be an object")
        # Validate against the actual service using a private staged file.
        data = json.dumps(config, sort_keys=True).encode()
        if len(data) > 65536:
            raise ValueError("config too large")
        if not self.target.is_file():
            raise ValueError("initial configuration must be provisioned by operator")
        old = self.target.read_bytes()
        fd, staged = tempfile.mkstemp(dir=self.target.parent, prefix=".validate-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            self.command("validate", staged)
        finally:
            os.unlink(staged)
        atomic_write(self.backup, old)
        atomic_write(self.target, data)
        try:
            self.command("reload")
            self.command("health")
        except (OSError, subprocess.SubprocessError):
            atomic_write(self.target, old)
            try:
                self.command("reload")
                self.command("health")
            except (OSError, subprocess.SubprocessError):
                return {"status": "rollback_failed", "error": "Previous file restored; service health failed"}
            return {"status": "rolled_back", "error": "New configuration failed health validation"}
        return {"status": "applied"}

    def rollback(self):
        if not self.backup.is_file():
            raise ValueError("no previous configuration")
        return self.apply({"version": 1, "config": json.loads(self.backup.read_bytes())})


def handler(agent):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *_):
            pass  # Do not log request bodies, secrets, or client-controlled text.

        def do_POST(self):
            try:
                if self.headers.get("Transfer-Encoding"):
                    raise ValueError("chunked requests are not accepted")
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 <= size <= 65536:
                    raise ValueError("request too large")
                body = self.rfile.read(size)
                if len(body) != size:
                    raise ValueError("incomplete body")
                if self.path == "/apply":
                    result = agent.apply(json.loads(body))
                elif self.path == "/rollback":
                    result = agent.rollback()
                elif self.path == "/health":
                    agent.command("health")
                    result = {"status": "healthy"}
                else:
                    raise ValueError("unknown action")
                code = 200 if result["status"] in ("applied", "healthy") else 409
            except (ValueError, OSError, subprocess.SubprocessError):
                code, result = 400, {"error": "Configuration rejected or service operation failed"}
            data = json.dumps(result).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
    return Handler


def tls_context(settings):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(settings["cert"], settings["key"])
    context.load_verify_locations(settings["client_ca"])
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("settings", type=Path)
    settings = json.loads(parser.parse_args().settings.read_text())
    context = tls_context(settings)
    # Serial requests intentionally serialize mutations; no concurrent rollbacks.
    server = HTTPServer((settings.get("listen_host", "127.0.0.1"), settings["listen_port"]), handler(Agent(settings)))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
