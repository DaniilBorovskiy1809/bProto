"""Real bProto binaries through TLS and HTTP3 carriers; no kernel TUN required."""
import asyncio
import importlib.util
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


tls = module("tls_carrier", "tools/tls-bridge/bridge.py")
quic = module("quic_carrier", "tools/quic-bridge/bridge.py")
wss = module("wss_carrier", "tools/fronting/bridge.py")
lab = module("connection_lab", "tools/connection_lab.py")


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class NativeCarrierTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.binary_dir = Path(os.environ.get("BPROTO_TEST_BIN_DIR", ROOT / "target/debug"))
        for name in ["vpn-server", "bproto"]:
            if not (self.binary_dir / name).is_file():
                self.fail(f"Build native binaries before running: missing {name}")
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.psk, self.tag = secrets.token_hex(32), secrets.token_hex(32)
        self.upstream = free_udp_port()
        server_config = self.root / "server.toml"
        server_config.write_text(lab.server_config(self.psk, self.tag, f"127.0.0.1:{self.upstream}"))
        self.native = await asyncio.create_subprocess_exec(str(self.binary_dir / "vpn-server"),
            "--config", str(server_config), stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(self.root / "key.pem"), "-out", str(self.root / "cert.pem"),
            "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
            check=True, capture_output=True)
        (self.root / "index.html").write_text("Operator site")
        self.cfg = dict(cert=str(self.root / "cert.pem"), key=str(self.root / "key.pem"),
            ca=str(self.root / "cert.pem"), hostname="localhost", token=secrets.token_hex(32),
            fallback_file=str(self.root / "index.html"), fallback_body=b"Operator site",
            upstream_host="127.0.0.1", upstream_port=self.upstream, server_host="127.0.0.1")

    async def asyncTearDown(self):
        if self.native.returncode is None:
            self.native.terminate()
            try:
                await asyncio.wait_for(self.native.wait(), 5)
            except asyncio.TimeoutError:
                self.native.kill()
                await self.native.wait()
        self.tmp.cleanup()

    async def exercise(self, transport, wrong_psk=False):
        if transport == "tls":
            server = await asyncio.start_server(
                lambda r, w: tls.serve_connection(r, w, self.cfg), "127.0.0.1", 0,
                ssl=tls.context(self.cfg, True), limit=8192)
            port = server.sockets[0].getsockname()[1]
            start = tls.client
        elif transport == "wss":
            server = await wss.server(dict(self.cfg, listen_port=0, fallback_body="Operator site"))
            port = server.sockets[0].getsockname()[1]
            start = lambda cfg: wss.client(dict(cfg, url=f"wss://localhost:{port}/bproto"))
        else:
            server = await quic.serve("127.0.0.1", 0,
                configuration=quic.configuration(self.cfg, False), retry=True,
                create_protocol=lambda *a, **kw: quic.Carrier(*a, cfg=self.cfg, **kw))
            port = server._transport.get_extra_info("sockname")[1]
            start = quic.client
        local_port = free_udp_port()
        task = asyncio.create_task(start(dict(self.cfg, server_port=port, local_port=local_port)))
        native_client = None
        try:
            # Wait for the carrier to bind its local UDP socket; don't send
            # readiness datagrams, which would pin the wrong client source.
            for _ in range(100):
                if task.done():
                    task.result()
                    self.fail("carrier exited")
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    try:
                        probe.bind(("127.0.0.1", local_port))
                    except OSError:
                        break
                await asyncio.sleep(.02)
            else:
                self.fail("carrier readiness timeout")
            config = self.root / "client.toml"
            config.write_text(lab.client_config(secrets.token_hex(32) if wrong_psk else self.psk,
                self.tag, f"127.0.0.1:{local_port}", "2s"))
            native_client = await asyncio.create_subprocess_exec(str(self.binary_dir / "bproto"),
                "--config", str(config), "connect", "--seconds", "1",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(native_client.communicate(), 10)
            output = (out + err).decode()
            if wrong_psk:
                self.assertNotEqual(native_client.returncode, 0)
                self.assertIn("handshake", output.lower())
            else:
                self.assertEqual(native_client.returncode, 0, output)
                self.assertIn("tunnel up:", output)
                self.assertIn("10.66.0.2", output)
            self.assertIsNone(self.native.returncode)
        finally:
            if native_client is not None and native_client.returncode is None:
                native_client.kill()
                await native_client.wait()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            server.close()
            if transport in ("tls", "wss"):
                await server.wait_closed()

    async def test_tls_native_handshake(self):
        await self.exercise("tls")

    async def test_tls_wrong_native_psk(self):
        await self.exercise("tls", wrong_psk=True)

    async def test_http3_native_handshake(self):
        await self.exercise("quic")

    async def test_http3_wrong_native_psk(self):
        await self.exercise("quic", wrong_psk=True)

    async def test_wss_native_handshake(self):
        await self.exercise("wss")

    async def test_wss_wrong_native_psk(self):
        await self.exercise("wss", wrong_psk=True)

    async def test_wss_rejects_wrong_carrier_token(self):
        import ssl
        from websockets.asyncio.client import connect
        from websockets.exceptions import InvalidStatus
        server = await wss.server(dict(self.cfg, listen_port=0, fallback_body="Operator site"))
        port = server.sockets[0].getsockname()[1]
        try:
            with self.assertRaises(InvalidStatus) as rejected:
                async with connect(f"wss://localhost:{port}/bproto",
                    ssl=ssl.create_default_context(cafile=self.cfg["ca"]),
                    additional_headers={"Authorization": "Bearer wrong"}, proxy=None):
                    self.fail("Wrong token accepted")
            self.assertEqual(rejected.exception.response.status_code, 200)
            self.assertIn(b"Operator site", rejected.exception.response.body)
        finally:
            server.close()
            await server.wait_closed()

    async def test_wss_rejects_wrong_hostname(self):
        import ssl
        server = await wss.server(dict(self.cfg, listen_port=0, fallback_body="Operator site"))
        port = server.sockets[0].getsockname()[1]
        try:
            with self.assertRaises(ssl.SSLCertVerificationError):
                await wss.client(dict(self.cfg, url=f"wss://127.0.0.1:{port}/bproto", local_port=0))
        finally:
            server.close()
            await server.wait_closed()

    async def test_wss_rejects_text_datagrams(self):
        import ssl
        from websockets.asyncio.client import connect
        from websockets.exceptions import ConnectionClosed
        server = await wss.server(dict(self.cfg, listen_port=0, fallback_body="Operator site"))
        port = server.sockets[0].getsockname()[1]
        try:
            async with connect(f"wss://localhost:{port}/bproto",
                ssl=ssl.create_default_context(cafile=self.cfg["ca"]),
                additional_headers={"Authorization": "Bearer " + self.cfg["token"]}, proxy=None) as ws:
                await ws.send("not a binary datagram")
                with self.assertRaises(ConnectionClosed):
                    await ws.recv()
                self.assertEqual(ws.close_code, 1008)
        finally:
            server.close()
            await server.wait_closed()

    async def test_wss_rejects_insecure_urls(self):
        for url in ["ws://localhost/bproto", "wss://user:password@host/bproto", "wss://host/#fragment"]:
            with self.assertRaises(ValueError):
                wss.validate_url(url)
