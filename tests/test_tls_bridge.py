import asyncio
import importlib.util
import pathlib
import ssl
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("bridge", pathlib.Path(__file__).resolve().parents[1] / "tools/tls-bridge/bridge.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"),
                        "-days", "1", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
        (root / "index.html").write_text("Local test site")
        self.cfg = dict(cert=str(root / "cert.pem"), key=str(root / "key.pem"),
                        ca=str(root / "cert.pem"), hostname="localhost", token="a" * 64,
                        fallback_file=str(root / "index.html"), upstream_host="127.0.0.1")
        class Echo(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport
            def datagram_received(self, data, address):
                self.transport.sendto(data, address)
        self.udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
        self.cfg["upstream_port"] = self.udp.get_extra_info("sockname")[1]
        self.server = await asyncio.start_server(lambda r, w: bridge.serve_connection(r, w, self.cfg),
                                                "127.0.0.1", 0, ssl=bridge.context(self.cfg, True), limit=8192)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self.udp.close()
        self.tmp.cleanup()

    async def connect(self, hostname="localhost"):
        return await asyncio.open_connection("127.0.0.1", self.port, ssl=bridge.context(self.cfg), server_hostname=hostname)

    async def test_tls13_datagram_roundtrip(self):
        reader, writer = await self.connect()
        self.assertEqual(writer.get_extra_info("ssl_object").version(), "TLSv1.3")
        writer.write(("CONNECT /bproto HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + self.cfg["token"] + "\r\n\r\n").encode())
        await writer.drain()
        self.assertEqual(await reader.readuntil(b"\r\n\r\n"), b"HTTP/1.1 200 Connection Established\r\n\r\n")
        for data in [b"x", bytes(range(256)) * 5, b"end"]:
            await bridge.write_packet(writer, data)
            self.assertEqual(await asyncio.wait_for(bridge.read_packet(reader), 2), data)
        await bridge.close(writer)

    async def test_probe_gets_site(self):
        reader, writer = await self.connect()
        writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        self.assertIn(b"Local test site", await asyncio.wait_for(reader.read(), 2))
        await bridge.close(writer)

    async def test_wrong_hostname_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            await self.connect("wrong.example")

    async def test_invalid_length_rejected(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\xff\xff")
        with self.assertRaises(ValueError):
            await bridge.read_packet(reader)
