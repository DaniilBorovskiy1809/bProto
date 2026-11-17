import asyncio
import importlib.util
import pathlib
import socket
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("quic_bridge", pathlib.Path(__file__).resolve().parents[1] / "tools/quic-bridge/bridge.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
from aioquic.asyncio import connect, serve
from aioquic.h3.events import DataReceived, HeadersReceived


class QuicTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"),
            "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
            check=True, capture_output=True)
        self.cfg = dict(cert=str(root / "cert.pem"), key=str(root / "key.pem"),
            ca=str(root / "cert.pem"), hostname="localhost", token="a"*64,
            fallback_body=b"Operator site", upstream_host="127.0.0.1")
        class Echo(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport
            def datagram_received(self, data, addr):
                self.transport.sendto(data, addr)
        self.udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
        self.cfg["upstream_port"] = self.udp.get_extra_info("sockname")[1]
        self.server = await serve("127.0.0.1", 0, configuration=bridge.configuration(self.cfg, False),
            retry=True, create_protocol=lambda *a, **kw: bridge.Carrier(*a, cfg=self.cfg, **kw))
        self.port = self.server._transport.get_extra_info("sockname")[1]

    async def asyncTearDown(self):
        self.server.close()
        self.udp.close()
        await asyncio.sleep(.05)
        self.tmp.cleanup()

    def connection(self, cfg=None, protocol=bridge.Carrier):
        return connect("127.0.0.1", self.port,
            configuration=bridge.configuration(cfg or self.cfg, True), create_protocol=protocol)

    async def test_authenticated_roundtrip_and_retry(self):
        async with self.connection() as client:
            await client.authenticate(self.cfg)
            self.assertEqual(client._quic._version, 1)
            self.assertEqual(client._quic._retry_count, 1)
            for packet in [b"hello", bytes(range(256))*8, b"last"]:
                client.send_packet(packet)
                self.assertEqual(await asyncio.wait_for(client.received.get(), 2), packet)

    async def test_local_udp_client_bridge(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        cfg = dict(self.cfg, server_host="127.0.0.1", server_port=self.port, local_port=port)
        task = asyncio.create_task(bridge.client(cfg))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(("127.0.0.1", 0))
        loop = asyncio.get_running_loop()
        try:
            for _ in range(30):
                if task.done():
                    task.result()
                await loop.sock_sendto(sock, b"native-datagram", ("127.0.0.1", port))
                try:
                    packet, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), .1)
                    self.assertEqual(packet, b"native-datagram")
                    break
                except asyncio.TimeoutError:
                    continue
            else:
                self.fail("local UDP carrier did not become ready")
        finally:
            sock.close()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_wrong_token_rejected(self):
        async with self.connection() as client:
            with self.assertRaises(ValueError):
                await client.authenticate(dict(self.cfg, token="b"*64))

    async def test_wrong_hostname_rejected(self):
        with self.assertRaises(ConnectionError):
            async with self.connection(dict(self.cfg, hostname="wrong.example")):
                self.fail("wrong hostname accepted")

    async def test_http3_get_serves_owned_site(self):
        class Browser(bridge.Carrier):
            def quic_event_received(self, event):
                for item in self.http.handle_event(event):
                    if isinstance(item, HeadersReceived):
                        self.status = dict(item.headers)[b":status"]
                    if isinstance(item, DataReceived):
                        self.received.put_nowait(item.data)
        async with self.connection(protocol=Browser) as client:
            stream = client._quic.get_next_available_stream_id()
            client.http.send_headers(stream, [(b":method", b"GET"), (b":scheme", b"https"),
                (b":authority", b"localhost"), (b":path", b"/")], end_stream=True)
            client.transmit()
            self.assertEqual(await asyncio.wait_for(client.received.get(), 2), b"Operator site")
            self.assertEqual(client.status, b"200")


class FramingTests(unittest.TestCase):
    def test_fragmented_and_coalesced_frames(self):
        decoder = bridge.Decoder()
        wire = bridge.encode(b"abc") + bridge.encode(b"def")
        output = []
        for byte in wire:
            output.extend(decoder.feed(bytes([byte])))
        self.assertEqual(output, [b"abc", b"def"])
        self.assertEqual(decoder.buffer, b"")

    def test_invalid_lengths(self):
        for data in [b"\x00\x00", b"\xff\xff"]:
            with self.assertRaises(ValueError):
                bridge.Decoder().feed(data)
        for data in [b"", bytes(2049)]:
            with self.assertRaises(ValueError):
                bridge.encode(data)
