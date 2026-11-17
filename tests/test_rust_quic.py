"""Rust h3/quinn against the independently implemented aioquic server."""
import asyncio
import os
from pathlib import Path
import socket
import subprocess
import test_quic_bridge as fixture


class RustQuicTests(fixture.QuicTests):
    async def native(self, token=None, hostname="localhost", extra_env=None):
        binary = Path(os.environ.get("BPROTO_H3_BINARY", "target/debug/examples/h3_bridge")).resolve()
        self.assertTrue(binary.is_file(), "Build the h3_bridge example first")
        der = Path(self.tmp.name) / "ca.der"
        subprocess.run(["openssl", "x509", "-in", self.cfg["ca"], "-outform", "DER", "-out", str(der)],
                       check=True, capture_output=True)
        return await asyncio.create_subprocess_exec(str(binary), f"127.0.0.1:{self.port}", hostname, str(der),
            env=dict(os.environ, BPROTO_BRIDGE_TOKEN=token or self.cfg["token"], **(extra_env or {})),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

    async def test_rust_bidirectional_datagrams(self):
        process = await self.native()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(("127.0.0.1", 0))
        try:
            line = await asyncio.wait_for(process.stdout.readline(), 12)
            if not line:
                self.fail((await process.stderr.read()).decode())
            port = int(line)
            loop = asyncio.get_running_loop()
            for packet in [b"hello", bytes(range(256)) * 8, b"last"]:
                await loop.sock_sendto(sock, packet, ("127.0.0.1", port))
                reply, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 2049), 3)
                self.assertEqual(reply, packet)
        finally:
            sock.close()
            if process.returncode is None:
                process.terminate()
            await asyncio.wait_for(process.wait(), 3)

    async def test_rust_rejects_wrong_token(self):
        process = await self.native(token="b"*64)
        out, err = await asyncio.wait_for(process.communicate(), 12)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(out, b"")
        self.assertIn(b"authentication rejected", err)

    async def test_rust_rejects_wrong_hostname(self):
        process = await self.native(hostname="wrong.example")
        out, _ = await asyncio.wait_for(process.communicate(), 12)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(out, b"")

    async def test_native_bproto_through_rust_h3(self):
        from test_native_carriers import lab, free_udp_port
        import secrets
        root = Path(self.tmp.name)
        binary_dir = Path(os.environ.get("BPROTO_TEST_BIN_DIR", "target/debug")).resolve()
        psk, tag = secrets.token_hex(32), secrets.token_hex(32)
        port = free_udp_port()
        self.cfg["upstream_port"] = port
        server_config = root / "native-server.toml"
        server_config.write_text(lab.server_config(psk, tag, f"127.0.0.1:{port}"))
        native = await asyncio.create_subprocess_exec(str(binary_dir / "vpn-server"),
            "--config", str(server_config), stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL)
        carrier = None
        client = None
        try:
            carrier = await self.native()
            line = await asyncio.wait_for(carrier.stdout.readline(), 12)
            self.assertTrue(line, "Rust carrier failed to start")
            config = root / "native-client.toml"
            config.write_text(lab.client_config(psk, tag, f"127.0.0.1:{int(line)}"))
            client = await asyncio.create_subprocess_exec(str(binary_dir / "bproto"), "--config",
                str(config), "connect", "--seconds", "1",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(client.communicate(), 10)
            self.assertEqual(client.returncode, 0, (out + err).decode())
            self.assertIn(b"10.66.0.2", out)
        finally:
            for process in [client, carrier, native]:
                if process is not None:
                    if process.returncode is None:
                        process.kill()
                    await process.wait()
