"""Observe the real QUIC ClientHello and prove required ECH doesn't downgrade."""
import asyncio
from pathlib import Path
import struct
import time
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from aioquic import tls
import test_rust_quic as fixture


def config_list():
    public = X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    name = b"localhost"
    contents = (b"\x01" + struct.pack("!H", 0x20) + struct.pack("!H", len(public)) + public
                + b"\x00\x04\x00\x01\x00\x01" + b"\x00" + bytes([len(name)]) + name + b"\x00\x00")
    config = b"\xfe\x0d" + struct.pack("!H", len(contents)) + contents
    return struct.pack("!H", len(config)) + config


class EchTests(fixture.RustQuicTests):
    async def attempt(self, data, expires):
        path = Path(self.tmp.name) / "ech.bin"
        path.write_bytes(data)
        return await self.native(hostname="private.example", extra_env={
            "BPROTO_ECH_CONFIG": str(path), "BPROTO_ECH_EXPIRES": str(expires)})

    async def test_required_ech_hides_inner_and_rejects_plain_server(self):
        observed = []
        parser = tls.pull_client_hello
        def observe(buffer):
            raw = bytes(buffer.data_slice(0, buffer.capacity))
            hello = parser(buffer)
            observed.append((hello, raw))
            return hello
        with patch.object(tls, "pull_client_hello", observe):
            process = await self.attempt(config_list(), int(time.time()) + 3600)
            out, err = await asyncio.wait_for(process.communicate(), 12)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(out, b"", "A rejected ECH connection must not expose a local carrier")
        self.assertTrue(observed, err.decode())
        for hello, raw in observed:
            self.assertGreater(len(raw), 100)
            self.assertIn(b"localhost", raw)
            self.assertEqual(hello.server_name, "localhost")
            self.assertNotIn(b"private.example", raw)
            self.assertIn(0xfe0d, [kind for kind, _ in hello.other_extensions])
        self.assertIn(b"serverrejectedencryptedclienthello", err.lower())

    async def test_expired_ech_fails_before_client_hello(self):
        parser = tls.pull_client_hello
        with patch.object(tls, "pull_client_hello", wraps=parser) as observed:
            process = await self.attempt(config_list(), int(time.time()) - 1)
            out, err = await asyncio.wait_for(process.communicate(), 12)
        self.assertEqual(observed.call_count, 0)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(out, b"")
        self.assertIn(b"expired", err)

    async def test_malformed_ech_never_sends_cleartext_fallback(self):
        parser = tls.pull_client_hello
        with patch.object(tls, "pull_client_hello", wraps=parser) as observed:
            process = await self.attempt(b"not-an-ech-config", int(time.time()) + 3600)
            out, _ = await asyncio.wait_for(process.communicate(), 12)
        self.assertEqual(observed.call_count, 0)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(out, b"")
