#!/usr/bin/env python3
"""Owned-domain WSS reverse-proxy carrier; not arbitrary domain fronting."""
import argparse
import asyncio
import hmac
import json
import os
from pathlib import Path
import socket
import ssl
from urllib.parse import urlsplit
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve

MAX_PACKET = 2048


async def duplex(first, second):
    tasks = [asyncio.create_task(first), asyncio.create_task(second)]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def validate_url(url):
    parsed = urlsplit(url)
    if parsed.scheme != "wss" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("An owned wss:// URL without credentials is required")
    return url


def authorize(cfg):
    def process(connection, request):
        values = request.headers.get_all("Authorization")
        expected = "Bearer " + cfg["token"]
        if request.path != cfg.get("path", "/bproto") or len(values) != 1 or not hmac.compare_digest(values[0].encode(), expected.encode()):
            return connection.respond(200, cfg["fallback_body"])
        return None
    return process


async def upstream(websocket, cfg):
    loop = asyncio.get_running_loop()
    addresses = await loop.getaddrinfo(cfg["upstream_host"], cfg["upstream_port"], type=socket.SOCK_DGRAM)
    family, kind, proto, _, address = addresses[0]
    sock = socket.socket(family, kind, proto)
    sock.setblocking(False)
    try:
        await loop.sock_connect(sock, address)

        async def receive():
            async for packet in websocket:
                if not isinstance(packet, bytes) or not 0 < len(packet) <= MAX_PACKET:
                    await websocket.close(code=1008, reason="Invalid datagram")
                    return
                await loop.sock_sendall(sock, packet)

        async def send():
            while True:
                packet = await loop.sock_recv(sock, MAX_PACKET + 1)
                if not 0 < len(packet) <= MAX_PACKET:
                    await websocket.close(code=1009, reason="Datagram too large")
                    return
                await websocket.send(packet)

        await duplex(receive(), send())
    finally:
        sock.close()


async def client(cfg):
    context = ssl.create_default_context(cafile=cfg.get("ca"))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    async with connect(validate_url(cfg["url"]), ssl=context,
        additional_headers={"Authorization": "Bearer " + cfg["token"]},
        compression=None, max_size=MAX_PACKET, max_queue=16, write_limit=16384,
        open_timeout=10, proxy=None) as websocket:
        local = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        local.setblocking(False)
        local.bind(("127.0.0.1", cfg["local_port"]))
        loop = asyncio.get_running_loop()
        peer = None
        try:
            async def send():
                nonlocal peer
                while True:
                    packet, source = await loop.sock_recvfrom(local, MAX_PACKET + 1)
                    if peer is None:
                        peer = source
                    if source == peer and 0 < len(packet) <= MAX_PACKET:
                        await websocket.send(packet)

            async def receive():
                async for packet in websocket:
                    if not isinstance(packet, bytes) or not packet:
                        raise ValueError("Invalid server datagram")
                    if peer is not None:
                        await loop.sock_sendto(local, packet, peer)
            await duplex(send(), receive())
        finally:
            local.close()


async def server(cfg):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cfg["cert"], cfg["key"])
    return await serve(lambda ws: upstream(ws, cfg),
        cfg.get("listen_host", "127.0.0.1"), cfg["listen_port"],
        ssl=context, process_request=authorize(cfg), compression=None,
        max_size=MAX_PACKET, max_queue=16, write_limit=16384)


async def run(mode, cfg):
    cfg["token"] = os.environ[cfg.get("token_env", "BPROTO_BRIDGE_TOKEN")]
    if len(cfg["token"]) != 64 or any(c not in "0123456789abcdefABCDEF" for c in cfg["token"]):
        raise ValueError("Token must be 64 hex characters")
    if mode == "client":
        await client(cfg)
    else:
        cfg["fallback_body"] = Path(cfg["fallback_file"]).read_text()
        if len(cfg["fallback_body"].encode()) > 65536:
            raise ValueError("Fallback page too large")
        async with await server(cfg):
            await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["client", "server"])
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    asyncio.run(run(args.mode, json.loads(args.config.read_text())))
