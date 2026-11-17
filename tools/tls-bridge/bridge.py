#!/usr/bin/env python3
"""Experimental TLS 1.3 carrier for native bProto UDP datagrams.

One authenticated TLS connection maps to one connected upstream UDP socket.
This is not HTTP/2, browser impersonation, or automatic CDN fronting.
"""
import argparse
import asyncio
import hmac
import json
import socket
import ssl
import struct
from pathlib import Path

MAX_PACKET = 2048


def context(config, server=False):
    if server:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(config['cert'], config['key'])
    else:
        ctx = ssl.create_default_context(cafile=config.get('ca'))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(['http/1.1'])
    return ctx


async def read_packet(reader):
    size, = struct.unpack('!H', await reader.readexactly(2))
    if not 0 < size <= MAX_PACKET:
        raise ValueError('invalid datagram length')
    return await reader.readexactly(size)


async def write_packet(writer, data):
    if not 0 < len(data) <= MAX_PACKET:
        raise ValueError('invalid datagram length')
    writer.write(struct.pack('!H', len(data)) + data)
    await writer.drain()


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


async def close(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 3)
    except (OSError, asyncio.TimeoutError):
        pass


async def serve_connection(reader, writer, cfg):
    upstream = None
    try:
        request = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
        expected = (
            'CONNECT /bproto HTTP/1.1\r\n'
            f'Host: {cfg["hostname"]}\r\n'
            f'Authorization: Bearer {cfg["token"]}\r\n\r\n'
        ).encode('ascii')
        if not hmac.compare_digest(request, expected):
            # Serve a local operator-owned page. Never impersonate a donor's
            # certificate or proxy arbitrary client-controlled destinations.
            body = Path(cfg['fallback_file']).read_bytes()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n'
                         + f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n'.encode()
                         + body)
            await writer.drain()
            return
        loop = asyncio.get_running_loop()
        addresses = await loop.getaddrinfo(cfg['upstream_host'], cfg['upstream_port'], type=socket.SOCK_DGRAM)
        family, kind, proto, _, address = addresses[0]
        upstream = socket.socket(family, kind, proto)
        upstream.setblocking(False)
        await loop.sock_connect(upstream, address)
        writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        await writer.drain()

        async def to_udp():
            while True:
                packet = await asyncio.wait_for(read_packet(reader), 90)
                await loop.sock_sendall(upstream, packet)

        async def to_tls():
            while True:
                packet = await loop.sock_recv(upstream, MAX_PACKET + 1)
                await write_packet(writer, packet)

        await duplex(to_udp(), to_tls())
    except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
        pass
    finally:
        if upstream is not None:
            upstream.close()
        await close(writer)


async def client(cfg):
    # TLS verification and hostname verification are always enabled.
    reader, writer = await asyncio.wait_for(asyncio.open_connection(
        cfg['server_host'], cfg['server_port'], ssl=context(cfg),
        server_hostname=cfg['hostname'], limit=8192), 10)
    local = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local.setblocking(False)
    try:
        writer.write(('CONNECT /bproto HTTP/1.1\r\n'
                      f'Host: {cfg["hostname"]}\r\n'
                      f'Authorization: Bearer {cfg["token"]}\r\n\r\n').encode('ascii'))
        await writer.drain()
        response = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
        if response != b'HTTP/1.1 200 Connection Established\r\n\r\n':
            raise ValueError('bridge authentication failed')
        # Loopback only; one native client per bridge process.
        local.bind(('127.0.0.1', cfg['local_port']))
        loop = asyncio.get_running_loop()
        peer = None

        async def to_tls():
            nonlocal peer
            while True:
                packet, source = await loop.sock_recvfrom(local, MAX_PACKET + 1)
                if peer is None:
                    peer = source
                if source == peer:
                    await write_packet(writer, packet)

        async def to_udp():
            while True:
                packet = await read_packet(reader)
                if peer is not None:
                    await loop.sock_sendto(local, packet, peer)

        await duplex(to_tls(), to_udp())
    finally:
        local.close()
        await close(writer)


async def run(mode, cfg):
    if len(cfg['token']) < 32 or not cfg['token'].isascii() or any(c.isspace() for c in cfg['token']):
        raise ValueError('token must contain at least 32 non-whitespace ASCII characters')
    if not cfg['hostname'] or any(c.isspace() for c in cfg['hostname']):
        raise ValueError('invalid hostname')
    if mode == 'client':
        await client(cfg)
    else:
        server = await asyncio.start_server(
            lambda r, w: serve_connection(r, w, cfg), cfg.get('listen_host', '127.0.0.1'),
            cfg['listen_port'], ssl=context(cfg, True), limit=8192,
            ssl_handshake_timeout=5)
        async with server:
            await server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['server', 'client'])
    parser.add_argument('config', type=Path)
    args = parser.parse_args()
    asyncio.run(run(args.mode, json.loads(args.config.read_text())))
