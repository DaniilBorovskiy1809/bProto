#!/usr/bin/env python3
"""bProto datagrams inside HTTP/3 DATA frames over QUIC v1."""
import argparse
import asyncio
import hmac
import json
import os
import struct
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamReset
from aioquic.quic.packet import QuicProtocolVersion

MAX_PACKET = 2048


def encode(packet):
    if not 0 < len(packet) <= MAX_PACKET:
        raise ValueError('invalid datagram length')
    return struct.pack('!H', len(packet)) + packet


class Decoder:
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        packets = []
        while len(self.buffer) >= 2:
            size, = struct.unpack('!H', self.buffer[:2])
            if not 0 < size <= MAX_PACKET:
                raise ValueError('invalid datagram length')
            if len(self.buffer) < size + 2:
                break
            packets.append(bytes(self.buffer[2:size + 2]))
            del self.buffer[:size + 2]
        return packets


def configuration(cfg, client):
    result = QuicConfiguration(is_client=client, alpn_protocols=['h3'],
                               supported_versions=[QuicProtocolVersion.VERSION_1],
                               idle_timeout=60, max_data=65536, max_stream_data=16384)
    if client:
        result.server_name = cfg['hostname']
        if cfg.get('ca'):
            result.load_verify_locations(cfg['ca'])
    else:
        result.load_cert_chain(cfg['cert'], cfg['key'])
    return result


class Carrier(QuicConnectionProtocol):
    def __init__(self, *args, cfg=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.cfg = cfg
        self.active = None
        self.decoder = Decoder()
        self.udp = None
        self.opening = None
        self.ready = asyncio.get_running_loop().create_future()
        self.received = asyncio.Queue(maxsize=128)

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self.cleanup()
            if not self.ready.done():
                self.ready.set_result(False)
            if self.received.full():
                self.received.get_nowait()
            self.received.put_nowait(None)
            return
        if isinstance(event, StreamReset) and event.stream_id == self.active:
            self.close(error_code=0x100)
            self.cleanup()
            return
        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived):
                if self.cfg is not None:
                    self.accept(item)
                elif item.stream_id == self.active and not self.ready.done():
                    headers = dict(item.headers)
                    self.ready.set_result(headers.get(b':status') == b'200'
                        and headers.get(b'content-type') == b'application/octet-stream'
                        and not item.stream_ended)
            elif isinstance(item, DataReceived) and item.stream_id == self.active:
                if self.cfg is None and (not self.ready.done() or not self.ready.result()):
                    continue
                try:
                    for packet in self.decoder.feed(item.data):
                        if self.cfg is not None:
                            if self.udp is None:
                                raise ValueError('data before acceptance')
                            self.udp.sendto(packet)
                        else:
                            self.received.put_nowait(packet)
                    if item.stream_ended:
                        self.close()
                        self.cleanup()
                except (ValueError, asyncio.QueueFull):
                    self.close(error_code=0x100, reason_phrase='invalid carrier stream')
                    self.cleanup()

    def accept(self, event):
        headers = dict(event.headers)
        expected = ('Bearer ' + self.cfg['token']).encode('ascii')
        authenticated = (
            len(headers) == len(event.headers)
            and headers.get(b':method') == b'POST'
            and headers.get(b':path') == b'/bproto'
            and headers.get(b':authority') == self.cfg['hostname'].encode('ascii')
            and hmac.compare_digest(headers.get(b'authorization', b''), expected)
            and not event.stream_ended
        )
        if not authenticated:
            body = self.cfg['fallback_body']
            self.http.send_headers(event.stream_id, [(b':status', b'200'),
                (b'content-type', b'text/html; charset=utf-8'),
                (b'content-length', str(len(body)).encode())])
            self.http.send_data(event.stream_id, body, end_stream=True)
            self.transmit()
            return
        if self.active is not None:
            self.http.send_headers(event.stream_id, [(b':status', b'429')], end_stream=True)
            self.transmit()
            return
        self.active = event.stream_id
        self.opening = asyncio.create_task(self.open_udp())

    async def open_udp(self):
        owner = self

        class Upstream(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                try:
                    owner.send_packet(data)
                except ValueError:
                    owner.close(error_code=0x100)

        try:
            self.udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                Upstream, remote_addr=(self.cfg['upstream_host'], self.cfg['upstream_port']))
            self.http.send_headers(self.active, [(b':status', b'200'),
                (b'content-type', b'application/octet-stream')])
            self.transmit()
        except OSError:
            self.close(error_code=0x102, reason_phrase='upstream unavailable')

    async def authenticate(self, cfg):
        self.active = self._quic.get_next_available_stream_id()
        self.http.send_headers(self.active, [(b':method', b'POST'), (b':scheme', b'https'),
            (b':authority', cfg['hostname'].encode('ascii')), (b':path', b'/bproto'),
            (b'authorization', ('Bearer ' + cfg['token']).encode('ascii'))])
        self.transmit()
        if not await asyncio.wait_for(self.ready, 10):
            raise ValueError('carrier authentication failed')

    def send_packet(self, data):
        self.http.send_data(self.active, encode(data), end_stream=False)
        self.transmit()

    def cleanup(self):
        if self.opening is not None:
            self.opening.cancel()
        if self.udp is not None:
            self.udp.close()


async def client(cfg):
    async with connect(cfg['server_host'], cfg['server_port'],
                       configuration=configuration(cfg, True), create_protocol=Carrier) as protocol:
        await protocol.authenticate(cfg)
        peer = None

        class Local(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                nonlocal peer
                if peer is None:
                    peer = addr
                if addr == peer and 0 < len(data) <= MAX_PACKET:
                    protocol.send_packet(data)

        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            Local, local_addr=('127.0.0.1', cfg['local_port']))
        try:
            while (packet := await protocol.received.get()) is not None:
                if peer is not None:
                    transport.sendto(packet, peer)
        finally:
            transport.close()


async def run(mode, cfg):
    # Secret values come from the process environment, not versioned config.
    cfg['token'] = os.environ[cfg.get('token_env', 'BPROTO_BRIDGE_TOKEN')]
    if len(cfg['token']) != 64 or any(c not in '0123456789abcdefABCDEF' for c in cfg['token']):
        raise ValueError('token must be 64 hex characters')
    if mode == 'client':
        await client(cfg)
    else:
        cfg['fallback_body'] = Path(cfg['fallback_file']).read_bytes()
        if len(cfg['fallback_body']) > 65536:
            raise ValueError('fallback page exceeds 64 KiB')
        server = await serve(cfg.get('listen_host', '127.0.0.1'), cfg['listen_port'],
            configuration=configuration(cfg, False), retry=True,
            create_protocol=lambda *a, **kw: Carrier(*a, cfg=cfg, **kw))
        try:
            await asyncio.Future()
        finally:
            server.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['server', 'client'])
    parser.add_argument('config', type=Path)
    args = parser.parse_args()
    asyncio.run(run(args.mode, json.loads(args.config.read_text())))
