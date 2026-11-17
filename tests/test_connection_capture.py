"""Ensure capture verification cannot pass for empty or leaking traffic."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('analyze_capture', ROOT/'tools/connection-lab/analyze_capture.py')
CAPTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPTURE)


def frame(index, protocol, payload):
    cooked = struct.pack('!HHIHBB8s', 0x0800, 0, index, 1, 0, 6, b'\0'*8)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = protocol
    if protocol == 17: payload = struct.pack('!HHHH', 4443, 50000, len(payload)+8, 0) + payload
    else: payload = b'\0'*20 + payload
    return cooked + ip + payload


class CaptureTests(unittest.TestCase):
    def analyze(self, packets):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'test.pcap'
            with path.open('wb') as stream:
                stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 276))
                for packet in packets:
                    stream.write(struct.pack('<IIII', 1, 0, len(packet), len(packet)))
                    stream.write(packet)
            return CAPTURE.analyze(path, {'2':'eth0', '3':'bplab0'})

    def tun(self):
        return [frame(3, 6, b'GET /probe HTTP/1.1\r\nX-Lab-Marker: '+CAPTURE.MARKER), frame(3, 6, CAPTURE.MARKER+b': synthetic test response')]

    def test_accepts_controlled_tun_request_response_and_opaque_udp(self):
        result = self.analyze([frame(2, 17, b'opaque-ciphertext')]+self.tun())
        self.assertEqual(result['result'], 'passed')
        self.assertEqual(result['cleartext_wire_markers'], 0)

    def test_rejects_plaintext_marker_in_outer_udp(self):
        with self.assertRaisesRegex(ValueError, 'leaked'):
            self.analyze([frame(2, 17, CAPTURE.MARKER)]+self.tun())

    def test_rejects_missing_tunnel_evidence(self):
        with self.assertRaisesRegex(ValueError, 'HTTP'):
            self.analyze([frame(2, 17, b'opaque')])

    def test_rejects_missing_outer_udp(self):
        with self.assertRaisesRegex(ValueError, 'No outer'):
            self.analyze(self.tun())

    def test_rejects_empty_capture(self):
        with self.assertRaisesRegex(ValueError, 'No outer'):
            self.analyze([])


if __name__ == '__main__': unittest.main()
