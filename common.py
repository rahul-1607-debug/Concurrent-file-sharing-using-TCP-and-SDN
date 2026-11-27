"""Shared protocol helpers.

Wire format (every control message):
    [4-byte big-endian length][JSON payload]
File data is sent as raw bytes right after the JSON header that announces
its size, so large files are streamed in chunks and never fully loaded in RAM.
"""
import json
import struct

SERVICE_PORT = 9000
CHUNK = 64 * 1024            # 64 KB streaming chunk
MAX_HEADER = 1_000_000       # refuse absurdly large JSON headers


def send_msg(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_exact(sock, n):
    """TCP is a byte stream: recv() may return fewer bytes than asked."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(CHUNK, n - len(buf)))
        if not chunk:
            raise ConnectionError("connection closed by peer")
        buf.extend(chunk)
    return bytes(buf)


def recv_msg(sock):
    (n,) = struct.unpack("!I", recv_exact(sock, 4))
    if n > MAX_HEADER:
        raise ValueError("header too large")
    return json.loads(recv_exact(sock, n))
