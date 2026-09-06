#!/usr/bin/env python3
"""
MR-UDP server daemon.

Matches the wire protocol implemented by the Android client
(app/src/main/java/com/sshproxy/vpn/MrUdpClient.kt) exactly:

  - Transport : single UDP socket.
  - Encryption: AES-256-GCM. Key = SHA-256(password). Each packet is
                sent as  nonce(12 bytes) || ciphertext+tag.
  - Plaintext frame (before encryption):
        type   : 1 byte  (unsigned)
        id     : 4 bytes (signed, big-endian)   -- stream / request id
        seq    : 4 bytes (signed, big-endian)   -- sequence number
        len    : 4 bytes (unsigned, big-endian) -- payload length (informational)
        payload: <len> bytes
  - Message types:
        HELLO=1, HELLO_OK=2, OPEN=3, OPEN_OK=4, DATA=5,
        ACK=6, CLOSE=7, UDP=8, PING=9
  - HELLO payload   : utf8(username) + utf8(password)   (each length-prefixed,
                       2-byte big-endian length + utf8 bytes)
  - OPEN payload    : utf8(host) + raw 2-byte big-endian port
  - OPEN_OK payload : single byte, 1 = accepted, 0 = failed
  - DATA/ACK        : payload is the raw chunk (<=1100 bytes) for DATA,
                       empty for ACK. Every DATA received must be ACKed
                       with the same id/seq.
  - CLOSE           : closes/removes the stream with that id.
  - UDP payload (client->server) : utf8(host) + raw 2-byte port + raw data
    UDP payload (server->client) : raw response data only (no host/port,
                       the client already knows it from its own request).
  - PING            : echoed back as-is (id=0, same seq).

Deployed by mrudp_manager.py as a systemd service:
    ExecStart=/usr/bin/python3 /root/mr_udp_server.py --port $MR_PORT
    EnvironmentFile provides MR_USER and MR_PASS.

Requirements:
    pip3 install cryptography --break-system-packages
"""

import argparse
import asyncio
import os
import struct
import sys
import time

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("[FATAL] Missing dependency. Run: pip3 install cryptography --break-system-packages",
          file=sys.stderr)
    sys.exit(1)

import hashlib

# ---- protocol constants (must mirror MrUdpClient.kt) ----------------------
HELLO, HELLO_OK, OPEN, OPEN_OK, DATA, ACK, CLOSE, UDP, PING = range(1, 10)

MAX_PAYLOAD = 1100
ACK_TIMEOUT = 1.8          # seconds, mirrors ACK_TIMEOUT_MS
MAX_RETRIES = 5
SESSION_IDLE_TIMEOUT = 300  # drop a client session after 5 min of silence
UDP_ASSOC_TIMEOUT = 5       # seconds to wait for a UDP reply from the target

log_prefix = "[mr-udp]"


def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{ts} {log_prefix} {msg}", flush=True)


def read_utf8(buf: bytes, off: int):
    length = struct.unpack(">H", buf[off:off + 2])[0]
    off += 2
    s = buf[off:off + length].decode("utf-8", errors="replace")
    off += length
    return s, off


def write_utf8(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def encode_frame(type_: int, id_: int, seq: int, payload: bytes) -> bytes:
    return struct.pack(">BiiI", type_, id_, seq, len(payload)) + payload


def decode_frame(plain: bytes):
    if len(plain) < 13:
        return None
    type_ = plain[0]
    id_, seq = struct.unpack(">ii", plain[1:9])
    payload = plain[13:]
    return type_, id_, seq, payload


class StreamState:
    __slots__ = ("id", "writer", "send_seq", "recv_seq", "ack_waiters", "closed")

    def __init__(self, id_: int, writer: asyncio.StreamWriter):
        self.id = id_
        self.writer = writer
        self.send_seq = 0
        self.recv_seq = 0
        self.ack_waiters = {}
        self.closed = False


class ClientSession:
    def __init__(self, addr):
        self.addr = addr
        self.authenticated = False
        self.streams: dict[int, StreamState] = {}
        self.last_seen = time.monotonic()

    def touch(self):
        self.last_seen = time.monotonic()


class MrUdpServer(asyncio.DatagramProtocol):
    def __init__(self, username: str, password: str):
        self.username = username
        self.key = hashlib.sha256(password.encode("utf-8")).digest()
        self.aead = AESGCM(self.key)
        self.password = password
        self.transport: asyncio.DatagramTransport | None = None
        self.sessions: dict[tuple, ClientSession] = {}

    # -- asyncio.DatagramProtocol -------------------------------------------------
    def connection_made(self, transport):
        self.transport = transport
        log(f"listening (username='{self.username}')")

    def error_received(self, exc):
        log(f"WARN: socket error: {exc}")

    def datagram_received(self, data: bytes, addr):
        asyncio.create_task(self._handle(data, addr))

    def connection_lost(self, exc):
        log(f"socket closed: {exc}")

    # -- crypto ---------------------------------------------------------------
    def decrypt(self, data: bytes):
        if len(data) < 12 + 16:
            return None
        nonce, ct = data[:12], data[12:]
        try:
            return self.aead.decrypt(nonce, ct, None)
        except InvalidTag:
            return None
        except Exception:
            return None

    def send_packet(self, addr, type_: int, id_: int, seq: int, payload: bytes):
        plain = encode_frame(type_, id_, seq, payload)
        nonce = os.urandom(12)
        ct = self.aead.encrypt(nonce, plain, None)
        try:
            self.transport.sendto(nonce + ct, addr)
        except Exception as e:
            log(f"WARN: sendto failed: {e}")

    # -- dispatch ---------------------------------------------------------------
    async def _handle(self, data: bytes, addr):
        plain = self.decrypt(data)
        if plain is None:
            return  # wrong password or corrupt packet -> silently drop
        frame = decode_frame(plain)
        if frame is None:
            return
        type_, id_, seq, payload = frame

        session = self.sessions.get(addr)
        if session is None:
            session = ClientSession(addr)
            self.sessions[addr] = session
        session.touch()

        if type_ == HELLO:
            await self._handle_hello(session, payload)
            return

        if not session.authenticated:
            return  # ignore everything until a valid HELLO arrives

        if type_ == OPEN:
            await self._handle_open(session, id_, payload)
        elif type_ == DATA:
            await self._handle_data(session, id_, seq, payload)
        elif type_ == ACK:
            self._handle_ack(session, id_, seq)
        elif type_ == CLOSE:
            self._handle_close(session, id_)
        elif type_ == UDP:
            asyncio.create_task(self._handle_udp(session, id_, payload))
        elif type_ == PING:
            self.send_packet(session.addr, PING, 0, seq, b"")

    async def _handle_hello(self, session: ClientSession, payload: bytes):
        try:
            user, off = read_utf8(payload, 0)
            pw, _ = read_utf8(payload, off)
        except Exception:
            return
        if user == self.username and pw == self.password:
            session.authenticated = True
            self.send_packet(session.addr, HELLO_OK, 0, 0, b"")
            log(f"client {session.addr[0]}:{session.addr[1]} authenticated")
        else:
            log(f"WARN: bad credentials from {session.addr[0]}:{session.addr[1]} (user='{user}')")

    async def _handle_open(self, session: ClientSession, id_: int, payload: bytes):
        try:
            host, off = read_utf8(payload, 0)
            port = struct.unpack(">H", payload[off:off + 2])[0]
        except Exception:
            self.send_packet(session.addr, OPEN_OK, id_, 0, b"\x00")
            return
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10
            )
        except Exception as e:
            log(f"OPEN failed -> {host}:{port} ({e})")
            self.send_packet(session.addr, OPEN_OK, id_, 0, b"\x00")
            return
        stream = StreamState(id_, writer)
        session.streams[id_] = stream
        self.send_packet(session.addr, OPEN_OK, id_, 0, b"\x01")
        asyncio.create_task(self._pump_target_to_client(session, stream, reader))

    async def _handle_data(self, session: ClientSession, id_: int, seq: int, payload: bytes):
        stream = session.streams.get(id_)
        if stream is not None and not stream.closed:
            if seq == stream.recv_seq:
                try:
                    stream.writer.write(payload)
                    await stream.writer.drain()
                    stream.recv_seq += 1
                except Exception:
                    self._close_stream(session, stream)
        # ack regardless, mirrors the client's own receive loop behaviour
        self.send_packet(session.addr, ACK, id_, seq, b"")

    def _handle_ack(self, session: ClientSession, id_: int, seq: int):
        stream = session.streams.get(id_)
        if stream is None:
            return
        fut = stream.ack_waiters.pop(seq, None)
        if fut is not None and not fut.done():
            fut.set_result(True)

    def _handle_close(self, session: ClientSession, id_: int):
        stream = session.streams.pop(id_, None)
        if stream is not None:
            self._close_stream(session, stream, notify=False)

    def _close_stream(self, session: ClientSession, stream: StreamState, notify: bool = True):
        if stream.closed:
            return
        stream.closed = True
        try:
            stream.writer.close()
        except Exception:
            pass
        for fut in stream.ack_waiters.values():
            if not fut.done():
                fut.set_result(False)
        stream.ack_waiters.clear()
        session.streams.pop(stream.id, None)
        if notify:
            self.send_packet(session.addr, CLOSE, stream.id, 0, b"")

    async def _pump_target_to_client(self, session: ClientSession, stream: StreamState, reader: asyncio.StreamReader):
        try:
            while not stream.closed:
                chunk = await reader.read(MAX_PAYLOAD)
                if not chunk:
                    break
                ok = await self._send_reliable(session, stream, chunk)
                if not ok:
                    break
        except Exception:
            pass
        finally:
            self._close_stream(session, stream, notify=True)

    async def _send_reliable(self, session: ClientSession, stream: StreamState, data: bytes) -> bool:
        seq = stream.send_seq
        stream.send_seq += 1
        loop = asyncio.get_event_loop()
        for _ in range(MAX_RETRIES):
            if stream.closed:
                return False
            fut = loop.create_future()
            stream.ack_waiters[seq] = fut
            self.send_packet(session.addr, DATA, stream.id, seq, data)
            try:
                result = await asyncio.wait_for(fut, timeout=ACK_TIMEOUT)
                if result:
                    return True
            except asyncio.TimeoutError:
                stream.ack_waiters.pop(seq, None)
                continue
        return False

    async def _handle_udp(self, session: ClientSession, id_: int, payload: bytes):
        try:
            host, off = read_utf8(payload, 0)
            port = struct.unpack(">H", payload[off:off + 2])[0]
            data = payload[off + 2:]
        except Exception:
            return
        resp = await self._udp_roundtrip(host, port, data, UDP_ASSOC_TIMEOUT)
        if resp is not None:
            self.send_packet(session.addr, UDP, id_, 0, resp)

    @staticmethod
    async def _udp_roundtrip(host: str, port: int, data: bytes, timeout: float):
        loop = asyncio.get_event_loop()
        fut = loop.create_future()

        class _Proto(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                transport.sendto(data)

            def datagram_received(self, resp_data, _addr):
                if not fut.done():
                    fut.set_result(resp_data)

            def error_received(self, exc):
                if not fut.done():
                    fut.set_exception(exc)

        try:
            transport, _ = await loop.create_datagram_endpoint(
                _Proto, remote_addr=(host, port)
            )
        except Exception:
            return None
        try:
            return await asyncio.wait_for(fut, timeout)
        except Exception:
            return None
        finally:
            transport.close()

    async def reap_idle_sessions(self):
        while True:
            await asyncio.sleep(30)
            now = time.monotonic()
            dead = [addr for addr, s in self.sessions.items()
                    if now - s.last_seen > SESSION_IDLE_TIMEOUT]
            for addr in dead:
                session = self.sessions.pop(addr, None)
                if session:
                    for stream in list(session.streams.values()):
                        self._close_stream(session, stream, notify=False)
                    log(f"dropped idle session {addr[0]}:{addr[1]}")


async def main():
    parser = argparse.ArgumentParser(description="MR-UDP server")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--bind", default="0.0.0.0")
    args = parser.parse_args()

    username = os.environ.get("MR_USER")
    password = os.environ.get("MR_PASS")
    if not username or not password:
        log("FATAL: MR_USER / MR_PASS environment variables are required")
        sys.exit(1)

    loop = asyncio.get_event_loop()
    server = MrUdpServer(username, password)
    transport, _ = await loop.create_datagram_endpoint(
        lambda: server, local_addr=(args.bind, args.port)
    )
    log(f"MR-UDP server started on {args.bind}:{args.port}")
    asyncio.create_task(server.reap_idle_sessions())
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
