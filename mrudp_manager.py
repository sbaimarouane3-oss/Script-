#!/usr/bin/env python3
"""
MR-UDP v1 server - the missing counterpart to app's MrUdpClient.kt.

Wire protocol (must match MrUdpClient.kt exactly):
  Frame (before encryption): type(1B) + id(int32 BE) + seq(int32 BE)
                              + payloadLen(int32 BE) + payload
  On the wire: nonce(12B) + AES-256-GCM(frame, key=SHA256(password), tag=16B)

Opcodes: HELLO=1 HELLO_OK=2 OPEN=3 OPEN_OK=4 DATA=5 ACK=6 CLOSE=7 UDP=8 PING=9

Env vars (written by mrvpn_manager.py to /opt/mr-vpn-manager/env/<id>.env
and loaded by its systemd unit):
    MR_USER  - expected username (informational check only)
    MR_PASS  - shared secret; AES key = SHA256(MR_PASS). MUST match the
               password entered in the app's MR-UDP form.
    MR_PORT  - UDP port to listen on

Usage:
    python3 mr_udp_server.py --port 4433 --user mrudp --pass 'secret'
    (or just rely on MR_USER / MR_PASS / MR_PORT from the environment,
    which is how mrvpn_manager.py's systemd unit invokes it)

Requires: pip3 install --break-system-packages cryptography
"""
import argparse
import asyncio
import hashlib
import os
import socket
import struct
import sys
import time

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("ERROR: missing dependency. Run:\n"
          "  pip3 install --break-system-packages cryptography", file=sys.stderr)
    sys.exit(1)

HELLO, HELLO_OK, OPEN, OPEN_OK, DATA, ACK, CLOSE, UDP, PING = range(1, 10)
MAX_PAYLOAD = 1100
ACK_TIMEOUT = 1.8
MAX_RETRIES = 5
SESSION_IDLE_TIMEOUT = 300
HEADER_FMT = ">biii"          # type, id, seq, payloadLen  (13 bytes)
HEADER_LEN = struct.calcsize(HEADER_FMT)


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


class Framer:
    """AES-256-GCM using key = SHA256(password), matching the client exactly."""

    def __init__(self, password: str):
        key = hashlib.sha256(password.encode("utf-8")).digest()
        self.aead = AESGCM(key)

    def encrypt(self, plain: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self.aead.encrypt(nonce, plain, None)

    def decrypt(self, data: bytes):
        if len(data) < 12 + 16:
            return None
        nonce, ct = data[:12], data[12:]
        try:
            return self.aead.decrypt(nonce, ct, None)
        except Exception:
            return None


def pack_frame(t, sid, seq, payload=b""):
    return struct.pack(HEADER_FMT, t, sid, seq, len(payload)) + payload


def unpack_frame(plain):
    if len(plain) < HEADER_LEN:
        return None
    t, sid, seq, _plen = struct.unpack(HEADER_FMT, plain[:HEADER_LEN])
    # Client's own decoder ignores the length field and just takes the
    # rest of the packet as payload - mirror that for compatibility.
    return t, sid, seq, plain[HEADER_LEN:]


def read_utf(buf: bytes, off: int):
    ln = (buf[off] << 8) | buf[off + 1]
    off += 2
    return buf[off:off + ln].decode("utf-8", "replace"), off + ln


class Stream:
    """One proxied TCP connection multiplexed inside the tunnel."""

    def __init__(self, session, sid, host, port):
        self.session = session
        self.id = sid
        self.host = host
        self.port = port
        self.reader = None
        self.writer = None
        self.up_expected_seq = 0        # next DATA seq expected FROM client
        self.down_seq = 0               # our own outgoing DATA seq counter
        self.down_ack_event = asyncio.Event()
        self.down_last_ack = -1
        self.closed = False
        self.last_active = time.time()

    def touch(self):
        self.last_active = time.time()

    async def connect(self) -> bool:
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=8)
            return True
        except Exception as e:
            log(f"stream {self.id}: connect to {self.host}:{self.port} failed: {e}")
            return False

    async def pump_remote_to_client(self):
        try:
            while not self.closed:
                data = await self.reader.read(MAX_PAYLOAD)
                if not data:
                    break
                for i in range(0, len(data), MAX_PAYLOAD):
                    await self.send_reliable(data[i:i + MAX_PAYLOAD])
        except Exception:
            pass
        finally:
            await self.close(notify=True)

    async def send_reliable(self, chunk: bytes):
        seq = self.down_seq
        self.down_seq += 1
        for _ in range(MAX_RETRIES):
            if self.closed:
                return
            self.down_ack_event.clear()
            self.session.send_frame(DATA, self.id, seq, chunk)
            try:
                await asyncio.wait_for(self.down_ack_event.wait(), ACK_TIMEOUT)
                if self.down_last_ack >= seq:
                    return
            except asyncio.TimeoutError:
                continue
        await self.close(notify=True)

    def on_ack(self, seq):
        if seq > self.down_last_ack:
            self.down_last_ack = seq
        self.down_ack_event.set()

    def on_data(self, seq, payload):
        self.touch()
        if seq == self.up_expected_seq:
            self.up_expected_seq += 1
            if self.writer:
                try:
                    self.writer.write(payload)
                except Exception:
                    pass
        # Ack every received seq (even duplicates) - mirrors the client.
        self.session.send_frame(ACK, self.id, seq, b"")

    async def close(self, notify=False):
        if self.closed:
            return
        self.closed = True
        try:
            if self.writer:
                self.writer.close()
        except Exception:
            pass
        if notify:
            self.session.send_frame(CLOSE, self.id, 0, b"")
        self.session.streams.pop(self.id, None)


class Session:
    """One authenticated client, keyed by its source (ip, port)."""

    def __init__(self, server, addr):
        self.server = server
        self.addr = addr
        self.authenticated = False
        self.streams = {}
        self.last_active = time.time()

    def touch(self):
        self.last_active = time.time()

    def send_frame(self, t, sid, seq, payload):
        enc = self.server.framer.encrypt(pack_frame(t, sid, seq, payload))
        self.server.transport.sendto(enc, self.addr)

    async def handle_hello(self, payload):
        try:
            off = 0
            user, off = read_utf(payload, off)
            _pw, off = read_utf(payload, off)
        except Exception:
            return
        # Packet only decrypted successfully because the password (=AES key)
        # was already correct, so this username check is just a courtesy.
        if self.server.expected_user and user != self.server.expected_user:
            log(f"{self.addr}: HELLO with unexpected username '{user}' - rejected")
            return
        self.authenticated = True
        self.touch()
        log(f"{self.addr}: authenticated as '{user}'")
        self.send_frame(HELLO_OK, 0, 0, b"")

    async def handle_open(self, sid, payload):
        try:
            off = 0
            host, off = read_utf(payload, off)
            port = (payload[off] << 8) | payload[off + 1]
        except Exception:
            self.send_frame(OPEN_OK, sid, 0, b"\x00")
            return
        stream = Stream(self, sid, host, port)
        self.streams[sid] = stream
        ok = await stream.connect()
        self.send_frame(OPEN_OK, sid, 0, bytes([1 if ok else 0]))
        if ok:
            asyncio.ensure_future(stream.pump_remote_to_client())
        else:
            self.streams.pop(sid, None)

    def handle_data(self, sid, seq, payload):
        stream = self.streams.get(sid)
        if stream:
            stream.on_data(seq, payload)
        else:
            # Unknown/closed stream - ack anyway so the client stops retrying.
            self.send_frame(ACK, sid, seq, b"")

    def handle_ack(self, sid, seq):
        stream = self.streams.get(sid)
        if stream:
            stream.on_ack(seq)

    async def handle_close(self, sid):
        stream = self.streams.pop(sid, None)
        if stream:
            await stream.close(notify=False)

    async def handle_udp(self, req_id, payload):
        try:
            off = 0
            host, off = read_utf(payload, off)
            port = (payload[off] << 8) | payload[off + 1]
            off += 2
            data = payload[off:]
        except Exception:
            return
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            sock.sendto(data, (host, port))
            resp = await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout=8)
            self.send_frame(UDP, req_id, 0, resp)
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            log(f"UDP relay to {host}:{port} failed: {e}")
        finally:
            sock.close()

    def handle_ping(self, seq):
        self.send_frame(PING, 0, seq, b"")


class MrUdpServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, framer, expected_user):
        self.framer = framer
        self.expected_user = expected_user
        self.sessions = {}
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        plain = self.framer.decrypt(data)
        if plain is None:
            return  # wrong password or corrupt packet - drop silently
        frame = unpack_frame(plain)
        if frame is None:
            return
        t, sid, seq, payload = frame

        session = self.sessions.get(addr)
        if session is None:
            if t != HELLO:
                return  # first packet from a new address must be HELLO
            session = Session(self, addr)
            self.sessions[addr] = session

        session.touch()
        if t == HELLO:
            asyncio.ensure_future(session.handle_hello(payload))
        elif not session.authenticated:
            return
        elif t == OPEN:
            asyncio.ensure_future(session.handle_open(sid, payload))
        elif t == DATA:
            session.handle_data(sid, seq, payload)
        elif t == ACK:
            session.handle_ack(sid, seq)
        elif t == CLOSE:
            asyncio.ensure_future(session.handle_close(sid))
        elif t == UDP:
            asyncio.ensure_future(session.handle_udp(sid, payload))
        elif t == PING:
            session.handle_ping(seq)

    async def reap_idle(self):
        while True:
            await asyncio.sleep(30)
            now = time.time()
            for addr, s in list(self.sessions.items()):
                if now - s.last_active > SESSION_IDLE_TIMEOUT:
                    for st in list(s.streams.values()):
                        asyncio.ensure_future(st.close(notify=False))
                    self.sessions.pop(addr, None)


async def main():
    ap = argparse.ArgumentParser(description="MR-UDP v1 server")
    ap.add_argument("--port", type=int, default=int(os.environ.get("MR_PORT", "4433")))
    ap.add_argument("--user", default=os.environ.get("MR_USER", ""))
    ap.add_argument("--pass", dest="password", default=os.environ.get("MR_PASS", ""))
    ap.add_argument("--bind", default="0.0.0.0")
    args = ap.parse_args()

    if not args.password:
        log("ERROR: no password set (env MR_PASS or --pass). Refusing to start.")
        sys.exit(1)

    framer = Framer(args.password)
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: MrUdpServerProtocol(framer, args.user or None),
        local_addr=(args.bind, args.port),
    )
    log(f"MR-UDP server listening on {args.bind}:{args.port} (user={args.user or '<any>'})")
    asyncio.ensure_future(protocol.reap_idle())
    try:
        await asyncio.Future()  # run forever
    finally:
        transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
