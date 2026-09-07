#!/usr/bin/env python3
"""
MR-UDP server daemon.

Matches the Android MR-UDP client protocol:
- Transport: single encrypted UDP socket.
- Encryption: AES-256-GCM, key = SHA-256(password).
- HELLO/OPEN/DATA/ACK/CLOSE/UDP/PING.
"""

import argparse
import asyncio
import hashlib
import os
import struct
import sys
import time

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    print(
        "[FATAL] Missing dependency. Run: "
        "pip3 install cryptography --break-system-packages",
        file=sys.stderr,
    )
    sys.exit(1)

HELLO, HELLO_OK, OPEN, OPEN_OK, DATA, ACK, CLOSE, UDP, PING = range(1, 10)

MAX_PAYLOAD = 1100
ACK_TIMEOUT = 1.8
MAX_RETRIES = 5
SESSION_IDLE_TIMEOUT = 300

# Persistent UDP association idle timeout.
UDP_ASSOC_TIMEOUT = 60

log_prefix = "[mr-udp]"


def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{ts} {log_prefix} {msg}", flush=True)


def read_utf8(buf: bytes, off: int):
    if off + 2 > len(buf):
        raise ValueError("missing UTF-8 length")

    length = struct.unpack(">H", buf[off:off + 2])[0]
    off += 2

    if off + length > len(buf):
        raise ValueError("invalid UTF-8 length")

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
    payload_len = struct.unpack(">I", plain[9:13])[0]

    if payload_len != len(plain) - 13:
        return None

    return type_, id_, seq, plain[13:]


class StreamState:
    __slots__ = (
        "id",
        "writer",
        "send_seq",
        "recv_seq",
        "ack_waiters",
        "closed",
    )

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
        self.udp_assocs = {}
        self.last_seen = time.monotonic()

    def touch(self):
        self.last_seen = time.monotonic()


class MrUdpServer(asyncio.DatagramProtocol):
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.key = hashlib.sha256(password.encode("utf-8")).digest()
        self.aead = AESGCM(self.key)
        self.transport: asyncio.DatagramTransport | None = None
        self.sessions: dict[tuple, ClientSession] = {}

    def connection_made(self, transport):
        self.transport = transport
        log(f"listening (username='{self.username}')")

    def error_received(self, exc):
        log(f"WARN: socket error: {exc}")

    def datagram_received(self, data: bytes, addr):
        asyncio.create_task(self._handle(data, addr))

    def connection_lost(self, exc):
        log(f"socket closed: {exc}")

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

    async def _handle(self, data: bytes, addr):
        plain = self.decrypt(data)
        if plain is None:
            return

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
            return

        if type_ == OPEN:
            await self._handle_open(session, id_, payload)

        elif type_ == DATA:
            await self._handle_data(session, id_, seq, payload)

        elif type_ == ACK:
            self._handle_ack(session, id_, seq)

        elif type_ == CLOSE:
            self._handle_close(session, id_)

        elif type_ == UDP:
            asyncio.create_task(
                self._handle_udp(session, id_, payload)
            )

        elif type_ == PING:
            self.send_packet(
                session.addr,
                PING,
                0,
                seq,
                b"",
            )

    async def _handle_hello(self, session: ClientSession, payload: bytes):
        try:
            user, off = read_utf8(payload, 0)
            pw, _ = read_utf8(payload, off)
        except Exception:
            return

        if user == self.username and pw == self.password:
            session.authenticated = True

            self.send_packet(
                session.addr,
                HELLO_OK,
                0,
                0,
                b"",
            )

            log(
                f"client {session.addr[0]}:{session.addr[1]} "
                f"authenticated"
            )
        else:
            log(
                f"WARN: bad credentials from "
                f"{session.addr[0]}:{session.addr[1]} "
                f"(user='{user}')"
            )

    async def _handle_open(
        self,
        session: ClientSession,
        id_: int,
        payload: bytes,
    ):
        try:
            host, off = read_utf8(payload, 0)

            if off + 2 > len(payload):
                raise ValueError("missing port")

            port = struct.unpack(
                ">H",
                payload[off:off + 2],
            )[0]

        except Exception:
            self.send_packet(
                session.addr,
                OPEN_OK,
                id_,
                0,
                b"\x00",
            )
            return

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10,
            )

        except Exception as e:
            log(
                f"OPEN failed -> {host}:{port} ({e})"
            )

            self.send_packet(
                session.addr,
                OPEN_OK,
                id_,
                0,
                b"\x00",
            )
            return

        stream = StreamState(id_, writer)
        session.streams[id_] = stream

        self.send_packet(
            session.addr,
            OPEN_OK,
            id_,
            0,
            b"\x01",
        )

        asyncio.create_task(
            self._pump_target_to_client(
                session,
                stream,
                reader,
            )
        )

    async def _handle_data(
        self,
        session: ClientSession,
        id_: int,
        seq: int,
        payload: bytes,
    ):
        stream = session.streams.get(id_)

        if stream is not None and not stream.closed:
            if seq == stream.recv_seq:
                try:
                    stream.writer.write(payload)
                    await stream.writer.drain()
                    stream.recv_seq += 1
                except Exception:
                    self._close_stream(
                        session,
                        stream,
                    )

        self.send_packet(
            session.addr,
            ACK,
            id_,
            seq,
            b"",
        )

    def _handle_ack(
        self,
        session: ClientSession,
        id_: int,
        seq: int,
    ):
        stream = session.streams.get(id_)

        if stream is None:
            return

        fut = stream.ack_waiters.pop(seq, None)

        if fut is not None and not fut.done():
            fut.set_result(True)

    def _handle_close(
        self,
        session: ClientSession,
        id_: int,
    ):
        stream = session.streams.pop(id_, None)

        if stream is not None:
            self._close_stream(
                session,
                stream,
                notify=False,
            )

    def _close_stream(
        self,
        session: ClientSession,
        stream: StreamState,
        notify: bool = True,
    ):
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

        session.streams.pop(
            stream.id,
            None,
        )

        if notify:
            self.send_packet(
                session.addr,
                CLOSE,
                stream.id,
                0,
                b"",
            )

    async def _pump_target_to_client(
        self,
        session: ClientSession,
        stream: StreamState,
        reader: asyncio.StreamReader,
    ):
        try:
            while not stream.closed:
                chunk = await reader.read(MAX_PAYLOAD)

                if not chunk:
                    break

                ok = await self._send_reliable(
                    session,
                    stream,
                    chunk,
                )

                if not ok:
                    break

        except Exception:
            pass

        finally:
            self._close_stream(
                session,
                stream,
                notify=True,
            )

    async def _send_reliable(
        self,
        session: ClientSession,
        stream: StreamState,
        data: bytes,
    ) -> bool:
        seq = stream.send_seq
        stream.send_seq += 1

        loop = asyncio.get_event_loop()

        for _ in range(MAX_RETRIES):
            if stream.closed:
                return False

            fut = loop.create_future()
            stream.ack_waiters[seq] = fut

            self.send_packet(
                session.addr,
                DATA,
                stream.id,
                seq,
                data,
            )

            try:
                result = await asyncio.wait_for(
                    fut,
                    timeout=ACK_TIMEOUT,
                )

                if result:
                    return True

            except asyncio.TimeoutError:
                stream.ack_waiters.pop(
                    seq,
                    None,
                )

        return False

    # -----------------------------------------------------------------------
    # Persistent UDP association
    # -----------------------------------------------------------------------

    async def _handle_udp(
        self,
        session: ClientSession,
        id_: int,
        payload: bytes,
    ):
        try:
            host, off = read_utf8(payload, 0)

            if off + 2 > len(payload):
                raise ValueError("missing UDP port")

            port = struct.unpack(
                ">H",
                payload[off:off + 2],
            )[0]

            data = payload[off + 2:]

        except Exception:
            return

        key = (session.addr, id_)
        assoc = session.udp_assocs.get(key)

        # Recreate a dead/expired association.
        if assoc is None or assoc.get("closed"):
            if assoc is not None:
                try:
                    assoc["transport"].close()
                except Exception:
                    pass

                session.udp_assocs.pop(
                    key,
                    None,
                )

            assoc = await self._create_udp_assoc(
                session,
                id_,
                host,
                port,
            )

            if assoc is None:
                return

            session.udp_assocs[key] = assoc

        # Protect against the same request id being reused for another
        # destination.
        elif (
            assoc.get("host") != host
            or assoc.get("port") != port
        ):
            try:
                assoc["transport"].close()
            except Exception:
                pass

            session.udp_assocs.pop(
                key,
                None,
            )

            assoc = await self._create_udp_assoc(
                session,
                id_,
                host,
                port,
            )

            if assoc is None:
                return

            session.udp_assocs[key] = assoc

        transport = assoc["transport"]

        try:
            transport.sendto(data)
            assoc["last_seen"] = time.monotonic()

        except Exception as e:
            assoc["closed"] = True

            log(
                f"WARN: UDP send failed -> "
                f"{host}:{port} ({e})"
            )

    async def _create_udp_assoc(
        self,
        session: ClientSession,
        id_: int,
        host: str,
        port: int,
    ):
        loop = asyncio.get_event_loop()

        key = (session.addr, id_)
        server = self

        class UDPProtocol(asyncio.DatagramProtocol):

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                assoc = session.udp_assocs.get(key)

                if assoc is None:
                    return

                assoc["last_seen"] = time.monotonic()

                server.send_packet(
                    session.addr,
                    UDP,
                    id_,
                    0,
                    data,
                )

            def error_received(self, exc):
                log(
                    f"WARN: UDP error -> "
                    f"{host}:{port} ({exc})"
                )

            def connection_lost(self, exc):
                assoc = session.udp_assocs.get(key)

                if assoc is not None:
                    assoc["closed"] = True

        try:
            transport, _ = await loop.create_datagram_endpoint(
                UDPProtocol,
                remote_addr=(host, port),
            )

            return {
                "transport": transport,
                "host": host,
                "port": port,
                "last_seen": time.monotonic(),
                "closed": False,
            }

        except Exception as e:
            log(
                f"UDP ASSOC failed -> "
                f"{host}:{port} ({e})"
            )
            return None

    # -----------------------------------------------------------------------
    # Cleanup
    # -----------------------------------------------------------------------

    async def reap_idle_sessions(self):
        while True:
            await asyncio.sleep(30)

            now = time.monotonic()

            # Clean expired UDP associations even while the session itself
            # remains active.
            for session in list(self.sessions.values()):
                for key, assoc in list(
                    session.udp_assocs.items()
                ):
                    if (
                        assoc.get("closed")
                        or now - assoc.get(
                            "last_seen",
                            now,
                        ) > UDP_ASSOC_TIMEOUT
                    ):
                        try:
                            assoc["transport"].close()
                        except Exception:
                            pass

                        session.udp_assocs.pop(
                            key,
                            None,
                        )

            dead = [
                addr
                for addr, session in self.sessions.items()
                if now - session.last_seen
                > SESSION_IDLE_TIMEOUT
            ]

            for addr in dead:
                session = self.sessions.pop(
                    addr,
                    None,
                )

                if session is None:
                    continue

                for stream in list(
                    session.streams.values()
                ):
                    self._close_stream(
                        session,
                        stream,
                        notify=False,
                    )

                for assoc in list(
                    session.udp_assocs.values()
                ):
                    try:
                        assoc["transport"].close()
                    except Exception:
                        pass

                session.udp_assocs.clear()

                log(
                    f"dropped idle session "
                    f"{addr[0]}:{addr[1]}"
                )


async def main():
    parser = argparse.ArgumentParser(
        description="MR-UDP server"
    )

    parser.add_argument(
        "--port",
        type=int,
        required=True,
    )

    parser.add_argument(
        "--bind",
        default="0.0.0.0",
    )

    args = parser.parse_args()

    username = os.environ.get("MR_USER")
    password = os.environ.get("MR_PASS")

    if not username or not password:
        log(
            "FATAL: MR_USER / MR_PASS environment "
            "variables are required"
        )
        sys.exit(1)

    loop = asyncio.get_event_loop()

    server = MrUdpServer(
        username,
        password,
    )

    transport, _ = await loop.create_datagram_endpoint(
        lambda: server,
        local_addr=(args.bind, args.port),
    )

    log(
        f"MR-UDP server started on "
        f"{args.bind}:{args.port}"
    )

    asyncio.create_task(
        server.reap_idle_sessions()
    )

    try:
        await asyncio.Event().wait()

    finally:
        transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
