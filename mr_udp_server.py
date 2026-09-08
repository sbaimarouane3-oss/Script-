#!/usr/bin/env python3
"""MR-UDP v1 server for MR VPN TUNNEL.

Encrypted UDP transport carrying multiplexed TCP streams and SOCKS-style UDP
forwarding. Matching Android client: MrUdpClient.kt.
"""
import argparse, hashlib, os, socket, struct, threading, time
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise SystemExit("Missing dependency. Install with: python3 -m pip install cryptography")

MAGIC = 0x4D525550
VERSION = 1
HELLO, HELLO_OK, OPEN, OPEN_OK, DATA, ACK, CLOSE, UDP, PING = range(1, 10)
MAX_PAYLOAD = 1100
ACK_TIMEOUT = 1.8
MAX_RETRIES = 5


def sha256(x): return hashlib.sha256(x).digest()


def pack_plain(typ, sid, seq, payload):
    return struct.pack('!BIII', typ, sid & 0xffffffff, seq & 0xffffffff, len(payload)) + payload


def unpack_plain(p):
    if len(p) < 13: return None
    typ, sid, seq, ln = struct.unpack('!BIII', p[:13])
    if ln != len(p)-13: return None
    return typ, sid, seq, p[13:]


class Client:
    def __init__(self, server, addr, username, password):
        self.server = server
        self.addr = addr
        self.username = username
        self.key = sha256(password.encode())
        self.aes = AESGCM(self.key)
        self.streams = {}
        self.lock = threading.RLock()
        self.alive = True

    def decrypt(self, dat):
        if len(dat) < 28: return None
        try: return self.aes.decrypt(dat[:12], dat[12:], None)
        except Exception: return None

    def encrypt(self, plain):
        nonce = os.urandom(12)
        return nonce + self.aes.encrypt(nonce, plain, None)

    def send(self, typ, sid, seq, payload=b''):
        if not self.alive: return
        dat = self.encrypt(pack_plain(typ, sid, seq, payload))
        try: self.server.sock.sendto(dat, self.addr)
        except OSError: self.alive = False

    def stop(self):
        self.alive = False
        with self.lock:
            for st in list(self.streams.values()): st.close()
            self.streams.clear()


class Stream:
    def __init__(self, client, sid, sock):
        self.client = client; self.sid = sid; self.sock = sock
        self.closed = False; self.recv_seq = 0; self.send_seq = 0
        self.ack_lock = threading.Condition(); self.last_ack = -1
        self.send_lock = threading.Lock()
        self.sock.settimeout(None)

    def ack(self, seq):
        with self.ack_lock:
            if seq > self.last_ack: self.last_ack = seq
            self.ack_lock.notify_all()

    def send_reliable(self, data):
        with self.send_lock:
            seq = self.send_seq; self.send_seq += 1
            for _ in range(MAX_RETRIES):
                if self.closed: return False
                self.client.send(DATA, self.sid, seq, data)
                end = time.monotonic() + ACK_TIMEOUT
                with self.ack_lock:
                    while self.last_ack < seq and not self.closed:
                        left = end - time.monotonic()
                        if left <= 0: break
                        self.ack_lock.wait(left)
                    if self.last_ack >= seq: return True
            self.close(); return False

    def reverse_loop(self):
        try:
            while self.client.alive and not self.closed:
                data = self.sock.recv(MAX_PAYLOAD)
                if not data: break
                if not self.send_reliable(data): break
        except Exception:
            pass
        finally: self.close()

    def client_data(self, seq, data):
        if self.closed: return
        if seq < self.recv_seq:
            self.client.send(ACK, self.sid, seq)
            return
        if seq != self.recv_seq:
            return
        try:
            self.sock.sendall(data)
            self.recv_seq += 1
            self.client.send(ACK, self.sid, seq)
        except Exception:
            self.close()

    def close(self):
        if self.closed: return
        self.closed = True
        try: self.sock.close()
        except Exception: pass
        with self.ack_lock: self.ack_lock.notify_all()
        with self.client.lock: self.client.streams.pop(self.sid, None)
        if self.client.alive: self.client.send(CLOSE, self.sid, 0)


class Server:
    def __init__(self, host, port, username, password):
        self.host=host; self.port=port; self.username=username; self.password=password
        self.sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port)); self.clients={}; self.lock=threading.RLock()

    def parse_hello(self, payload):
        if len(payload) < 4: return None
        p=0
        ul=struct.unpack('!H',payload[p:p+2])[0]; p+=2
        if p+ul+2>len(payload): return None
        u=payload[p:p+ul].decode('utf-8','strict'); p+=ul
        pl=struct.unpack('!H',payload[p:p+2])[0]; p+=2
        if p+pl!=len(payload): return None
        pw=payload[p:p+pl].decode('utf-8','strict')
        return u,pw

    def handle(self, dat, addr):
        with self.lock: c=self.clients.get(addr)
        if c is None:
            # We need to try each candidate password. The protocol uses the
            # configured password as the AES key, so without a client object
            # there is no way to authenticate/decrypt. Create a temporary
            # cipher with the server password first.
            try:
                aes=AESGCM(sha256(self.password.encode()))
                if len(dat)<28: return
                plain=aes.decrypt(dat[:12],dat[12:],None)
                msg=unpack_plain(plain)
            except Exception: return
            if not msg or msg[0] != HELLO: return
            hp=self.parse_hello(msg[3])
            if not hp or hp[0] != self.username or hp[1] != self.password: return
            c=Client(self,addr,self.username,self.password)
            with self.lock: self.clients[addr]=c
            c.send(HELLO_OK,0,0)
            print(f"[+] Authenticated {addr[0]}:{addr[1]} user={self.username}",flush=True)
            return
        plain=c.decrypt(dat)
        if not plain: return
        msg=unpack_plain(plain)
        if not msg: return
        typ,sid,seq,payload=msg
        if typ == PING: c.send(PING,0,seq); return
        if typ == OPEN: self.open_stream(c,sid,payload); return
        if typ == DATA:
            with c.lock: st=c.streams.get(sid)
            if st: st.client_data(seq,payload)
            return
        if typ == ACK:
            with c.lock: st=c.streams.get(sid)
            if st: st.ack(seq)
            return
        if typ == CLOSE:
            with c.lock: st=c.streams.get(sid)
            if st: st.close()
            return
        if typ == UDP: self.forward_udp(c,sid,payload); return

    def open_stream(self,c,sid,payload):
        host = '?'
        port = 0
        try:
            p=0
            if len(payload) < 4:
                raise ValueError(f"OPEN payload too short: {len(payload)}")
            hl=struct.unpack('!H',payload[p:p+2])[0];p+=2
            if p+hl+2 > len(payload):
                raise ValueError(f"invalid OPEN host length: {hl}, payload={len(payload)}")
            host=payload[p:p+hl].decode('utf-8','strict');p+=hl
            port=struct.unpack('!H',payload[p:p+2])[0]
            print(f"[OPEN] sid={sid} {host}:{port}", flush=True)
            sock=socket.create_connection((host,port),timeout=10)
            st=Stream(c,sid,sock)
            with c.lock: c.streams[sid]=st
            c.send(OPEN_OK,sid,0,b'\x01')
            print(f"[OPEN-OK] sid={sid} {host}:{port} connected", flush=True)
            threading.Thread(target=st.reverse_loop,daemon=True).start()
        except Exception as e:
            print(f"[OPEN-FAIL] sid={sid} {host}:{port} -> {type(e).__name__}: {e}", flush=True)
            c.send(OPEN_OK,sid,0,b'\x00')

    def forward_udp(self,c,sid,payload):
        host = '?'
        port = 0
        s = None
        try:
            p=0
            if len(payload) < 4:
                raise ValueError(f"UDP payload too short: {len(payload)}")
            hl=struct.unpack('!H',payload[p:p+2])[0];p+=2
            if p+hl+2 > len(payload):
                raise ValueError(f"invalid UDP host length: {hl}, payload={len(payload)}")
            host=payload[p:p+hl].decode('utf-8','strict');p+=hl
            port=struct.unpack('!H',payload[p:p+2])[0];p+=2
            data=payload[p:]
            print(f"[UDP] sid={sid} -> {host}:{port} bytes={len(data)}", flush=True)

            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            s.settimeout(3)
            sent=s.sendto(data,(host,port))
            print(f"[UDP-SENT] sid={sid} {host}:{port} bytes={sent}", flush=True)

            end=time.monotonic()+3
            received=0
            while time.monotonic()<end:
                try:
                    d,src=s.recvfrom(65535)
                    received += 1
                    print(f"[UDP-RECV] sid={sid} from={src[0]}:{src[1]} bytes={len(d)}", flush=True)
                    c.send(UDP,sid,0,d)
                except socket.timeout:
                    print(f"[UDP-TIMEOUT] sid={sid} {host}:{port} replies={received}", flush=True)
                    break
            if received == 0:
                print(f"[UDP-NO-REPLY] sid={sid} {host}:{port}", flush=True)
        except Exception as e:
            print(f"[UDP-FAIL] sid={sid} {host}:{port} -> {type(e).__name__}: {e}", flush=True)
        finally:
            if s is not None:
                try: s.close()
                except Exception: pass

    def run(self):
        print(f"MR-UDP v1 listening on {self.host}:{self.port}/udp",flush=True)
        while True:
            try:
                dat,addr=self.sock.recvfrom(65535)
                threading.Thread(target=self.handle,args=(dat,addr),daemon=True).start()
            except KeyboardInterrupt: break
            except Exception as e: print(f"[WARN] {e}",flush=True)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--listen',default='0.0.0.0')
    ap.add_argument('--port',type=int,default=int(os.environ.get('MR_PORT','4433')))
    ap.add_argument('--user',default=os.environ.get('MR_USER',''))
    ap.add_argument('--password',default=os.environ.get('MR_PASS',''))
    a=ap.parse_args()
    if not a.user or not a.password:
        ap.error('username/password required (use --user/--password or MR_USER/MR_PASS)')
    Server(a.listen,a.port,a.user,a.password).run()
if __name__=='__main__': main()
