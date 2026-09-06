#!/usr/bin/env python3
# MR VPN TUNNEL - Server Manager
# Manage VPS-side servers for every protocol the app supports:
#   MR-UDP, SSH, Shadowsocks, VLESS (Xray-core)
#
# Requirements:
#   - Python 3 + systemd, run as root
#   - MR-UDP  : /root/mr_udp_server.py
#   - SSH     : the box's own sshd (accounts are created/locked, not a new daemon)
#   - Shadowsocks : ss-server (shadowsocks-libev) on PATH
#   - VLESS   : xray binary on PATH (or edit XRAY_BIN below)
#
# Usage:
#   sudo python3 mrvpn_manager.py
#
# Data is stored locally in /opt/mr-vpn-manager/servers.json

import json
import os
import random
import re
import secrets
import shutil
import string
import subprocess
import sys
import time
import uuid
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

APP = "MR VPN TUNNEL"
BASE = Path("/opt/mr-vpn-manager")
DB = BASE / "servers.json"
CFG_DIR = BASE / "config"
ENV_DIR = BASE / "env"
BIN_DIR = BASE / "bin"
SSH_WS_PROXY_SCRIPT = BIN_DIR / "ssh_ws_proxy.py"
SYSTEMD_DIR = Path("/etc/systemd/system")
MR_UDP_SERVER_SCRIPT = Path("/root/mr_udp_server.py")
SS_BIN = shutil.which("ss-server") or "/usr/bin/ss-server"
XRAY_BIN = shutil.which("xray") or "/usr/local/bin/xray"

class C:
    RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
    GREEN="\033[92m"; CYAN="\033[96m"; YELLOW="\033[93m"
    MAGENTA="\033[95m"; RED="\033[91m"; BLUE="\033[94m"; WHITE="\033[97m"

# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def clear():
    os.system("clear")

def width():
    try:
        return max(64, min(shutil.get_terminal_size().columns, 100))
    except Exception:
        return 80

def line(ch="=", color=C.DIM):
    print(color + ch * width() + C.RESET)

def box(title, rows, color=C.CYAN):
    w=width()
    print(f"{color}+{'-'*(w-2)}+{C.RESET}")
    title=f" {title} "
    pad=max(0,w-4-len(title))
    print(f"{color}|{C.RESET} {C.BOLD}{C.MAGENTA}{title}{C.RESET}{' '*pad} {color}|{C.RESET}")
    print(f"{color}+{'-'*(w-2)}+{C.RESET}")
    for row in rows:
        row=str(row)
        print(f"{color}|{C.RESET} {row[:w-4]:<{w-4}} {color}|{C.RESET}")
    print(f"{color}+{'-'*(w-2)}+{C.RESET}")

_LOGO_ART = [
    "███╗   ███╗██████╗ ██╗   ██╗██████╗ ███╗   ██╗",
    "████╗ ████║██╔══██╗██║   ██║██╔══██╗████╗  ██║",
    "██╔████╔██║██████╔╝██║   ██║██████╔╝██╔██╗ ██║",
    "██║╚██╔╝██║██╔══██╗╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║",
    "██║ ╚═╝ ██║██║  ██║ ╚████╔╝ ██║     ██║ ╚████║",
    "╚═╝     ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝     ╚═╝  ╚═══╝",
]

def banner():
    print()
    art_width=max(len(row) for row in _LOGO_ART)
    if art_width<=width():
        for row in _LOGO_ART:
            print(C.CYAN+C.BOLD+row+C.RESET)
        print(C.MAGENTA+C.BOLD+"TUNNEL  -  SERVER MANAGER"+C.RESET)
    else:
        print(C.CYAN+C.BOLD+"MR VPN TUNNEL"+C.RESET)
        print(C.MAGENTA+C.BOLD+"SERVER MANAGER"+C.RESET)
    line("=", C.MAGENTA)

def ensure():
    for d in (BASE, CFG_DIR, ENV_DIR, BIN_DIR):
        d.mkdir(parents=True, exist_ok=True)
    if not DB.exists():
        DB.write_text("[]", encoding="utf-8")

def load():
    try:
        data=json.loads(DB.read_text(encoding="utf-8"))
        return data if isinstance(data,list) else []
    except Exception:
        return []

def save(data):
    tmp=DB.with_suffix(".tmp")
    tmp.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding="utf-8")
    os.chmod(tmp,0o600)
    tmp.replace(DB)
    os.chmod(DB,0o600)

def ask(prompt, default=None, secret=False):
    shown="********" if secret and default else default
    if default is None:
        while True:
            v=input(f"{C.YELLOW}>{C.RESET} {C.CYAN}{prompt}{C.RESET}: ").strip()
            if v: return v
    else:
        v=input(f"{C.YELLOW}>{C.RESET} {C.CYAN}{prompt}{C.RESET} {C.DIM}[{shown}]{C.RESET}: ").strip()
        return v if v else default

def ask_int(prompt, default, minimum=1, maximum=65535):
    while True:
        v=input(f"{C.YELLOW}>{C.RESET} {C.CYAN}{prompt}{C.RESET} {C.DIM}[{default}]{C.RESET}: ").strip()
        if not v: return default
        try:
            n=int(v)
            if minimum<=n<=maximum: return n
        except ValueError:
            pass
        print(f"{C.RED}[ERROR] Invalid number ({minimum}-{maximum}).{C.RESET}")

def ask_choice(prompt, options, default=None):
    """options: list of (key, label). Returns the chosen key."""
    for k,label in options:
        mark=" (default)" if k==default else ""
        print(f"  {C.CYAN}{k}{C.RESET}) {label}{C.DIM}{mark}{C.RESET}")
    valid={k for k,_ in options}
    while True:
        v=input(f"{C.YELLOW}>{C.RESET} {prompt}: ").strip()
        if not v and default is not None: return default
        if v in valid: return v
        print(f"{C.RED}[ERROR] Invalid choice.{C.RESET}")

def yes(prompt, default=False):
    d="Y/n" if default else "y/N"
    v=input(f"{C.YELLOW}>{C.RESET} {C.CYAN}{prompt}{C.RESET} ({d}): ").strip().lower()
    if not v: return default
    return v in ("y","yes","1")

def valid_id(name):
    return re.sub(r"[^a-zA-Z0-9_-]+","-",name.strip()).strip("-_").lower()[:32] or "server"

def run(cmd, quiet=False):
    p=subprocess.run(cmd,text=True,capture_output=True)
    if p.returncode and not quiet:
        err=p.stderr.strip() or p.stdout.strip()
        if err: print(C.RED+err+C.RESET)
    return p

def detect_ip():
    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org", timeout=3) as r:
            ip=r.read().decode().strip()
            if ip: return ip
    except Exception:
        pass
    try:
        p=run(["hostname","-I"], True)
        return p.stdout.strip().split()[0] if p.stdout.strip() else ""
    except Exception:
        return ""

def gen_password(n=14):
    alphabet=string.ascii_letters+string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))

def gen_uuid():
    return str(uuid.uuid4())

def port_in_use(data, port, exclude_id=None):
    return any(int(s.get("port",0))==port and s["id"]!=exclude_id for s in data)

# ---- shared Linux-account helpers (used by SSH and SSH+WebSocket) --------

def create_account(username, password):
    run(["useradd","-M","-N","-s","/usr/sbin/nologin",username])
    subprocess.run(["chpasswd"],input=f"{username}:{password}\n",text=True)
    run(["usermod","-U",username],True)

def delete_account(username):
    run(["userdel","-r",username],True)

def lock_account(username):
    run(["usermod","-L",username],True)

def unlock_account(username):
    run(["usermod","-U",username],True)

def account_status(username):
    r=run(["passwd","-S",username],True)
    out=r.stdout.strip().split()
    state=out[1] if len(out)>1 else "?"
    return "STOPPED" if state=="L" else "RUNNING"

# ---- shared SSH+WebSocket front proxy -------------------------------------
# A tiny, dependency-free TCP proxy: it reads the client's initial HTTP/WS
# -looking request (the app's "payload"), ignores it, sends back a canned
# HTTP response, then relays raw bytes to the real sshd - so SSH traffic
# rides inside what looks like a plain WebSocket/HTTP connection.

SSH_WS_PROXY_SRC = '''#!/usr/bin/env python3
"""Minimal HTTP/WebSocket-front TCP proxy for SSH-over-WebSocket tunnels."""
import argparse, asyncio

async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try: writer.close()
        except Exception: pass

async def handle(client_reader, client_writer, target_host, target_port, response):
    try:
        try:
            await asyncio.wait_for(client_reader.readuntil(b"\\r\\n\\r\\n"), timeout=5)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass
        client_writer.write(response)
        await client_writer.drain()
        target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
        await asyncio.gather(
            pipe(client_reader, target_writer),
            pipe(target_reader, client_writer),
        )
    except Exception:
        pass
    finally:
        try: client_writer.close()
        except Exception: pass

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True, help="host:port to listen on")
    ap.add_argument("--target", required=True, help="host:port to forward to, e.g. 127.0.0.1:22")
    ap.add_argument("--response-file", required=True, help="file with the raw bytes to send back after the handshake")
    args = ap.parse_args()
    with open(args.response_file, "rb") as f:
        response = f.read()
    lhost, lport = args.listen.rsplit(":", 1)
    thost, tport = args.target.rsplit(":", 1)
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, thost, int(tport), response),
        lhost or "0.0.0.0", int(lport)
    )
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
'''

def ensure_ssh_ws_proxy_script():
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    SSH_WS_PROXY_SCRIPT.write_text(SSH_WS_PROXY_SRC, encoding="utf-8")
    os.chmod(SSH_WS_PROXY_SCRIPT, 0o755)

# --------------------------------------------------------------------------
# optional DNS helpers
# --------------------------------------------------------------------------
# DuckDNS provides free subdomains (for example: myserver.duckdns.org).
# Cloudflare manages DNS for domains already added to a Cloudflare account.
# Tokens are kept in the local environment/config only; they are not printed.

def dns_http_get(url, params):
    query = urllib.parse.urlencode(params)
    req = urllib.request.Request(f"{url}?{query}", headers={"User-Agent": "MR-VPN-TUNNEL-DNS/1.0"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", errors="replace").strip()

def configure_dns(vps_ip):
    print()
    box("OPTIONAL DNS / DOMAIN", [
        "Create or update a DNS name pointing to this VPS.",
        "DNS is optional; choose 3 to keep the VPS IP only."
    ], C.BLUE)

    choice = ask_choice(
        "DNS provider",
        [
            ("1", "DuckDNS - free subdomain (*.duckdns.org)"),
            ("2", "Cloudflare - existing domain in your Cloudflare account"),
            ("3", "No DNS - use VPS IP only"),
        ],
        default="3"
    )

    if choice == "3":
        return {"provider": "none", "hostname": ""}

    try:
        if choice == "1":
            token = ask("DuckDNS token", secret=True)
            hostname = ask("DuckDNS subdomain (without .duckdns.org)")
            hostname = hostname.strip().lower().replace(".duckdns.org", "")
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", hostname):
                print(C.RED + "[ERROR] Invalid DuckDNS subdomain." + C.RESET)
                return {"provider": "none", "hostname": ""}

            result = dns_http_get(
                "https://www.duckdns.org/update",
                {"domains": hostname, "token": token, "ip": vps_ip}
            )
            if result != "OK":
                print(C.RED + f"[ERROR] DuckDNS update failed: {result}" + C.RESET)
                return {"provider": "none", "hostname": ""}

            fqdn = f"{hostname}.duckdns.org"
            print(C.GREEN + f"[OK] DNS updated: {fqdn} -> {vps_ip}" + C.RESET)
            return {"provider": "duckdns", "hostname": fqdn}

        # Cloudflare
        api_token = ask("Cloudflare API Token", secret=True)
        zone = ask("Cloudflare zone (example.com)")
        hostname = ask("Hostname (example: vpn)")
        zone = zone.strip().lower().rstrip(".")
        hostname = hostname.strip().lower().rstrip(".")

        if hostname in ("", "@"):
            fqdn = zone
            record_name = zone
        elif hostname.endswith("." + zone):
            fqdn = hostname
            record_name = hostname
        else:
            fqdn = f"{hostname}.{zone}"
            record_name = fqdn

        # Get the zone ID.
        zone_req = urllib.request.Request(
            "https://api.cloudflare.com/client/v4/zones?" +
            urllib.parse.urlencode({"name": zone, "status": "active"}),
            headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json",
                     "User-Agent": "MR-VPN-TUNNEL-DNS/1.0"}
        )
        with urllib.request.urlopen(zone_req, timeout=10) as r:
            zone_data = json.loads(r.read().decode("utf-8"))

        if not zone_data.get("success") or not zone_data.get("result"):
            print(C.RED + "[ERROR] Cloudflare zone not found or token has no access." + C.RESET)
            return {"provider": "none", "hostname": ""}

        zone_id = zone_data["result"][0]["id"]

        # Find an existing A record.
        record_req = urllib.request.Request(
            "https://api.cloudflare.com/client/v4/zones/" + zone_id + "/dns_records?" +
            urllib.parse.urlencode({"type": "A", "name": record_name}),
            headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json",
                     "User-Agent": "MR-VPN-TUNNEL-DNS/1.0"}
        )
        with urllib.request.urlopen(record_req, timeout=10) as r:
            record_data = json.loads(r.read().decode("utf-8"))

        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "User-Agent": "MR-VPN-TUNNEL-DNS/1.0"
        }
        payload = json.dumps({
            "type": "A",
            "name": record_name,
            "content": vps_ip,
            "ttl": 300,
            "proxied": False
        }).encode("utf-8")

        if record_data.get("result"):
            record_id = record_data["result"][0]["id"]
            req = urllib.request.Request(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
                data=payload, method="PUT", headers=headers
            )
        else:
            req = urllib.request.Request(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                data=payload, method="POST", headers=headers
            )

        with urllib.request.urlopen(req, timeout=10) as r:
            result = json.loads(r.read().decode("utf-8"))

        if not result.get("success"):
            print(C.RED + "[ERROR] Cloudflare DNS update failed." + C.RESET)
            return {"provider": "none", "hostname": ""}

        print(C.GREEN + f"[OK] DNS updated: {fqdn} -> {vps_ip}" + C.RESET)
        return {"provider": "cloudflare", "hostname": fqdn}

    except Exception as e:
        print(C.RED + f"[ERROR] DNS setup failed: {e}" + C.RESET)
        return {"provider": "none", "hostname": ""}

# --------------------------------------------------------------------------
# protocol backends
# --------------------------------------------------------------------------
# Every backend implements: add_fields, provision, deprovision, start, stop,
# restart, status, summary_rows, logs.  "s" is the server dict, which always
# has: id, protocol, name, vps_ip, port, created, expires, cfg{...}.

def svc_name(prefix, sid):
    return f"mr-{prefix}-{sid}"

# ---- MR-UDP ---------------------------------------------------------------

class MrUdpBackend:
    key="mrudp"; label="MR-UDP (custom encrypted UDP tunnel)"

    def add_fields(self, data, port):
        if not MR_UDP_SERVER_SCRIPT.exists():
            print(C.YELLOW+f"[WARN] {MR_UDP_SERVER_SCRIPT} not found - copy it to /root/ before starting."+C.RESET)
        username=ask("Username","mrudp")
        password=ask("Password", gen_password(), secret=True)
        return {"username":username,"password":password}

    def provision(self, s):
        cfg=s["cfg"]
        env=ENV_DIR/f"{s['id']}.env"
        env.write_text(
            f"MR_USER='{cfg['username']}'\nMR_PASS='{cfg['password']}'\nMR_PORT='{s['port']}'\n",
            encoding="utf-8"
        )
        os.chmod(env,0o600)
        unit=SYSTEMD_DIR/(svc_name('udp',s['id'])+".service")
        unit.write_text(f"""[Unit]
Description=MR VPN TUNNEL - MR-UDP {s['name']}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile={env}
ExecStart=/usr/bin/python3 {MR_UDP_SERVER_SCRIPT} --port $MR_PORT
Restart=on-failure
RestartSec=2
User=root
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
""",encoding="utf-8")
        os.chmod(unit,0o644)
        run(["systemctl","daemon-reload"],True)

    def deprovision(self, s):
        run(["systemctl","disable","--now",svc_name('udp',s['id'])],True)
        (SYSTEMD_DIR/(svc_name('udp',s['id'])+".service")).unlink(missing_ok=True)
        (ENV_DIR/f"{s['id']}.env").unlink(missing_ok=True)
        run(["systemctl","daemon-reload"],True)

    def start(self, s):
        return run(["systemctl","enable","--now",svc_name('udp',s['id'])])

    def stop(self, s):
        return run(["systemctl","disable","--now",svc_name('udp',s['id'])],True)

    def restart(self, s):
        return run(["systemctl","restart",svc_name('udp',s['id'])])

    def status(self, s):
        r=run(["systemctl","is-active",svc_name('udp',s['id'])],True)
        return "RUNNING" if r.stdout.strip()=="active" else "STOPPED"

    def summary_rows(self, s):
        cfg=s["cfg"]
        return [
            f"{C.WHITE}Username{C.RESET}      : {cfg['username']}",
            f"{C.WHITE}Password{C.RESET}      : {'*'*len(cfg['password'])}",
            f"{C.WHITE}Service Unit{C.RESET}  : {svc_name('udp',s['id'])}.service",
        ]

    def logs(self, s):
        subprocess.run(["journalctl","-u",svc_name('udp',s['id']),"-n","80","-f"])

# ---- SSH --------------------------------------------------------------
# Uses the box's own sshd. "Servers" here are just Linux accounts that get
# locked/unlocked and deleted; there is no dedicated systemd unit.

class SshBackend:
    key="ssh"; label="SSH (system SSH account)"

    def add_fields(self, data, port):
        username=ask("Username", "mru_"+"".join(random.choices(string.ascii_lowercase+string.digits,k=5)))
        password=ask("Password", gen_password(), secret=True)
        return {"username":username,"password":password}

    def provision(self, s):
        cfg=s["cfg"]
        create_account(cfg["username"], cfg["password"])

    def deprovision(self, s):
        delete_account(s["cfg"]["username"])

    def start(self, s):
        return unlock_account(s["cfg"]["username"])

    def stop(self, s):
        return lock_account(s["cfg"]["username"])

    def restart(self, s):
        return self.start(s)

    def status(self, s):
        return account_status(s["cfg"]["username"])

    def summary_rows(self, s):
        cfg=s["cfg"]
        return [
            f"{C.WHITE}Username{C.RESET}      : {cfg['username']}",
            f"{C.WHITE}Password{C.RESET}      : {'*'*len(cfg['password'])}",
            f"{C.WHITE}Note{C.RESET}          : uses the system's own sshd on port {s['port']}",
        ]

    def logs(self, s):
        subprocess.run(["journalctl","-u","ssh","-n","80","-f"])

# ---- SSH + WebSocket (payload/CDN front) ----------------------------------
# A real SSH account (same as above) PLUS a small proxy in front of it that
# speaks just enough HTTP/WebSocket to satisfy the app's "payload" handshake
# before becoming a transparent pipe into sshd. This is what lets SSH ride
# through a WS/CDN front the way the app's SSH-Payload / SSH-TLS-Payload
# modes expect on the client side.

class SshWsBackend:
    key="sshws"; label="SSH + WebSocket (payload/CDN front)"

    def add_fields(self, data, port):
        username=ask("Username", "mru_"+"".join(random.choices(string.ascii_lowercase+string.digits,k=5)))
        password=ask("Password", gen_password(), secret=True)
        local_port=ask_int("Local sshd port already running on this VPS",22,1,65535)
        response=ask("Handshake response (use [crlf] for newlines)",
                      "HTTP/1.1 101 Switching Protocols[crlf][crlf]")
        return {"username":username,"password":password,"local_port":local_port,"response":response}

    def response_path(self, s):
        return CFG_DIR/f"{svc_name('sshws',s['id'])}.response"

    def provision(self, s):
        cfg=s["cfg"]
        create_account(cfg["username"], cfg["password"])
        ensure_ssh_ws_proxy_script()
        rpath=self.response_path(s)
        rpath.write_text(cfg["response"].replace("[crlf]","\r\n"), encoding="utf-8")
        os.chmod(rpath,0o600)
        unit=SYSTEMD_DIR/(svc_name('sshws',s['id'])+".service")
        unit.write_text(f"""[Unit]
Description=MR VPN TUNNEL - SSH WebSocket {s['name']}
After=network-online.target sshd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {SSH_WS_PROXY_SCRIPT} --listen 0.0.0.0:{s['port']} --target 127.0.0.1:{cfg['local_port']} --response-file {rpath}
Restart=on-failure
RestartSec=2
User=root
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
""",encoding="utf-8")
        os.chmod(unit,0o644)
        run(["systemctl","daemon-reload"],True)

    def deprovision(self, s):
        run(["systemctl","disable","--now",svc_name('sshws',s['id'])],True)
        (SYSTEMD_DIR/(svc_name('sshws',s['id'])+".service")).unlink(missing_ok=True)
        self.response_path(s).unlink(missing_ok=True)
        run(["systemctl","daemon-reload"],True)
        delete_account(s["cfg"]["username"])

    def start(self, s):
        unlock_account(s["cfg"]["username"])
        return run(["systemctl","enable","--now",svc_name('sshws',s['id'])])

    def stop(self, s):
        r=run(["systemctl","disable","--now",svc_name('sshws',s['id'])],True)
        lock_account(s["cfg"]["username"])
        return r

    def restart(self, s):
        return run(["systemctl","restart",svc_name('sshws',s['id'])])

    def status(self, s):
        r=run(["systemctl","is-active",svc_name('sshws',s['id'])],True)
        return "RUNNING" if r.stdout.strip()=="active" else "STOPPED"

    def summary_rows(self, s):
        cfg=s["cfg"]
        return [
            f"{C.WHITE}Username{C.RESET}      : {cfg['username']}",
            f"{C.WHITE}Password{C.RESET}      : {'*'*len(cfg['password'])}",
            f"{C.WHITE}Listen Port{C.RESET}   : {s['port']}  (WebSocket front)",
            f"{C.WHITE}Local sshd{C.RESET}    : 127.0.0.1:{cfg['local_port']}",
            f"{C.WHITE}Response File{C.RESET} : {self.response_path(s)}",
            f"{C.WHITE}Service Unit{C.RESET}  : {svc_name('sshws',s['id'])}.service",
        ]

    def logs(self, s):
        subprocess.run(["journalctl","-u",svc_name('sshws',s['id']),"-n","80","-f"])

# ---- Shadowsocks -----------------------------------------------------

class ShadowsocksBackend:
    key="shadowsocks"; label="Shadowsocks (ss-libev)"

    def add_fields(self, data, port):
        if not shutil.which("ss-server") and not Path(SS_BIN).exists():
            print(C.YELLOW+"[WARN] ss-server not found on PATH - install shadowsocks-libev first."+C.RESET)
        password=ask("Password", gen_password(), secret=True)
        method=ask("Encryption method","chacha20-ietf-poly1305")
        return {"password":password,"method":method}

    def cfg_path(self, s):
        return CFG_DIR/f"{svc_name('ss',s['id'])}.json"

    def provision(self, s):
        cfg=s["cfg"]
        conf={
            "server":"0.0.0.0","server_port":s["port"],"password":cfg["password"],
            "method":cfg["method"],"mode":"tcp_and_udp","fast_open":True
        }
        path=self.cfg_path(s)
        path.write_text(json.dumps(conf,indent=2),encoding="utf-8")
        os.chmod(path,0o600)
        unit=SYSTEMD_DIR/(svc_name('ss',s['id'])+".service")
        unit.write_text(f"""[Unit]
Description=MR VPN TUNNEL - Shadowsocks {s['name']}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={SS_BIN} -c {path}
Restart=on-failure
RestartSec=2
User=root
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
""",encoding="utf-8")
        os.chmod(unit,0o644)
        run(["systemctl","daemon-reload"],True)

    def deprovision(self, s):
        run(["systemctl","disable","--now",svc_name('ss',s['id'])],True)
        (SYSTEMD_DIR/(svc_name('ss',s['id'])+".service")).unlink(missing_ok=True)
        self.cfg_path(s).unlink(missing_ok=True)
        run(["systemctl","daemon-reload"],True)

    def start(self, s):
        return run(["systemctl","enable","--now",svc_name('ss',s['id'])])

    def stop(self, s):
        return run(["systemctl","disable","--now",svc_name('ss',s['id'])],True)

    def restart(self, s):
        return run(["systemctl","restart",svc_name('ss',s['id'])])

    def status(self, s):
        r=run(["systemctl","is-active",svc_name('ss',s['id'])],True)
        return "RUNNING" if r.stdout.strip()=="active" else "STOPPED"

    def summary_rows(self, s):
        cfg=s["cfg"]
        return [
            f"{C.WHITE}Method{C.RESET}        : {cfg['method']}",
            f"{C.WHITE}Password{C.RESET}      : {'*'*len(cfg['password'])}",
            f"{C.WHITE}Config File{C.RESET}   : {self.cfg_path(s)}",
            f"{C.WHITE}Service Unit{C.RESET}  : {svc_name('ss',s['id'])}.service",
        ]

    def logs(self, s):
        subprocess.run(["journalctl","-u",svc_name('ss',s['id']),"-n","80","-f"])

# ---- Xray-core: VMess / VLESS / Trojan ---------------------------------
# One backend, one systemd unit family, three selectable inner protocols
# plus tcp/ws/grpc transport and optional TLS - covers every case the app's
# XrayConfigParser understands (vmess://, vless://, trojan://, or raw JSON).

XRAY_INNER = [("1","vmess"),("2","vless"),("3","trojan")]
XRAY_NETWORK = [("1","tcp"),("2","ws"),("3","grpc")]

class XrayBackend:
    key="xray"; label="VMess / VLESS / Trojan (Xray-core)"

    def add_fields(self, data, port):
        if not shutil.which("xray") and not Path(XRAY_BIN).exists():
            print(C.YELLOW+"[WARN] xray binary not found on PATH - install Xray-core first."+C.RESET)
        inner=dict(XRAY_INNER)[ask_choice("Inner protocol", XRAY_INNER, default="2")]

        if inner=="trojan":
            secret=ask("Password", gen_password())
            alter_id=0
        else:
            secret=ask("UUID", gen_uuid())
            alter_id=ask_int("AlterId (VMess only, 0 = modern/no legacy auth)",0,0,255) if inner=="vmess" else 0

        network=dict(XRAY_NETWORK)[ask_choice("Transport", XRAY_NETWORK, default="2")]
        path=""
        if network in ("ws","grpc"):
            path=ask("Path / gRPC service name", f"/{inner}")

        tls=yes("Report TLS to the client?",True)
        fronted=False
        domain=""
        if tls:
            fronted=yes("Is TLS terminated in front of Xray (Nginx/Cloudflare/CDN)?",True)
            if not fronted:
                domain=ask("Domain (certificate must already exist via certbot)")
        sni=ask("SNI / Host header (domain the app will dial)","")
        allow_insecure=yes("Allow insecure certificate on the client?",True) if tls else False

        return {
            "inner":inner,"secret":secret,"alter_id":alter_id,"network":network,
            "path":path,"tls":tls,"fronted":fronted,"domain":domain,
            "sni":sni,"allow_insecure":allow_insecure
        }

    def cfg_path(self, s):
        return CFG_DIR/f"{svc_name('xray',s['id'])}.json"

    def client_json_path(self, s):
        return CFG_DIR/f"{svc_name('xray',s['id'])}.client.json"

    def _stream_settings(self, s, for_inbound):
        cfg=s["cfg"]
        stream={"network":cfg["network"]}
        host=cfg["sni"] or s.get("vps_ip","")
        if cfg["network"]=="ws":
            stream["wsSettings"]={"headers":{"Host":host},"path":cfg["path"] or f"/{cfg['inner']}"}
        elif cfg["network"]=="grpc":
            stream["grpcSettings"]={"serviceName":cfg["path"] or cfg["inner"]}

        if not cfg["tls"]:
            stream["security"]="none"
            return stream

        stream["security"]="tls"
        if for_inbound and not cfg["fronted"] and cfg["domain"]:
            # Xray itself terminates TLS with a real certificate.
            stream["tlsSettings"]={"certificates":[{
                "certificateFile":f"/etc/letsencrypt/live/{cfg['domain']}/fullchain.pem",
                "keyFile":f"/etc/letsencrypt/live/{cfg['domain']}/privkey.pem"
            }]}
        elif for_inbound and cfg["fronted"]:
            # A reverse proxy / CDN in front already terminates TLS,
            # so Xray itself listens in plain mode.
            stream["security"]="none"
        else:
            # Client side: just report the SNI + allowInsecure the app expects.
            stream["tlsSettings"]={"allowInsecure":cfg["allow_insecure"],"serverName":host}
        return stream

    def _inbound_settings(self, s):
        cfg=s["cfg"]
        if cfg["inner"]=="vmess":
            return {"clients":[{"id":cfg["secret"],"alterId":cfg["alter_id"],"level":8}]}
        if cfg["inner"]=="vless":
            return {"clients":[{"id":cfg["secret"],"level":8}],"decryption":"none"}
        return {"clients":[{"password":cfg["secret"],"level":8}]}  # trojan

    def provision(self, s):
        cfg=s["cfg"]
        conf={
            "inbounds":[{
                "port":s["port"],
                "protocol":cfg["inner"],
                "settings":self._inbound_settings(s),
                "streamSettings":self._stream_settings(s, for_inbound=True)
            }],
            "outbounds":[{"protocol":"freedom"}]
        }
        path=self.cfg_path(s)
        path.write_text(json.dumps(conf,indent=2),encoding="utf-8")
        os.chmod(path,0o600)

        client=self.build_client_json(s)
        cpath=self.client_json_path(s)
        cpath.write_text(json.dumps(client,indent=2),encoding="utf-8")
        os.chmod(cpath,0o600)

        unit=SYSTEMD_DIR/(svc_name('xray',s['id'])+".service")
        unit.write_text(f"""[Unit]
Description=MR VPN TUNNEL - {cfg['inner'].upper()} {s['name']}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={XRAY_BIN} run -c {path}
Restart=on-failure
RestartSec=2
User=root
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
""",encoding="utf-8")
        os.chmod(unit,0o644)
        run(["systemctl","daemon-reload"],True)

    def build_client_json(self, s):
        """Client-import JSON in the exact shape the app's Xray JSON
        importer expects (outbounds[0].protocol/settings/streamSettings/tag)."""
        cfg=s["cfg"]
        address=cfg["sni"] or s.get("vps_ip","")
        inner=cfg["inner"]

        if inner=="trojan":
            settings={"servers":[{"address":address,"port":s["port"],"password":cfg["secret"]}]}
        else:
            user={"id":cfg["secret"],"level":8}
            if inner=="vmess":
                user.update({"alterId":cfg["alter_id"],"security":"auto"})
            else:  # vless
                user["encryption"]="none"
            settings={"vnext":[{"address":address,"port":s["port"],"users":[user]}]}

        return {
            "inbounds":[],
            "outbounds":[{
                "mux":{"enabled":False},
                "protocol":inner,
                "settings":settings,
                "streamSettings":self._stream_settings(s, for_inbound=False),
                "tag":inner.upper()
            }],
            "policy":{"levels":{"8":{"handshake":4,"connIdle":300,"uplinkOnly":1,"downlinkOnly":1}}}
        }

    def deprovision(self, s):
        run(["systemctl","disable","--now",svc_name('xray',s['id'])],True)
        (SYSTEMD_DIR/(svc_name('xray',s['id'])+".service")).unlink(missing_ok=True)
        self.cfg_path(s).unlink(missing_ok=True)
        self.client_json_path(s).unlink(missing_ok=True)
        run(["systemctl","daemon-reload"],True)

    def start(self, s):
        return run(["systemctl","enable","--now",svc_name('xray',s['id'])])

    def stop(self, s):
        return run(["systemctl","disable","--now",svc_name('xray',s['id'])],True)

    def restart(self, s):
        return run(["systemctl","restart",svc_name('xray',s['id'])])

    def status(self, s):
        r=run(["systemctl","is-active",svc_name('xray',s['id'])],True)
        return "RUNNING" if r.stdout.strip()=="active" else "STOPPED"

    def summary_rows(self, s):
        cfg=s["cfg"]
        secret_label="Password" if cfg["inner"]=="trojan" else "UUID"
        rows=[
            f"{C.WHITE}Inner Protocol{C.RESET}: {cfg['inner'].upper()}",
            f"{C.WHITE}{secret_label:<14}{C.RESET}: {cfg['secret']}",
            f"{C.WHITE}Transport{C.RESET}     : {cfg['network']}",
        ]
        if cfg["network"] in ("ws","grpc"):
            rows.append(f"{C.WHITE}Path/Service{C.RESET}  : {cfg['path']}")
        tls_desc="no"
        if cfg["tls"]:
            tls_desc="yes (fronted by reverse proxy/CDN)" if cfg["fronted"] else f"yes ({cfg['domain']})"
        rows.append(f"{C.WHITE}TLS{C.RESET}           : {tls_desc}")
        if cfg["sni"]:
            rows.append(f"{C.WHITE}SNI/Host{C.RESET}      : {cfg['sni']}")
        rows.append(f"{C.WHITE}Config File{C.RESET}   : {self.cfg_path(s)}")
        rows.append(f"{C.WHITE}Client JSON{C.RESET}   : {self.client_json_path(s)}")
        rows.append(f"{C.WHITE}Service Unit{C.RESET}  : {svc_name('xray',s['id'])}.service")
        return rows

    def logs(self, s):
        subprocess.run(["journalctl","-u",svc_name('xray',s['id']),"-n","80","-f"])

BACKENDS = {b.key: b for b in (MrUdpBackend(), SshBackend(), SshWsBackend(), ShadowsocksBackend(), XrayBackend())}

# --------------------------------------------------------------------------
# one-time migration: the old standalone "vless" backend was merged into the
# unified "xray" backend (which also covers vmess/trojan). Any server saved
# under the old key is converted in place, its systemd unit/config are
# regenerated under the new name, and it is restarted if it was running.
# --------------------------------------------------------------------------

def migrate_legacy_protocols(data):
    changed=False
    for s in data:
        if s.get("protocol")!="vless":
            continue
        old=s["cfg"]
        old_svc=svc_name('vless', s['id'])
        was_running=run(["systemctl","is-active",old_svc],True).stdout.strip()=="active"

        run(["systemctl","disable","--now",old_svc],True)
        (SYSTEMD_DIR/(old_svc+".service")).unlink(missing_ok=True)
        (CFG_DIR/(old_svc+".json")).unlink(missing_ok=True)
        run(["systemctl","daemon-reload"],True)

        s["protocol"]="xray"
        s["cfg"]={
            "inner":"vless",
            "secret":old.get("uuid") or gen_uuid(),
            "alter_id":0,
            "network":old.get("network","tcp"),
            "path":old.get("ws_path",""),
            "tls":bool(old.get("tls",False)),
            "fronted":False,
            "domain":old.get("domain",""),
            "sni":old.get("domain",""),
            "allow_insecure":bool(old.get("tls",False)),
        }
        BACKENDS["xray"].provision(s)
        if was_running:
            BACKENDS["xray"].start(s)
        changed=True
        print(C.YELLOW+f"[MIGRATED] '{s['name']}' converted from vless -> xray backend."+C.RESET)
    if changed:
        save(data)
    return changed
PROTOCOL_MENU = [(str(i+1), b.label) for i,b in enumerate(BACKENDS.values())]
PROTOCOL_KEYS = list(BACKENDS.keys())

def backend_for(s):
    if "dns" not in s:
        s["dns"] = {"provider": "none", "hostname": ""}
    return BACKENDS[s["protocol"]]

# --------------------------------------------------------------------------
# shared status / expiry
# --------------------------------------------------------------------------

def status(s):
    exp=datetime.fromisoformat(s["expires"])
    if datetime.now(timezone.utc)>=exp:
        return "EXPIRED", C.RED
    st=backend_for(s).status(s)
    return (st, C.GREEN if st=="RUNNING" else C.YELLOW)

def sync_expired(data):
    for s in data:
        st,_=status(s)
        if st=="EXPIRED":
            backend_for(s).stop(s)

def print_summary(s, title="SERVER SUMMARY"):
    st,_=status(s)
    exp=datetime.fromisoformat(s["expires"]).astimezone()
    rows=[
        f"{C.WHITE}Name{C.RESET}          : {s['name']}",
        f"{C.WHITE}Server ID{C.RESET}     : {s['id']}",
        f"{C.WHITE}Protocol{C.RESET}      : {backend_for(s).label}",
        f"{C.WHITE}VPS IP{C.RESET}        : {s.get('vps_ip') or 'not set'}",
        f"{C.WHITE}Domain{C.RESET}        : {s.get('dns', {}).get('hostname') or 'none'}",
        f"{C.WHITE}Port{C.RESET}          : {s['port']}",
    ]
    rows += backend_for(s).summary_rows(s)
    rows += [
        f"{C.WHITE}Status{C.RESET}        : {st}",
        f"{C.WHITE}Expires{C.RESET}       : {exp.strftime('%Y-%m-%d %H:%M:%S %Z')}",
    ]
    box(title, rows, C.GREEN)

# --------------------------------------------------------------------------
# menu actions
# --------------------------------------------------------------------------

def add_server(data):
    clear(); banner()
    box("ADD SERVER",[
        "Choose a protocol, then enter the server details.",
        "Each server is provisioned independently on this VPS."
    ])
    proto_choice=ask_choice("Protocol", PROTOCOL_MENU, default="1")
    proto_key=PROTOCOL_KEYS[int(proto_choice)-1]
    backend=BACKENDS[proto_key]

    detected=detect_ip()
    vps_ip=ask("VPS IP", detected or None)
    dns=configure_dns(vps_ip)
    name=ask("Server name")
    sid=valid_id(name)
    if any(x["id"]==sid for x in data):
        print(C.RED+"[ERROR] This name already exists."+C.RESET); input("Press Enter..."); return
    default_port=22 if proto_key=="ssh" else 443
    port=ask_int("Port",default_port)
    if port_in_use(data, port):
        print(C.RED+"[ERROR] This port is already used by another server. Choose a different port."+C.RESET)
        input("Press Enter..."); return

    cfg=backend.add_fields(data, port)
    days=ask_int("Validity period (days)",30,1,3650)
    exp=datetime.now(timezone.utc)+timedelta(days=days)
    s={
        "id":sid,"protocol":proto_key,"name":name,"vps_ip":vps_ip,"port":port,
        "created":datetime.now(timezone.utc).isoformat(),"expires":exp.isoformat(),
        "dns":dns,
        "cfg":cfg
    }
    backend.provision(s)
    data.append(s); save(data)
    if yes("Start the server now?",True):
        backend.start(s)
    print(C.GREEN+"[OK] Server added successfully."+C.RESET)
    print()
    print_summary(s, title="NEW SERVER")
    if hasattr(backend, "build_client_json"):
        print()
        box("CLIENT IMPORT JSON (paste into the app)", [], C.YELLOW)
        print(json.dumps(backend.build_client_json(s), indent=2))
    input("Press Enter to continue...")

def list_servers(data):
    clear(); banner()
    if not data:
        box("SERVERS",["No servers found. Use 'Add Server' to create one."])
        input("Press Enter..."); return
    rows=[]
    for i,s in enumerate(data,1):
        st,col=status(s)
        exp=datetime.fromisoformat(s["expires"]).astimezone()
        proto=backend_for(s).key
        rows.append(f"{C.WHITE}{i:>2}{C.RESET}  {C.BOLD}{s['name'][:16]:<16}{C.RESET} "
                    f"{proto:<11} {s['port']:<6} {col}{st:<8}{C.RESET}  "
                    f"{exp.strftime('%Y-%m-%d %H:%M')}")
    box("SERVER LIST",rows,C.BLUE)
    input("Press Enter...")

def choose(data, title="Select a server"):
    if not data:
        print(C.YELLOW+"No servers found."+C.RESET); return None
    for i,s in enumerate(data,1):
        st,_=status(s)
        print(f"  {C.CYAN}{i}{C.RESET}) {s['name']}  [{backend_for(s).key}]  [{st}]  port:{s['port']}")
    v=input(f"{C.YELLOW}>{C.RESET} {title} [0=back]: ").strip()
    try: n=int(v)
    except ValueError: return None
    if 1<=n<=len(data): return data[n-1]
    return None

def edit_server(data):
    clear(); banner()
    s=choose(data,"Select the server to edit")
    if not s: return
    backend=backend_for(s)
    s["name"]=ask("Name",s["name"])
    s["vps_ip"]=ask("VPS IP",s.get("vps_ip",detect_ip()))
    if yes("Change validity period?",False):
        days=ask_int("Days from now",30,1,3650)
        s["expires"]=(datetime.now(timezone.utc)+timedelta(days=days)).isoformat()
    if yes("Re-enter protocol credentials (password/uuid/etc.)?",False):
        was_running=status(s)[0]=="RUNNING"
        backend.deprovision(s)
        s["cfg"]=backend.add_fields(data, s["port"])
        backend.provision(s)
        if was_running: backend.start(s)
    save(data)
    print(C.GREEN+"[OK] Server updated."+C.RESET)
    print()
    print_summary(s, title="UPDATED SERVER")
    input("Press Enter...")

def start_server(data):
    clear(); banner()
    s=choose(data,"Select the server to start")
    if not s:return
    st,_=status(s)
    if st=="EXPIRED":
        print(C.RED+"[ERROR] This server has expired. Renew it first."+C.RESET)
    else:
        r=backend_for(s).start(s)
        print(C.GREEN+"[OK] Server is RUNNING."+C.RESET)
    input("Press Enter...")

def stop_server(data):
    clear(); banner()
    s=choose(data,"Select the server to stop")
    if not s:return
    backend_for(s).stop(s)
    print(C.YELLOW+"[STOPPED] Server has been stopped."+C.RESET)
    input("Press Enter...")

def restart_server(data):
    clear(); banner()
    s=choose(data,"Select the server to restart")
    if not s:return
    st,_=status(s)
    if st=="EXPIRED":
        print(C.RED+"[ERROR] This server has expired."+C.RESET)
    else:
        backend_for(s).restart(s)
        print(C.GREEN+"[OK] Server restarted."+C.RESET)
    input("Press Enter...")

def renew_server(data):
    clear(); banner()
    s=choose(data,"Select the server to renew")
    if not s:return
    days=ask_int("Days to add",30,1,3650)
    old=datetime.fromisoformat(s["expires"])
    now=datetime.now(timezone.utc)
    base=max(old,now)
    s["expires"]=(base+timedelta(days=days)).isoformat()
    save(data)
    print(C.GREEN+f"[OK] Added {days} day(s)."+C.RESET)
    input("Press Enter...")

def delete_server(data):
    clear(); banner()
    s=choose(data,"Select the server to delete")
    if not s:return
    if not yes(f"Are you sure you want to permanently delete {s['name']}?",False): return
    backend_for(s).deprovision(s)
    data.remove(s); save(data)
    print(C.GREEN+"[OK] Server and its local data deleted."+C.RESET)
    input("Press Enter...")

def logs_server(data):
    clear(); banner()
    s=choose(data,"Select the server to view logs")
    if not s:return
    print(C.CYAN+f"\nLogs: {s['name']}  (Ctrl+C to exit)\n"+C.RESET)
    try:
        backend_for(s).logs(s)
    except KeyboardInterrupt:
        pass

def details(data):
    clear(); banner()
    s=choose(data,"Select a server")
    if not s:return
    backend=backend_for(s)
    print_summary(s, title="SERVER DETAILS")
    if hasattr(backend, "build_client_json") and yes("Show client import JSON?",False):
        print()
        box("CLIENT IMPORT JSON (paste into the app)", [], C.YELLOW)
        print(json.dumps(backend.build_client_json(s), indent=2))
    input("Press Enter...")

def main():
    if os.geteuid()!=0:
        print(C.RED+"[ERROR] This manager must be run as root."+C.RESET)
        print("Use: sudo python3 mrvpn_manager.py")
        sys.exit(1)
    ensure()
    while True:
        data=load()
        migrate_legacy_protocols(data)
        sync_expired(data)
        clear(); banner()
        running=sum(status(s)[0]=="RUNNING" for s in data)
        rows=[
            f"{C.WHITE}Total Servers{C.RESET}: {C.CYAN}{len(data)}{C.RESET}    "
            f"{C.WHITE}Running{C.RESET}: {C.GREEN}{running}{C.RESET}",
            "",
            f"{C.GREEN}1{C.RESET}) Add Server",
            f"{C.CYAN}2{C.RESET}) List Servers",
            f"{C.YELLOW}3{C.RESET}) Edit Server",
            f"{C.GREEN}4{C.RESET}) Start Server",
            f"{C.YELLOW}5{C.RESET}) Stop Server",
            f"{C.MAGENTA}6{C.RESET}) Restart Server",
            f"{C.CYAN}7{C.RESET}) Renew Validity",
            f"{C.RED}8{C.RESET}) Delete Server",
            f"{C.BLUE}9{C.RESET}) Details / Status",
            f"{C.WHITE}10{C.RESET}) Logs",
            f"{C.RED}0{C.RESET}) Exit",
        ]
        box("CONTROL PANEL",rows,C.CYAN)
        choice=input(f"\n{C.YELLOW}>{C.RESET} Choice: ").strip()
        actions={
            "1":add_server,"2":list_servers,"3":edit_server,"4":start_server,
            "5":stop_server,"6":restart_server,"7":renew_server,"8":delete_server,
            "9":details,"10":logs_server
        }
        if choice=="0":
            print(C.CYAN+"MR VPN TUNNEL - Server Manager - Goodbye."+C.RESET); break
        fn=actions.get(choice)
        if fn:
            fn(data)
        else:
            print(C.RED+"[ERROR] Invalid choice."+C.RESET); time.sleep(.7)

if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n"+C.YELLOW+"Exited."+C.RESET)
