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
from datetime import datetime, timedelta, timezone
from pathlib import Path

APP = "MR VPN TUNNEL"
BASE = Path("/opt/mr-vpn-manager")
DB = BASE / "servers.json"
CFG_DIR = BASE / "config"
ENV_DIR = BASE / "env"
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
    for d in (BASE, CFG_DIR, ENV_DIR):
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
        run(["useradd","-M","-N","-s","/usr/sbin/nologin",cfg["username"]])
        p=subprocess.run(["chpasswd"],input=f"{cfg['username']}:{cfg['password']}\n",text=True)
        run(["usermod","-U",cfg["username"]],True)  # ensure unlocked

    def deprovision(self, s):
        run(["userdel","-r",s["cfg"]["username"]],True)

    def start(self, s):
        return run(["usermod","-U",s["cfg"]["username"]],True)

    def stop(self, s):
        return run(["usermod","-L",s["cfg"]["username"]],True)

    def restart(self, s):
        return self.start(s)

    def status(self, s):
        r=run(["passwd","-S",s["cfg"]["username"]],True)
        out=r.stdout.strip().split()
        state=out[1] if len(out)>1 else "?"
        return "STOPPED" if state=="L" else "RUNNING"

    def summary_rows(self, s):
        cfg=s["cfg"]
        return [
            f"{C.WHITE}Username{C.RESET}      : {cfg['username']}",
            f"{C.WHITE}Password{C.RESET}      : {'*'*len(cfg['password'])}",
            f"{C.WHITE}Note{C.RESET}          : uses the system's own sshd on port {s['port']}",
        ]

    def logs(self, s):
        subprocess.run(["journalctl","-u","ssh","-n","80","-f"])

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

# ---- VLESS / Xray ------------------------------------------------------

class VlessBackend:
    key="vless"; label="VLESS / V2Ray (Xray-core)"

    def add_fields(self, data, port):
        if not shutil.which("xray") and not Path(XRAY_BIN).exists():
            print(C.YELLOW+"[WARN] xray binary not found on PATH - install Xray-core first."+C.RESET)
        client_id=ask("UUID", gen_uuid())
        network=ask_choice("Transport", [("1","tcp"),("2","ws")], default="1")
        network="tcp" if network=="1" else "ws"
        ws_path=""
        if network=="ws":
            ws_path=ask("WebSocket path","/vless")
        tls=yes("Enable TLS (requires an existing certificate)?",False)
        domain=""
        if tls:
            domain=ask("Domain (certificate must already exist via certbot)")
        return {"uuid":client_id,"network":network,"ws_path":ws_path,"tls":tls,"domain":domain}

    def cfg_path(self, s):
        return CFG_DIR/f"{svc_name('vless',s['id'])}.json"

    def provision(self, s):
        cfg=s["cfg"]
        stream={"network":cfg["network"]}
        if cfg["network"]=="ws":
            stream["wsSettings"]={"path":cfg["ws_path"] or "/vless"}
        if cfg["tls"] and cfg["domain"]:
            stream["security"]="tls"
            stream["tlsSettings"]={"certificates":[{
                "certificateFile":f"/etc/letsencrypt/live/{cfg['domain']}/fullchain.pem",
                "keyFile":f"/etc/letsencrypt/live/{cfg['domain']}/privkey.pem"
            }]}
        else:
            stream["security"]="none"
        conf={
            "inbounds":[{
                "port":s["port"],
                "protocol":"vless",
                "settings":{"clients":[{"id":cfg["uuid"],"level":0}],"decryption":"none"},
                "streamSettings":stream
            }],
            "outbounds":[{"protocol":"freedom"}]
        }
        path=self.cfg_path(s)
        path.write_text(json.dumps(conf,indent=2),encoding="utf-8")
        os.chmod(path,0o600)
        unit=SYSTEMD_DIR/(svc_name('vless',s['id'])+".service")
        unit.write_text(f"""[Unit]
Description=MR VPN TUNNEL - VLESS {s['name']}
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

    def deprovision(self, s):
        run(["systemctl","disable","--now",svc_name('vless',s['id'])],True)
        (SYSTEMD_DIR/(svc_name('vless',s['id'])+".service")).unlink(missing_ok=True)
        self.cfg_path(s).unlink(missing_ok=True)
        run(["systemctl","daemon-reload"],True)

    def start(self, s):
        return run(["systemctl","enable","--now",svc_name('vless',s['id'])])

    def stop(self, s):
        return run(["systemctl","disable","--now",svc_name('vless',s['id'])],True)

    def restart(self, s):
        return run(["systemctl","restart",svc_name('vless',s['id'])])

    def status(self, s):
        r=run(["systemctl","is-active",svc_name('vless',s['id'])],True)
        return "RUNNING" if r.stdout.strip()=="active" else "STOPPED"

    def summary_rows(self, s):
        cfg=s["cfg"]
        rows=[
            f"{C.WHITE}UUID{C.RESET}          : {cfg['uuid']}",
            f"{C.WHITE}Transport{C.RESET}     : {cfg['network']}",
        ]
        if cfg["network"]=="ws":
            rows.append(f"{C.WHITE}WS Path{C.RESET}       : {cfg['ws_path']}")
        rows.append(f"{C.WHITE}TLS{C.RESET}           : {'yes ('+cfg['domain']+')' if cfg['tls'] else 'no'}")
        rows.append(f"{C.WHITE}Config File{C.RESET}   : {self.cfg_path(s)}")
        rows.append(f"{C.WHITE}Service Unit{C.RESET}  : {svc_name('vless',s['id'])}.service")
        return rows

    def logs(self, s):
        subprocess.run(["journalctl","-u",svc_name('vless',s['id']),"-n","80","-f"])

BACKENDS = {b.key: b for b in (MrUdpBackend(), SshBackend(), ShadowsocksBackend(), VlessBackend())}
PROTOCOL_MENU = [(str(i+1), b.label) for i,b in enumerate(BACKENDS.values())]
PROTOCOL_KEYS = list(BACKENDS.keys())

def backend_for(s):
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
        "cfg":cfg
    }
    backend.provision(s)
    data.append(s); save(data)
    if yes("Start the server now?",True):
        backend.start(s)
    print(C.GREEN+"[OK] Server added successfully."+C.RESET)
    print()
    print_summary(s, title="NEW SERVER")
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
    print_summary(s, title="SERVER DETAILS")
    input("Press Enter...")

def main():
    if os.geteuid()!=0:
        print(C.RED+"[ERROR] This manager must be run as root."+C.RESET)
        print("Use: sudo python3 mrvpn_manager.py")
        sys.exit(1)
    ensure()
    while True:
        data=load()
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
