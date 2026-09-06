#!/usr/bin/env python3
# MR VPN TUNNEL - MR-UDP Manager
# Manage MR-UDP servers from the terminal
# Requirements: Python 3 + systemd + /root/mr_udp_server.py
#
# Usage:
#   python3 mrudp_manager.py
#
# Data is stored locally in /opt/mr-udp-manager/servers.json
# Each server runs as an independent systemd service:
#   mr-udp-<id>.service

import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

APP = "MR VPN TUNNEL"
PROTO = "MR-UDP"
BASE = Path("/opt/mr-udp-manager")
DB = BASE / "servers.json"
SERVER_SCRIPT = Path("/root/mr_udp_server.py")
SYSTEMD_DIR = Path("/etc/systemd/system")

class C:
    RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
    GREEN="\033[92m"; CYAN="\033[96m"; YELLOW="\033[93m"
    MAGENTA="\033[95m"; RED="\033[91m"; BLUE="\033[94m"; WHITE="\033[97m"

def clear():
    os.system("clear")

def width():
    try:
        return max(64, min(shutil.get_terminal_size().columns, 100))
    except Exception:
        return 80

def line(ch="-", color=C.DIM):
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

## Plain ASCII (7-bit) letter font, 5 rows tall. Uses only '#' and spaces so
## it renders identically on every terminal/font, unlike heavy Unicode block
## glyphs which some SSH/terminal apps render broken or misaligned.
_FONT = {
    "M": ["#   #","## ##","# # #","#   #","#   #"],
    "R": ["#### ","#   #","#### ","#  # ","#   #"],
    "V": ["#   #","#   #","#   #"," # # ","  #  "],
    "P": ["#### ","#   #","#### ","#    ","#    "],
    "N": ["#   #","##  #","# # #","#  ##","#   #"],
    "T": ["#####","  #  ","  #  ","  #  ","  #  "],
    "U": ["#   #","#   #","#   #","#   #"," ### "],
    "L": ["#    ","#    ","#    ","#    ","#####"],
    "E": ["#####","#    ","#### ","#    ","#####"],
    " ": ["   ","   ","   ","   ","   "],
}

def _build_banner_art(text, gap=1):
    glyphs=[_FONT[ch] for ch in text]
    rows=[]
    for r in range(5):
        rows.append((" "*gap).join(g[r] for g in glyphs))
    return rows

def banner():
    print()
    title="MR VPN TUNNEL"
    art=_build_banner_art(title)
    art_width=len(art[0]) if art else 0
    if art_width<=width():
        for row in art:
            print(C.CYAN+C.BOLD+row+C.RESET)
        print(C.MAGENTA+C.BOLD+"MR-UDP MANAGER"+C.RESET)
    else:
        # Terminal too narrow for the big letters - fall back to plain text
        # instead of letting it wrap and look broken.
        print(C.CYAN+C.BOLD+title+C.RESET)
        print(C.MAGENTA+C.BOLD+"MR-UDP MANAGER"+C.RESET)
    line("=", C.MAGENTA)

def ensure():
    BASE.mkdir(parents=True, exist_ok=True)
    if not DB.exists():
        DB.write_text("[]", encoding="utf-8")
    if not SERVER_SCRIPT.exists():
        print(f"{C.RED}[ERROR] File not found: {SERVER_SCRIPT}{C.RESET}")
        print(f"{C.YELLOW}Place mr_udp_server.py in /root/ before running the manager.{C.RESET}")
        sys.exit(1)

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

def yes(prompt, default=False):
    d="Y/n" if default else "y/N"
    v=input(f"{C.YELLOW}>{C.RESET} {C.CYAN}{prompt}{C.RESET} ({d}): ").strip().lower()
    if not v: return default
    return v in ("y","yes","1")

def service_name(sid):
    return f"mr-udp-{sid}"

def valid_id(name):
    return re.sub(r"[^a-zA-Z0-9_-]+","-",name.strip()).strip("-_").lower()[:32] or "server"

def run(cmd, quiet=False):
    p=subprocess.run(cmd,text=True,capture_output=True)
    if p.returncode and not quiet:
        err=p.stderr.strip() or p.stdout.strip()
        if err: print(C.RED+err+C.RESET)
    return p

def service_file(s):
    sid=s["id"]
    user=s["username"].replace("'","'\\''")
    password=s["password"].replace("'","'\\''")
    port=s["port"]
    # EnvironmentFile avoids putting credentials in the ExecStart command line.
    envdir=BASE/"env"
    envdir.mkdir(parents=True,exist_ok=True)
    env=envdir/f"{sid}.env"
    env.write_text(
        f"MR_USER='{user}'\nMR_PASS='{password}'\nMR_PORT='{port}'\n",
        encoding="utf-8"
    )
    os.chmod(env,0o600)
    unit=SYSTEMD_DIR/(service_name(sid)+".service")
    unit.write_text(f"""[Unit]
Description=MR VPN TUNNEL - MR-UDP {s['name']}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile={env}
ExecStart=/usr/bin/python3 {SERVER_SCRIPT} --port $MR_PORT
Restart=on-failure
RestartSec=2
User=root
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
""",encoding="utf-8")
    os.chmod(unit,0o644)
    return unit

def status(s):
    r=run(["systemctl","is-active",service_name(s["id"])],True)
    active=r.stdout.strip()=="active"
    exp=datetime.fromisoformat(s["expires"])
    expired=datetime.now(timezone.utc)>=exp
    if expired:
        return "EXPIRED", C.RED
    if active:
        return "RUNNING", C.GREEN
    return "STOPPED", C.YELLOW

def sync_expired(data):
    changed=False
    for s in data:
        st,_=status(s)
        if st=="EXPIRED":
            run(["systemctl","stop",service_name(s["id"])],True)
    return changed

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

def print_summary(s, title="SERVER SUMMARY"):
    """Clean, professional server info block shown after save/details."""
    st,_=status(s)
    exp=datetime.fromisoformat(s["expires"]).astimezone()
    w=width()
    rows=[
        f"{C.WHITE}Name{C.RESET}          : {s['name']}",
        f"{C.WHITE}Server ID{C.RESET}     : {s['id']}",
        f"{C.WHITE}VPS IP{C.RESET}        : {s.get('vps_ip') or 'not set'}",
        f"{C.WHITE}Protocol{C.RESET}      : {PROTO}",
        f"{C.WHITE}Port{C.RESET}          : {s['port']}",
        f"{C.WHITE}Username{C.RESET}      : {s['username']}",
        f"{C.WHITE}Password{C.RESET}      : {'*'*len(s['password'])}",
        f"{C.WHITE}Status{C.RESET}        : {st}",
        f"{C.WHITE}Expires{C.RESET}       : {exp.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"{C.WHITE}Service Unit{C.RESET}  : {service_name(s['id'])}.service",
    ]
    box(title, rows, C.GREEN)

def add_server(data):
    clear(); banner()
    box("ADD SERVER",[
        "Enter the VPS and server details.",
        "The server will be registered as an independent systemd service.",
        "Each server can have its own port, username, and password."
    ])
    detected=detect_ip()
    vps_ip=ask("VPS IP", detected or None)
    name=ask("Server name")
    sid=valid_id(name)
    if any(x["id"]==sid for x in data):
        print(C.RED+"[ERROR] This name already exists."+C.RESET); input("Press Enter..."); return
    port=ask_int("UDP Port",4433)
    if any(int(x.get("port",0))==port for x in data):
        print(C.RED+"[ERROR] This UDP port is already in use by another server. Choose a different port."+C.RESET)
        input("Press Enter..."); return
    username=ask("Username","mrudp")
    password=ask("Password",secret=True)
    days=ask_int("Validity period (days)",30,1,3650)
    exp=datetime.now(timezone.utc)+timedelta(days=days)
    s={
        "id":sid,"name":name,"vps_ip":vps_ip,"port":port,"username":username,
        "password":password,"created":datetime.now(timezone.utc).isoformat(),
        "expires":exp.isoformat()
    }
    data.append(s); save(data)
    service_file(s)
    run(["systemctl","daemon-reload"],True)
    if yes("Start the server now?",True):
        run(["systemctl","enable","--now",service_name(sid)])
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
        rows.append(f"{C.WHITE}{i:>2}{C.RESET}  {C.BOLD}{s['name'][:20]:<20}{C.RESET} "
                    f"{s['port']:<6} {col}{st:<8}{C.RESET}  "
                    f"{exp.strftime('%Y-%m-%d %H:%M')}")
    box("MR-UDP SERVER LIST",rows,C.BLUE)
    input("Press Enter...")

def choose(data, title="Select a server"):
    if not data:
        print(C.YELLOW+"No servers found."+C.RESET); return None
    for i,s in enumerate(data,1):
        st,_=status(s)
        print(f"  {C.CYAN}{i}{C.RESET}) {s['name']}  [{st}]  UDP:{s['port']}")
    v=input(f"{C.YELLOW}>{C.RESET} {title} [0=back]: ").strip()
    try: n=int(v)
    except ValueError: return None
    if 1<=n<=len(data): return data[n-1]
    return None

def edit_server(data):
    clear(); banner()
    s=choose(data,"Select the server to edit")
    if not s: return
    oldid=s["id"]
    s["name"]=ask("Name",s["name"])
    s["vps_ip"]=ask("VPS IP",s.get("vps_ip",detect_ip()))
    newport=ask_int("UDP Port",s["port"])
    if any(x is not s and int(x.get("port",0))==newport for x in data):
        print(C.RED+"[ERROR] This UDP port is already in use by another server."+C.RESET); input("Press Enter..."); return
    s["username"]=ask("Username",s["username"])
    pw=input(f"{C.YELLOW}>{C.RESET} Password {C.DIM}[Enter = keep current]{C.RESET}: ").strip()
    if pw: s["password"]=pw
    s["port"]=newport
    if yes("Change validity period?",False):
        days=ask_int("Days from now",30,1,3650)
        s["expires"]=(datetime.now(timezone.utc)+timedelta(days=days)).isoformat()
    run(["systemctl","stop",service_name(oldid)],True)
    service_file(s)
    save(data)
    run(["systemctl","daemon-reload"],True)
    if yes("Start the server after editing?",True):
        run(["systemctl","enable","--now",service_name(s["id"])])
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
        service_file(s); run(["systemctl","daemon-reload"],True)
        r=run(["systemctl","enable","--now",service_name(s["id"])])
        if r.returncode==0: print(C.GREEN+"[OK] Server is RUNNING."+C.RESET)
    input("Press Enter...")

def stop_server(data):
    clear(); banner()
    s=choose(data,"Select the server to stop")
    if not s:return
    run(["systemctl","disable","--now",service_name(s["id"])],True)
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
        run(["systemctl","restart",service_name(s["id"])])
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
    sid=s["id"]
    run(["systemctl","disable","--now",service_name(sid)],True)
    unit=SYSTEMD_DIR/(service_name(sid)+".service")
    env=BASE/"env"/f"{sid}.env"
    unit.unlink(missing_ok=True); env.unlink(missing_ok=True)
    data.remove(s); save(data)
    run(["systemctl","daemon-reload"],True)
    print(C.GREEN+"[OK] Server, service, and local data deleted."+C.RESET)
    input("Press Enter...")

def logs_server(data):
    clear(); banner()
    s=choose(data,"Select the server to view logs")
    if not s:return
    print(C.CYAN+f"\nLogs: {s['name']}  (Ctrl+C to exit)\n"+C.RESET)
    try:
        subprocess.run(["journalctl","-u",service_name(s["id"]),"-n","80","-f"])
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
        print("Use: sudo python3 mrudp_manager.py")
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
            print(C.CYAN+"MR VPN TUNNEL - MR-UDP Manager - Goodbye."+C.RESET); break
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
