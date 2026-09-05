#!/usr/bin/env python3
# MR VPN TUNNEL • MR-UDP Manager
# إدارة سيرفرات MR-UDP من Terminal
# المتطلبات: Python 3 + systemd + /root/mr_udp_server.py
#
# الاستخدام:
#   python3 mrudp_manager.py
#
# البيانات تحفظ محلياً في /opt/mr-udp-manager/servers.json
# كل سيرفر يعمل كـ systemd service مستقل:
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

def line(ch="─", color=C.DIM):
    print(color + ch * width() + C.RESET)

def box(title, rows, color=C.CYAN):
    w=width()
    print(f"{color}╭{'─'*(w-2)}╮{C.RESET}")
    title=f" {title} "
    pad=max(0,w-4-len(title))
    print(f"{color}│{C.RESET} {C.BOLD}{C.MAGENTA}{title}{C.RESET}{' '*pad} {color}│{C.RESET}")
    print(f"{color}├{'─'*(w-2)}┤{C.RESET}")
    for row in rows:
        row=str(row)
        print(f"{color}│{C.RESET} {row[:w-4]:<{w-4}} {color}│{C.RESET}")
    print(f"{color}╰{'─'*(w-2)}╯{C.RESET}")

def banner():
    print()
    art=[
        "███╗   ███╗██████╗       ██╗   ██╗██████╗ ",
        "████╗ ████║██╔══██╗      ██║   ██║██╔══██╗",
        "██╔████╔██║██████╔╝█████╗██║   ██║██║  ██║",
        "██║╚██╔╝██║██╔══██╗╚════╝╚██╗ ██╔╝██║  ██║",
        "██║ ╚═╝ ██║██║  ██║       ╚████╔╝ ██████╔╝",
        "╚═╝     ╚═╝╚═╝  ╚═╝        ╚═══╝  ╚═════╝ ",
    ]
    for x in art:
        print(C.CYAN+C.BOLD+x+C.RESET)
    print(C.MAGENTA+C.BOLD+"             MR VPN TUNNEL  •  MR-UDP MANAGER"+C.RESET)
    line("═", C.MAGENTA)

def ensure():
    BASE.mkdir(parents=True, exist_ok=True)
    if not DB.exists():
        DB.write_text("[]", encoding="utf-8")
    if not SERVER_SCRIPT.exists():
        print(f"{C.RED}✘ ما لقيتش {SERVER_SCRIPT}{C.RESET}")
        print(f"{C.YELLOW}حط mr_udp_server.py في /root/ قبل تشغيل المدير.{C.RESET}")
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
            v=input(f"{C.YELLOW}➤{C.RESET} {C.CYAN}{prompt}{C.RESET}: ").strip()
            if v: return v
    else:
        v=input(f"{C.YELLOW}➤{C.RESET} {C.CYAN}{prompt}{C.RESET} {C.DIM}[{shown}]{C.RESET}: ").strip()
        return v if v else default

def ask_int(prompt, default, minimum=1, maximum=65535):
    while True:
        v=input(f"{C.YELLOW}➤{C.RESET} {C.CYAN}{prompt}{C.RESET} {C.DIM}[{default}]{C.RESET}: ").strip()
        if not v: return default
        try:
            n=int(v)
            if minimum<=n<=maximum: return n
        except ValueError:
            pass
        print(f"{C.RED}✘ رقم غير صحيح ({minimum}-{maximum}).{C.RESET}")

def yes(prompt, default=False):
    d="Y/n" if default else "y/N"
    v=input(f"{C.YELLOW}➤{C.RESET} {C.CYAN}{prompt}{C.RESET} ({d}): ").strip().lower()
    if not v: return default
    return v in ("y","yes","1","نعم","ن")

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

def add_server(data):
    clear(); banner()
    box("إضافة سيرفر MR-UDP",[
        "دخل معلومات VPS والسيرفر غادي يتسجل كـ systemd service مستقل.",
        "مثال: كل سيرفر يقدر يكون عندو Port و Username و Password مختلف."
    ])
    detected=detect_ip()
    vps_ip=ask("VPS IP", detected or None)
    name=ask("اسم السيرفر")
    sid=valid_id(name)
    if any(x["id"]==sid for x in data):
        print(C.RED+"✘ الاسم موجود من قبل."+C.RESET); input("Enter..."); return
    port=ask_int("UDP Port",4433)
    if any(int(x.get("port",0))==port for x in data):
        print(C.RED+"✘ هذا UDP Port مستعمل من سيرفر آخر. اختار Port مختلف."+C.RESET)
        input("Enter..."); return
    username=ask("Username","mrudp")
    password=ask("Password",secret=True)
    days=ask_int("مدة الصلاحية بالأيام",30,1,3650)
    exp=datetime.now(timezone.utc)+timedelta(days=days)
    s={
        "id":sid,"name":name,"vps_ip":vps_ip,"port":port,"username":username,
        "password":password,"created":datetime.now(timezone.utc).isoformat(),
        "expires":exp.isoformat()
    }
    data.append(s); save(data)
    service_file(s)
    run(["systemctl","daemon-reload"],True)
    if yes("تشغيل السيرفر الآن؟",True):
        run(["systemctl","enable","--now",service_name(sid)])
    print(C.GREEN+"✔ تمت إضافة السيرفر."+C.RESET)
    input("Enter للرجوع...")

def list_servers(data):
    clear(); banner()
    if not data:
        box("السيرفرات",["ما كاين حتى سيرفر. استعمل ➕ إضافة سيرفر."])
        input("Enter..."); return
    rows=[]
    for i,s in enumerate(data,1):
        st,col=status(s)
        exp=datetime.fromisoformat(s["expires"]).astimezone()
        rows.append(f"{C.WHITE}{i:>2}{C.RESET}  {C.BOLD}{s['name'][:20]:<20}{C.RESET} "
                    f"{s['port']:<6} {col}{st:<8}{C.RESET}  "
                    f"{exp.strftime('%Y-%m-%d %H:%M')}")
    box("قائمة MR-UDP Servers",rows,C.BLUE)
    input("Enter للرجوع...")

def choose(data, title="اختار السيرفر"):
    if not data:
        print(C.YELLOW+"ما كاين حتى سيرفر."+C.RESET); return None
    for i,s in enumerate(data,1):
        st,_=status(s)
        print(f"  {C.CYAN}{i}{C.RESET}) {s['name']}  [{st}]  UDP:{s['port']}")
    v=input(f"{C.YELLOW}➤{C.RESET} {title} [0=رجوع]: ").strip()
    try: n=int(v)
    except ValueError: return None
    if 1<=n<=len(data): return data[n-1]
    return None

def edit_server(data):
    clear(); banner()
    s=choose(data,"اختار السيرفر للتعديل")
    if not s: return
    oldid=s["id"]
    s["name"]=ask("الاسم",s["name"])
    s["vps_ip"]=ask("VPS IP",s.get("vps_ip",detect_ip()))
    newport=ask_int("UDP Port",s["port"])
    if any(x is not s and int(x.get("port",0))==newport for x in data):
        print(C.RED+"✘ هذا UDP Port مستعمل من سيرفر آخر."+C.RESET); input("Enter..."); return
    s["username"]=ask("Username",s["username"])
    pw=input(f"{C.YELLOW}➤{C.RESET} Password {C.DIM}[Enter = نفس القديم]{C.RESET}: ").strip()
    if pw: s["password"]=pw
    s["port"]=newport
    if yes("تغيير مدة الصلاحية؟",False):
        days=ask_int("عدد الأيام من الآن",30,1,3650)
        s["expires"]=(datetime.now(timezone.utc)+timedelta(days=days)).isoformat()
    run(["systemctl","stop",service_name(oldid)],True)
    service_file(s)
    save(data)
    run(["systemctl","daemon-reload"],True)
    if yes("تشغيل السيرفر بعد التعديل؟",True):
        run(["systemctl","enable","--now",service_name(s["id"])])
    print(C.GREEN+"✔ تم تعديل السيرفر."+C.RESET)
    input("Enter...")

def start_server(data):
    clear(); banner()
    s=choose(data,"اختار السيرفر للتشغيل")
    if not s:return
    st,_=status(s)
    if st=="EXPIRED":
        print(C.RED+"✘ السيرفر منتهي الصلاحية. جدد المدة أولاً."+C.RESET)
    else:
        service_file(s); run(["systemctl","daemon-reload"],True)
        r=run(["systemctl","enable","--now",service_name(s["id"])])
        if r.returncode==0: print(C.GREEN+"✔ السيرفر RUNNING."+C.RESET)
    input("Enter...")

def stop_server(data):
    clear(); banner()
    s=choose(data,"اختار السيرفر للإيقاف")
    if not s:return
    run(["systemctl","disable","--now",service_name(s["id"])],True)
    print(C.YELLOW+"⏸ تم إيقاف السيرفر."+C.RESET)
    input("Enter...")

def restart_server(data):
    clear(); banner()
    s=choose(data,"اختار السيرفر لإعادة التشغيل")
    if not s:return
    st,_=status(s)
    if st=="EXPIRED":
        print(C.RED+"✘ السيرفر منتهي الصلاحية."+C.RESET)
    else:
        run(["systemctl","restart",service_name(s["id"])])
        print(C.GREEN+"✔ تم Restart."+C.RESET)
    input("Enter...")

def renew_server(data):
    clear(); banner()
    s=choose(data,"اختار السيرفر لتجديد الصلاحية")
    if not s:return
    days=ask_int("إضافة أيام",30,1,3650)
    old=datetime.fromisoformat(s["expires"])
    now=datetime.now(timezone.utc)
    base=max(old,now)
    s["expires"]=(base+timedelta(days=days)).isoformat()
    save(data)
    print(C.GREEN+f"✔ تمت إضافة {days} يوم."+C.RESET)
    input("Enter...")

def delete_server(data):
    clear(); banner()
    s=choose(data,"اختار السيرفر للحذف")
    if not s:return
    if not yes(f"متأكد تحذف {s['name']} نهائياً؟",False): return
    sid=s["id"]
    run(["systemctl","disable","--now",service_name(sid)],True)
    unit=SYSTEMD_DIR/(service_name(sid)+".service")
    env=BASE/"env"/f"{sid}.env"
    unit.unlink(missing_ok=True); env.unlink(missing_ok=True)
    data.remove(s); save(data)
    run(["systemctl","daemon-reload"],True)
    print(C.GREEN+"✔ تم حذف السيرفر والخدمة والبيانات المحلية."+C.RESET)
    input("Enter...")

def logs_server(data):
    clear(); banner()
    s=choose(data,"اختار السيرفر لعرض Logs")
    if not s:return
    print(C.CYAN+f"\nLogs: {s['name']}  (Ctrl+C للخروج)\n"+C.RESET)
    try:
        subprocess.run(["journalctl","-u",service_name(s["id"]),"-n","80","-f"])
    except KeyboardInterrupt:
        pass

def details(data):
    clear(); banner()
    s=choose(data,"اختار السيرفر")
    if not s:return
    st,_=status(s)
    exp=datetime.fromisoformat(s["expires"]).astimezone()
    rows=[
        f"{C.WHITE}Name{C.RESET}       : {s['name']}",
        f"{C.WHITE}VPS IP{C.RESET}    : {s.get('vps_ip','غير محدد')}",
        f"{C.WHITE}UDP Port{C.RESET}   : {s['port']}",
        f"{C.WHITE}Username{C.RESET}   : {s['username']}",
        f"{C.WHITE}Password{C.RESET}   : {'*'*len(s['password'])}",
        f"{C.WHITE}Status{C.RESET}     : {st}",
        f"{C.WHITE}Expires{C.RESET}    : {exp.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"{C.WHITE}Service{C.RESET}    : {service_name(s['id'])}",
    ]
    box("تفاصيل السيرفر",rows,C.GREEN)
    input("Enter...")

def main():
    if os.geteuid()!=0:
        print(C.RED+"✘ خاصك تشغل المدير بصلاحية root."+C.RESET)
        print("استعمل: sudo python3 mrudp_manager.py")
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
            f"{C.GREEN}1{C.RESET}) ➕ إضافة سيرفر",
            f"{C.CYAN}2{C.RESET}) 📋 قائمة السيرفرات",
            f"{C.YELLOW}3{C.RESET}) ✏️ تعديل سيرفر",
            f"{C.GREEN}4{C.RESET}) ▶️ تشغيل سيرفر",
            f"{C.YELLOW}5{C.RESET}) ⏸️ إيقاف سيرفر",
            f"{C.MAGENTA}6{C.RESET}) 🔄 Restart",
            f"{C.CYAN}7{C.RESET}) ⏳ تجديد الصلاحية",
            f"{C.RED}8{C.RESET}) 🗑️ حذف سيرفر",
            f"{C.BLUE}9{C.RESET}) 📊 تفاصيل/حالة",
            f"{C.WHITE}10{C.RESET}) 📝 Logs",
            f"{C.RED}0{C.RESET}) 🚪 خروج",
        ]
        box("لوحة التحكم",rows,C.CYAN)
        choice=input(f"\n{C.YELLOW}➤{C.RESET} اختيار: ").strip()
        actions={
            "1":add_server,"2":list_servers,"3":edit_server,"4":start_server,
            "5":stop_server,"6":restart_server,"7":renew_server,"8":delete_server,
            "9":details,"10":logs_server
        }
        if choice=="0":
            print(C.CYAN+"MR VPN TUNNEL • MR-UDP Manager — إلى اللقاء 👋"+C.RESET); break
        fn=actions.get(choice)
        if fn:
            fn(data)
        else:
            print(C.RED+"✘ اختيار غير صحيح."+C.RESET); time.sleep(.7)

if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n"+C.YELLOW+"تم الخروج."+C.RESET)

