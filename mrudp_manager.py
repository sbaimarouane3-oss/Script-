#!/usr/bin/env python3
# MR VPN TUNNEL Server Manager v2
# Server-side manager matched to MR VPN TUNNEL's SSH, MR-UDP and Xray paths.

import json, os, re, shlex, shutil, socket, subprocess, sys, time, urllib.request
from pathlib import Path

BASE = Path('/opt/mr-vpn-tunnel')
DB = BASE / 'servers.json'
ENV = BASE / 'env'
CONF = BASE / 'xray'
UNIT = Path('/etc/systemd/system')
MRUDP_DEFAULT = Path('/root/mr_udp_server.py')
PROXY_SCRIPT = BASE / 'mrproxy.py'

PROTO = {
    '1': 'mrudp',
    '2': 'ssh',
    '3': 'vless',
    '4': 'vmess',
    '5': 'trojan',
    '6': 'shadowsocks',
}


def run(cmd, check=False, input_text=None):
    p = subprocess.run(cmd, shell=True, text=True, input=input_text,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if check and p.returncode != 0:
        raise RuntimeError(p.stdout.strip() or f'command failed: {cmd}')
    return p.returncode, p.stdout.strip()


def q(s):
    return shlex.quote(str(s))


def valid_user(name):
    return bool(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', name or ''))


def valid_port(p):
    try:
        p = int(p)
        return 1 <= p <= 65535
    except Exception:
        return False


def load():
    BASE.mkdir(parents=True, exist_ok=True); ENV.mkdir(exist_ok=True); CONF.mkdir(exist_ok=True)
    if not DB.exists(): return []
    try:
        return json.loads(DB.read_text())
    except Exception:
        return []


def save(data):
    BASE.mkdir(parents=True, exist_ok=True)
    tmp = DB.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    os.chmod(tmp, 0o600); tmp.replace(DB)


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(('1.1.1.1', 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return 'SERVER-IP'


def public_ip():
    for url in ('https://api.ipify.org', 'https://ifconfig.me/ip'):
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                x = r.read().decode().strip()
                if x: return x
        except Exception: pass
    return local_ip()


def ask(prompt, default=''):
    x = input(f'{prompt}' + (f' [{default}]' if default else '') + ': ').strip()
    return x or default


def unit_name(s):
    return f"mrvpn-{s['id']}.service"


def systemd_start(name):
    rc, out = run(f'systemctl daemon-reload && systemctl enable --now {q(name)}')
    return rc == 0, out


def systemd_stop(name):
    run(f'systemctl disable --now {q(name)}')


def status(s):
    unit = unit_name(s)
    rc, out = run(f'systemctl is-active {q(unit)}')
    return out if out else 'inactive'


def free_port(data, port, ignore=None):
    for s in data:
        if ignore and s.get('id') == ignore: continue
        if int(s.get('port', -1)) == int(port) or int(s.get('proxy_port', -1)) == int(port): return False
    return True


def ensure_root():
    if os.geteuid() != 0:
        print('[ERR] Run as root.'); sys.exit(1)


def install_base():
    print('[*] Installing base packages...')
    run('apt-get update -y', check=True)
    run('apt-get install -y openssh-server curl ca-certificates unzip', check=True)
    run('systemctl enable --now ssh || systemctl enable --now sshd')
    print('[OK] Base packages ready.')



def ensure_ssh_user(user, password):
    rc, _ = run(f'id {q(user)}')
    if rc != 0:
        rc, out = run(f'useradd -m -s /bin/bash {q(user)}')
        if rc != 0:
            print('[ERR] useradd failed:', out); return False
    rc, out = run('chpasswd', input_text=f'{user}:{password}\n')
    if rc != 0:
        print('[ERR] chpasswd failed:', out); return False
    run(f'usermod -s /bin/bash {q(user)}')
    return True


def configure_sshd_port(port):
    sshd_cfg = Path('/etc/ssh/sshd_config')
    backup = sshd_cfg.read_text() if sshd_cfg.exists() else ''
    if port == 22:
        return True
    lines = backup.splitlines()
    first_match = next((i for i, line in enumerate(lines)
                        if re.match(r'^\s*Match\b', line)), len(lines))
    if not any(re.match(r'^\s*Port\s+' + re.escape(str(port)) + r'\s*$', x)
               for x in lines[:first_match]):
        lines.insert(first_match, f'Port {port}')
        sshd_cfg.write_text('\n'.join(lines) + '\n')
    rc, out = run('sshd -t')
    if rc != 0:
        sshd_cfg.write_text(backup)
        print('[ERR] sshd config test failed:', out); return False
    rc, out = run('systemctl restart ssh || systemctl restart sshd')
    if rc != 0:
        sshd_cfg.write_text(backup)
        run('systemctl restart ssh || systemctl restart sshd')
        print('[ERR] SSH restart failed:', out); return False
    rc, out = run(f"ss -lntH | awk '$4 ~ /:{int(port)}$/ {{print $4}}'")
    if rc != 0 or not out:
        sshd_cfg.write_text(backup)
        run('systemctl restart ssh || systemctl restart sshd')
        print(f'[ERR] sshd is not listening on TCP port {port}; configuration rolled back.')
        return False
    return True


def write_proxy_script():
    BASE.mkdir(parents=True, exist_ok=True)
    code = '''#!/usr/bin/env python3
import selectors, socket, threading
MAX_HEADER = 16384

def recv_headers(conn):
    conn.settimeout(5.0)
    data = bytearray()
    while len(data) < MAX_HEADER:
        chunk = conn.recv(min(4096, MAX_HEADER - len(data)))
        if not chunk: break
        data.extend(chunk)
        if b"\\r\\n\\r\\n" in data or b"\\n\\n" in data: break
    return bytes(data)

def bridge(a, b):
    sel = selectors.DefaultSelector()
    sel.register(a, selectors.EVENT_READ, b)
    sel.register(b, selectors.EVENT_READ, a)
    try:
        while True:
            events = sel.select(timeout=300)
            if not events: return
            for key, _ in events:
                src, dst = key.fileobj, key.data
                try: data = src.recv(65536)
                except OSError: return
                if not data: return
                try: dst.sendall(data)
                except OSError: return
    finally:
        try: sel.unregister(a)
        except Exception: pass
        try: sel.unregister(b)
        except Exception: pass

def handle(client, target_host, target_port):
    try:
        req = recv_headers(client)
        if not req: return
        upstream = socket.create_connection((target_host, target_port), timeout=5)
        try:
            client.sendall(b"HTTP/1.1 200 Connection Established\\r\\nConnection: keep-alive\\r\\n\\r\\n")
            client.settimeout(None); upstream.settimeout(None)
            bridge(client, upstream)
        finally:
            try: upstream.close()
            except Exception: pass
    except Exception:
        try: client.sendall(b"HTTP/1.1 502 Bad Gateway\\r\\nConnection: close\\r\\n\\r\\n")
        except Exception: pass
    finally:
        try: client.close()
        except Exception: pass

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--listen', type=int, required=True)
    ap.add_argument('--target-host', default='127.0.0.1')
    ap.add_argument('--target-port', type=int, required=True)
    args = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', args.listen)); srv.listen(128)
    print(f'MR VPN TUNNEL Proxy listening on 0.0.0.0:{args.listen} -> {args.target_host}:{args.target_port}', flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c, args.target_host, args.target_port), daemon=True).start()

if __name__ == '__main__': main()
'''
    PROXY_SCRIPT.write_text(code)
    os.chmod(PROXY_SCRIPT, 0o755)


def ssh_proxy_payload_add(data):
    name = ask('Server name', 'SSH-Proxy-Payload')
    try:
        ssh_port = int(ask('SSH port', '80'))
        proxy_port = int(ask('Remote Proxy port', '8080'))
    except ValueError:
        print('[ERR] Invalid port.'); return
    if not valid_port(ssh_port) or not valid_port(proxy_port):
        print('[ERR] Invalid port.'); return
    if ssh_port == proxy_port:
        print('[ERR] SSH port and Remote Proxy port must be different.'); return
    if not free_port(data, proxy_port):
        print('[ERR] Remote Proxy port is already used by this manager.'); return

    existing = next((x for x in data
                     if x.get('protocol') == 'ssh' and int(x.get('port', -1)) == ssh_port), None)
    if existing:
        user = existing.get('username', '')
        password = existing.get('password', '')
        print(f'[OK] Reusing existing SSH server on port {ssh_port} (user={user}).')
    else:
        if not free_port(data, ssh_port):
            print('[ERR] SSH port is already used by another manager server.'); return
        while True:
            user = ask('SSH username', 'mruser')
            if valid_user(user): break
            print('[ERR] Invalid Linux username. Example: mruser or vpn_user')
        password = ask('SSH password')
        if not password:
            print('[ERR] Password cannot be empty.'); return
        if not ensure_ssh_user(user, password): return
        if not configure_sshd_port(ssh_port): return

    write_proxy_script()
    sid = f'sshpp-{int(time.time())}'
    env = ENV / f'{sid}.env'
    env.write_text(f'PROXY_PORT={proxy_port}\nSSH_PORT={ssh_port}\n')
    os.chmod(env, 0o600)
    unit = UNIT / f'{sid}.service'
    unit.write_text(f'''[Unit]
Description=MR VPN TUNNEL SSH Proxy Payload {name}
After=network-online.target ssh.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile={env}
ExecStart=/usr/bin/python3 {PROXY_SCRIPT} --listen $PROXY_PORT --target-host 127.0.0.1 --target-port $SSH_PORT
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
''')
    rec = {'id':sid,'protocol':'ssh-proxy-payload','name':name,'port':ssh_port,
           'proxy_port':proxy_port,'username':user,'password':password,'created':int(time.time())}
    ok, out = systemd_start(unit.name)
    if not ok:
        unit.unlink(missing_ok=True); env.unlink(missing_ok=True)
        print('[ERR] Proxy service failed to start:\n', out); return
    time.sleep(1)
    if status(rec) != 'active':
        run(f'systemctl status {q(unit.name)} --no-pager -l')
        systemd_stop(unit.name); unit.unlink(missing_ok=True); env.unlink(missing_ok=True)
        print('[ERR] Proxy service is not active.'); return
    data.append(rec); save(data)
    ip = public_ip()
    print('[OK] SSH-Proxy-Payload RUNNING')
    print(f'     SSH:          {ip}:{ssh_port}/tcp')
    print(f'     Remote Proxy: {ip}:{proxy_port}/tcp')
    print(f'     Username:     {user}')
    print(f'     Password:     {password}')
    print('     Payload: GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]')


def ssh_add(data):
    name = ask('Server name', 'SSH-Server')
    while True:
        user = ask('SSH username', 'mruser')
        if valid_user(user): break
        print('[ERR] Invalid Linux username. Example: mruser or vpn_user')
    password = ask('SSH password')
    if not password:
        print('[ERR] Password cannot be empty.'); return
    port = int(ask('SSH port', '22'))
    if not valid_port(port): print('[ERR] Invalid port.'); return
    if not free_port(data, port): print('[ERR] Port already used by this manager.'); return

    if not ensure_ssh_user(user, password): return
    if not configure_sshd_port(port): return
    sid = f'ssh-{int(time.time())}'
    s = {'id': sid, 'protocol':'ssh', 'name':name, 'port':port, 'username':user,
         'password':password, 'created':int(time.time())}
    data.append(s); save(data)
    print(f'[OK] SSH ready: {public_ip()}:{port}  user={user}')


def mrudp_add(data):
    name = ask('Server name', 'MR-UDP')
    port = int(ask('UDP port', '4433'))
    if not valid_port(port): print('[ERR] Invalid port.'); return
    if not free_port(data, port): print('[ERR] Port already used by this manager.'); return
    script = Path(ask('MR-UDP server script', str(MRUDP_DEFAULT)))
    if not script.is_file():
        print(f'[ERR] File not found: {script}')
        print('      Put your working mr_udp_server.py there, then retry.')
        return
    user = ask('MR-UDP username', 'mrudp')
    password = ask('MR-UDP password')
    if not password: print('[ERR] Password cannot be empty.'); return
    sid = f'mrudp-{int(time.time())}'
    env = ENV / f'{sid}.env'
    env.write_text(f'MRUDP_SCRIPT={script}\nMRUDP_PORT={port}\nMRUDP_USER={user}\nMRUDP_PASS={password}\n')
    os.chmod(env, 0o600)
    unit = UNIT / f'{sid}.service'
    unit.write_text(f'''[Unit]\nDescription=MR VPN TUNNEL - MR-UDP {name}\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nEnvironmentFile={env}\nExecStart=/usr/bin/python3 $MRUDP_SCRIPT --port $MRUDP_PORT --user $MRUDP_USER --password $MRUDP_PASS\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n''')
    s = {'id':sid,'protocol':'mrudp','name':name,'port':port,'username':user,'password':password,'script':str(script),'created':int(time.time())}
    ok, out = systemd_start(unit.name)
    if not ok:
        unit.unlink(missing_ok=True); env.unlink(missing_ok=True)
        print('[ERR] MR-UDP failed to start:\n', out); return
    time.sleep(1)
    if status(s) != 'active':
        systemd_stop(unit.name); unit.unlink(missing_ok=True); env.unlink(missing_ok=True)
        print('[ERR] MR-UDP service is not active.'); return
    data.append(s); save(data)
    print(f'[OK] MR-UDP RUNNING: {public_ip()}:{port}/udp user={user}')


def ensure_xray():
    if shutil.which('xray'): return True
    if Path('/usr/local/bin/xray').exists(): return True
    print('[INFO] Xray binary not found.')
    print('Install Xray using your trusted/verified Xray distribution, then run this option again.')
    return False


def uuid4():
    import uuid; return str(uuid.uuid4())


def xray_config(s):
    proto=s['protocol']; port=s['port']; user=s['username']; pw=s['password']
    if proto == 'vless':
        outbound_users = [{'id': user, 'email': s['name']}]
        clients = [{'id': user, 'email': s['name']}]
        inb={'listen':'0.0.0.0','port':port,'protocol':'vless','settings':{'clients':clients,'decryption':'none'},'streamSettings':{'network':'tcp','security':'none'}}
    elif proto == 'vmess':
        clients=[{'id':user,'alterId':0,'email':s['name']}]
        inb={'listen':'0.0.0.0','port':port,'protocol':'vmess','settings':{'clients':clients},'streamSettings':{'network':'tcp','security':'none'}}
    elif proto == 'trojan':
        inb={'listen':'0.0.0.0','port':port,'protocol':'trojan','settings':{'clients':[{'password':pw,'email':s['name']} ]},'streamSettings':{'network':'tcp','security':'none'}}
    else:
        inb={'listen':'0.0.0.0','port':port,'protocol':'shadowsocks','settings':{'method':s.get('method','aes-128-gcm'),'password':pw,'network':'tcp,udp'}}
    return {'log':{'loglevel':'warning'},'inbounds':[inb],
            'outbounds':[{'protocol':'freedom','tag':'direct'},{'protocol':'blackhole','tag':'block'}]}


def xray_add(data):
    if not ensure_xray(): return
    proto=ask('Protocol', 'vless').lower()
    if proto not in ('vless','vmess','trojan','shadowsocks'):
        print('[ERR] Unsupported Xray protocol.'); return
    name=ask('Server name', proto.upper())
    port=int(ask('Port', {'vless':'10001','vmess':'10002','trojan':'10003','shadowsocks':'10004'}[proto]))
    if not valid_port(port) or not free_port(data,port): print('[ERR] Invalid or duplicate port.'); return
    user=ask('UUID' if proto in ('vless','vmess') else 'Username', uuid4() if proto in ('vless','vmess') else 'mrss')
    pw=ask('Password', uuid4()) if proto in ('trojan','shadowsocks') else ''
    method=ask('Shadowsocks method','aes-128-gcm') if proto=='shadowsocks' else ''
    sid=f'xray-{proto}-{int(time.time())}'
    s={'id':sid,'protocol':proto,'name':name,'port':port,'username':user,'password':pw,'method':method,'created':int(time.time())}
    cfg=CONF/f'{sid}.json'; cfg.write_text(json.dumps(xray_config(s),indent=2)); os.chmod(cfg,0o600)
    unit=UNIT/f'{sid}.service'
    xbin='/usr/local/bin/xray' if Path('/usr/local/bin/xray').exists() else shutil.which('xray')
    unit.write_text(f'''[Unit]\nDescription=MR VPN TUNNEL - Xray {proto} {name}\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart={xbin} run -config {cfg}\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n''')
    ok,out=systemd_start(unit.name)
    if not ok:
        unit.unlink(missing_ok=True); cfg.unlink(missing_ok=True); print('[ERR] Xray failed:\n',out); return
    time.sleep(1)
    if status(s)!='active':
        run(f'systemctl status {q(unit.name)} --no-pager -l')
        systemd_stop(unit.name); unit.unlink(missing_ok=True); cfg.unlink(missing_ok=True); return
    data.append(s); save(data)
    print(f'[OK] {proto.upper()} RUNNING: {public_ip()}:{port}')
    if proto in ('vless','vmess'): print(f'     ID/UUID: {user}')
    else: print(f'     Password: {pw}')
    if proto=='shadowsocks': print(f'     Method: {method}')
    print('     Transport: TCP, Security: none (matches a plain TCP Xray endpoint).')


def list_servers(data):
    print('\n=== MR VPN TUNNEL SERVERS ===')
    if not data: print('No servers.'); return
    for i,s in enumerate(data,1):
        endpoint = f"{public_ip()}:{s['port']}"
        if s.get('proxy_port'): endpoint += f" proxy={public_ip()}:{s['proxy_port']}"
        print(f"{i}. {s['name']} | {s['protocol'].upper()} | {endpoint} | {status(s)}")


def choose(data):
    if not data: print('No servers.'); return None
    list_servers(data)
    try: i=int(input('Number: ')); return data[i-1]
    except Exception: print('[ERR] Invalid selection.'); return None


def actions(data):
    s=choose(data)
    if not s:return
    unit=unit_name(s)
    print('\n1 Start\n2 Stop\n3 Restart\n4 Logs\n5 Delete')
    a=input('Action: ').strip()
    if a=='1': systemd_start(unit); print(status(s))
    elif a=='2': systemd_stop(unit); print('STOPPED')
    elif a=='3': run(f'systemctl restart {q(unit)}'); time.sleep(1); print(status(s))
    elif a=='4': run(f'journalctl -u {q(unit)} -n 80 --no-pager')
    elif a=='5':
        systemd_stop(unit)
        Path('/etc/systemd/system',unit).unlink(missing_ok=True)
        if s['protocol'] in ('mrudp','ssh-proxy-payload'): (ENV/f"{s['id']}.env").unlink(missing_ok=True)
        if s['protocol'] in ('vless','vmess','trojan','shadowsocks'): (CONF/f"{s['id']}.json").unlink(missing_ok=True)
        data.remove(s); save(data); run('systemctl daemon-reload'); print('[OK] Deleted.')


def main():
    ensure_root(); data=load()
    print('\n=== MR VPN TUNNEL SERVER MANAGER v2 ===')
    print(f'Public IP: {public_ip()}')
    while True:
        print('''
1) Install base SSH dependencies
2) Add MR-UDP server
3) Add SSH server/user
4) Add SSH-Proxy-Payload server
5) Add VLESS (Xray)
6) Add VMess (Xray)
7) Add Trojan (Xray)
8) Add Shadowsocks (Xray)
9) List servers
10) Manage server
0) Exit''')
        c=input('Select: ').strip()
        if c=='0': break
        if c=='1': install_base()
        elif c=='2': mrudp_add(data)
        elif c=='3': ssh_add(data)
        elif c=='4':
            ssh_proxy_payload_add(data)
        elif c in ('5','6','7','8'):
            forced={'5':'vless','6':'vmess','7':'trojan','8':'shadowsocks'}[c]
            # xray_add asks for protocol; keep menu clear by pre-setting input through a tiny wrapper.
            old=ask
            def ax(prompt, default=''):
                if prompt=='Protocol': return forced
                return old(prompt, default)
            globals()['ask']=ax
            try: xray_add(data)
            finally: globals()['ask']=old
        elif c=='9': list_servers(data)
        elif c=='10': actions(data)
        else: print('[ERR] Unknown option.')

if __name__=='__main__': main()
