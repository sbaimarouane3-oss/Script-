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
        if int(s.get('port', -1)) == int(port): return False
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

    # This manager only configures the real sshd port if the requested port is 22.
    # For another port we add a Port directive and verify sshd before saving.
    rc, _ = run(f'id {q(user)}')
    if rc != 0:
        rc, out = run(f'useradd -m -s /bin/bash {q(user)}')
        if rc != 0: print('[ERR] useradd failed:', out); return
    rc, out = run(f'chpasswd', input_text=f'{user}:{password}\n')
    if rc != 0: print('[ERR] chpasswd failed:', out); return
    run(f'usermod -s /bin/bash {q(user)}')

    sshd_cfg = Path('/etc/ssh/sshd_config')
    backup = sshd_cfg.read_text() if sshd_cfg.exists() else ''
    if port != 22:
        # OpenSSH does not allow a global Port directive inside a Match block.
        # Insert the new Port before the first Match directive, rather than at EOF.
        lines = backup.splitlines()
        has_port = any(re.match(r'^\s*Port\s+' + re.escape(str(port)) + r'\s*$', x) for x in lines)
        if not has_port:
            match_idx = next((i for i, x in enumerate(lines) if re.match(r'^\s*Match\b', x, re.I)), len(lines))
            lines.insert(match_idx, f'Port {port}')
            sshd_cfg.write_text('\n'.join(lines).rstrip() + '\n')
        rc, out = run('sshd -t')
        if rc != 0:
            sshd_cfg.write_text(backup)
            # Do not leave a newly-created account behind after a failed SSH setup.
            run(f'userdel -r {q(user)}')
            print('[ERR] sshd config test failed:', out)
            return
        rc, out = run('systemctl restart ssh || systemctl restart sshd')
        if rc != 0:
            sshd_cfg.write_text(backup)
            run('systemctl restart ssh || systemctl restart sshd')
            run(f'userdel -r {q(user)}')
            print('[ERR] SSH service restart failed:', out)
            return

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
        print(f"{i}. {s['name']} | {s['protocol'].upper()} | {public_ip()}:{s['port']} | {status(s)}")


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
        if s['protocol']=='mrudp': (ENV/f"{s['id']}.env").unlink(missing_ok=True)
        if s['protocol'] in ('vless','vmess','trojan','shadowsocks'): (CONF/f"{s['id']}.json").unlink(missing_ok=True)
        data.remove(s); save(data); run('systemctl daemon-reload'); print('[OK] Deleted.')


def main():
    ensure_root(); data=load()
    print('\n=== MR VPN TUNNEL SERVER MANAGER v2 ===')
    print(f'Public IP: {public_ip()}')
    while True:
        print('''\n1) Install base SSH dependencies\n2) Add MR-UDP server\n3) Add SSH server/user\n4) Add VLESS (Xray)\n5) Add VMess (Xray)\n6) Add Trojan (Xray)\n7) Add Shadowsocks (Xray)\n8) List servers\n9) Manage server\n0) Exit''')
        c=input('Select: ').strip()
        if c=='0': break
        if c=='1': install_base()
        elif c=='2': mrudp_add(data)
        elif c=='3': ssh_add(data)
        elif c in ('4','5','6','7'):
            forced={'4':'vless','5':'vmess','6':'trojan','7':'shadowsocks'}[c]
            # xray_add asks for protocol; keep menu clear by pre-setting input through a tiny wrapper.
            old=ask
            def ax(prompt, default=''):
                if prompt=='Protocol': return forced
                return old(prompt, default)
            globals()['ask']=ax
            try: xray_add(data)
            finally: globals()['ask']=old
        elif c=='8': list_servers(data)
        elif c=='9': actions(data)
        else: print('[ERR] Unknown option.')

if __name__=='__main__': main()
