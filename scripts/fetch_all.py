#!/usr/bin/env python3
"""
直连节点提取器（无套娃、无 MASQUE）
包含: Opera / Proton / TunnelBear / Urban VPN / Windscribe
"""
import os
import sys
import json
import time
import base64
import random
import string
import hashlib
import urllib.request
import urllib.parse
import urllib.error
import subprocess
import asyncio
import yaml

# ==========================================
# 1. Urban VPN 节点提取 (Chrome 扩展 API 逆向)
# ==========================================
def get_urban_nodes():
    print("[1/5] 正在获取 Urban VPN 节点...")
    nodes = []
    # 挑选低延迟和常用国家
    TARGETS = {"US": "美国", "JP": "日本", "HK": "香港", "SG": "新加坡", "GB": "英国", "KR": "韩国", "DE": "德国"}
    
    # 模拟其 Chrome 扩展获取官方节点池
    url = "https://urban-vpn.com/wp-admin/admin-ajax.php?action=uvpn_get_locations"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Referer": "https://urban-vpn.com/"
    }
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
            for item in data:
                cc = item.get("country_code")
                if cc in TARGETS:
                    c_name = TARGETS[cc]
                    # 获取其服务器 IP
                    hosts = item.get("servers", [])
                    for idx, host in enumerate(hosts[:2]): # 每国选前 2 台稳定机器
                        nodes.append({
                            "name": f"Urban-{c_name}{idx+1}",
                            "type": "http",
                            "server": host,
                            "port": 443,
                            "username": "urban",
                            "password": "urban",
                            "tls": True,
                            "skip-cert-verify": True
                        })
    except Exception as e:
        print(f"  [!] Urban VPN 获取略过: {e}")
        
    print(f"  -> Urban VPN 成功提取 {len(nodes)} 个节点")
    return nodes

# ==========================================
# 2. TunnelBear 节点提取 (全自动模拟开户)
# ==========================================
def get_tunnelbear_nodes():
    print("[2/5] 正在获取 TunnelBear 节点...")
    nodes = []
    # 随机生成无验证凭据
    rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    email = f"tb_{rand_suffix}@gmail.com"
    password = f"TbP@{rand_suffix}#99"

    url = "https://api.tunnelbear.com/core/web/api/login"
    data = urllib.parse.urlencode({
        "username": email,
        "password": password,
        "action": "register"
    }).encode()
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": "chrome-extension://omidakfkgchncldgfdjfladcemakghjk"
    }

    try:
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            res = json.loads(r.read().decode())
            token = res.get("details", {}).get("proxyAuthToken")
            
            if token:
                # 接入官方核心代理节点 (端口全部为 443 HTTPS)
                POPULAR_SERVERS = {
                    "日本": "jp.lazerbear.net",
                    "新加坡": "sg.lazerbear.net",
                    "美国": "us.lazerbear.net",
                    "英国": "uk.lazerbear.net",
                    "德国": "de.lazerbear.net"
                }
                for c_name, host in POPULAR_SERVERS.items():
                    nodes.append({
                        "name": f"TunnelBear-{c_name}",
                        "type": "http",
                        "server": host,
                        "port": 443,
                        "username": "user",
                        "password": token,
                        "tls": True,
                        "skip-cert-verify": False
                    })
    except Exception as e:
        print(f"  [!] TunnelBear 提取略过: {e}")

    print(f"  -> TunnelBear 成功提取 {len(nodes)} 个节点")
    return nodes

# ==========================================
# 3. Windscribe 节点提取 (免邮箱临时开户)
# ==========================================
def get_windscribe_nodes():
    print("[3/5] 正在获取 Windscribe 节点...")
    nodes = []
    SECRET = "952b4412f002315aa50751032fcaab03"
    t = int(time.time())
    client_hash = hashlib.md5((SECRET + str(t)).encode()).hexdigest()
    
    rand_user = "u" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=9))
    rand_pass = ''.join(random.choices(string.ascii_letters + string.digits, k=14)) + "!1Aa"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/103.0.0.0",
        "Origin": "chrome-extension://hnmpcagpplmpfojmgmnngilcnanddlhb",
        "Accept": "application/json"
    }
    
    try:
        # 1. 开户
        reg_data = urllib.parse.urlencode({
            "client_auth_hash": client_hash, "time": str(t), "session_type_id": "2",
            "username": rand_user, "password": rand_pass
        }).encode()
        reg_req = urllib.request.Request("https://api.windscribe.com/Users", data=reg_data, headers=headers)
        with urllib.request.urlopen(reg_req, timeout=15) as r:
            user_data = json.loads(r.read().decode()).get("data", {})
            
        session_hash = user_data.get("session_auth_hash")
        loc_hash = user_data.get("loc_hash")
        if not (session_hash and loc_hash):
            return nodes

        # 2. 拿连接用户名和密码
        t2 = int(time.time())
        c_hash2 = hashlib.md5((SECRET + str(t2)).encode()).hexdigest()
        q = urllib.parse.urlencode({"client_auth_hash": c_hash2, "session_auth_hash": session_hash, "time": str(t2)})
        cred_req = urllib.request.Request(f"https://api.windscribe.com/ServerCredentials?{q}", headers=headers)
        with urllib.request.urlopen(cred_req, timeout=15) as r:
            cred_data = json.loads(r.read().decode()).get("data", {})
            proxy_user = base64.b64decode(cred_data.get("username", "")).decode()
            proxy_pass = base64.b64decode(cred_data.get("password", "")).decode()

        # 3. 选节点列表（优先香港、美西等）
        serv_req = urllib.request.Request(f"https://assets.windscribe.com/serverlist/chrome/0/{loc_hash}", headers=headers)
        with urllib.request.urlopen(serv_req, timeout=15) as r:
            serv_data = json.loads(r.read().decode()).get("data", [])
            
        CC_MAP = {"HK": "香港", "US-W": "美国西", "CA": "加拿大", "DE": "德国", "GB": "英国"}
        for c in serv_data:
            short = c.get("short_name")
            if short in CC_MAP and not c.get("premium_only"):
                for group in c.get("groups", []):
                    for host in group.get("hosts", [])[:1]:
                        hostname = host.get("hostname")
                        if hostname:
                            nodes.append({
                                "name": f"Windscribe-{CC_MAP[short]}",
                                "type": "http",
                                "server": hostname,
                                "port": 443,
                                "username": proxy_user,
                                "password": proxy_pass,
                                "tls": True,
                                "sni": hostname,
                                "skip-cert-verify": False
                            })
    except Exception as e:
        print(f"  [!] Windscribe 提取略过: {e}")

    print(f"  -> Windscribe 成功提取 {len(nodes)} 个节点")
    return nodes

# ==========================================
# 4. Opera 节点提取 (通过内置二进制)
# ==========================================
def get_opera_nodes(binary_path="./opera-proxy"):
    print("[4/5] 正在获取 Opera 节点...")
    nodes = []
    if not os.path.exists(binary_path):
        print(f"  [!] 未检测到 {binary_path}，跳过 Opera")
        return nodes

    import re
    REGIONS = {"AS": "亚洲", "EU": "欧洲", "AM": "美洲"}
    for code, c_name in REGIONS.items():
        try:
            r = subprocess.run([binary_path, "-country", code, "-list-proxies"],
                               capture_output=True, text=True, timeout=30)
            login = re.search(r"Proxy login: (\S+)", r.stdout)
            pw = re.search(r"Proxy password: (\S+)", r.stdout)
            if not (login and pw):
                continue

            seq = 0
            for line in r.stdout.splitlines():
                m = re.match(r"^([\w.-]+\.sec-tunnel\.com),([\d.]+),(\d+)$", line.strip())
                if m:
                    host, ip, port = m.groups()
                    seq += 1
                    nodes.append({
                        "name": f"Opera-{c_name}{seq}",
                        "type": "http",
                        "server": ip,
                        "port": int(port),
                        "username": login.group(1),
                        "password": pw.group(1),
                        "tls": True,
                        "sni": host,
                        "skip-cert-verify": False
                    })
        except Exception as e:
            print(f"  [!] Opera {code} 异常: {e}")
            
    print(f"  -> Opera 成功提取 {len(nodes)} 个节点")
    return nodes

# ==========================================
# 5. Proton 节点提取 (WireGuard 协议)
# ==========================================
async def get_proton_nodes():
    print("[5/5] 正在获取 Proton WireGuard 节点...")
    nodes = []
    user = os.environ.get("PROTON_USER")
    pwd = os.environ.get("PROTON_PASS")
    if not user or not pwd:
        print("  [!] 缺少 PROTON_USER / PROTON_PASS 环境变量，跳过 Proton")
        return nodes

    try:
        from proton.session import Session
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        s = Session(appversion="linux-vpn@4.8.2", user_agent="ProtonVPN/4.8.2 (Linux; Ubuntu/24.04)")
        if not await s.async_authenticate(user, pwd):
            return nodes

        sk = ed25519.Ed25519PrivateKey.generate()
        pem = sk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        raw_sk = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

        h = bytearray(hashlib.sha512(raw_sk).digest()[:32])
        h[0] &= 248; h[31] &= 127; h[31] |= 64
        wg_sk = base64.b64encode(bytes(h)).decode()

        await s.async_api_request("/vpn/v1/certificate", jsondata={
            "ClientPublicKey": pem, "Mode": "session", "Duration": "10080 min", "DeviceName": "actions"
        })

        lg = await s.async_api_request("/vpn/logicals")
        free = [x for x in lg["LogicalServers"] if x.get("Tier") == 0]

        WANT_CC = {"JP": "日本", "SG": "新加坡", "US": "美国", "NL": "荷兰"}
        count = {}
        for srv in sorted(free, key=lambda x: x.get("Score", 99)):
            cc = srv["ExitCountry"]
            if cc in WANT_CC and count.get(cc, 0) < 2:
                phys = (srv.get("Servers") or [{}])[0]
                pub = phys.get("X25519PublicKey")
                ip = phys.get("EntryIP")
                if pub and ip:
                    count[cc] = count.get(cc, 0) + 1
                    nodes.append({
                        "name": f"Proton-{WANT_CC[cc]}{count[cc]}",
                        "type": "wireguard",
                        "server": ip,
                        "port": 51820,
                        "ip": "10.2.0.2",
                        "private-key": wg_sk,
                        "public-key": pub,
                        "udp": True,
                        "dns": ["1.1.1.1"]
                    })
    except Exception as e:
        print(f"  [!] Proton 异常: {e}")
        
    print(f"  -> Proton 成功提取 {len(nodes)} 个节点")
    return nodes

# ==========================================
# 组装完整的 Clash / mihomo 配置
# ==========================================
async def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "dist"
    os.makedirs(outdir, exist_ok=True)

    all_nodes = []
    all_nodes.extend(get_urban_nodes())
    all_nodes.extend(get_tunnelbear_nodes())
    all_nodes.extend(get_windscribe_nodes())
    all_nodes.extend(get_opera_nodes())
    all_nodes.extend(await get_proton_nodes())

    if not all_nodes:
        sys.exit("错误: 未抓取到任何可用节点！")

    names = [n["name"] for n in all_nodes]
    
    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "unified-delay": True,
        "proxies": all_nodes,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择", "🔄 故障转移"] + names
            },
            {
                "name": "♻️ 自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": names
            },
            {
                "name": "🔄 故障转移",
                "type": "fallback",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 180,
                "proxies": names
            }
        ],
        "rules": [
            "GEOIP,LAN,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 节点选择"
        ]
    }

    yaml_path = os.path.join(outdir, "free-nodes.yaml")
    with open(yaml_path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    print(f"\n[OK] 提取完成，共收集 {len(all_nodes)} 个节点，保存至: {yaml_path}")

if __name__ == "__main__":
    asyncio.run(main())
