#!/usr/bin/env python3
"""
直连节点提取器（四合一落地版）
包含: Windscribe (HTTPS) / Opera (HTTPS) / Proton (WireGuard) / Psiphon (HTTP/CDN)
配套 ACL4SSR 精细化国内分流、广告拦截、AI流媒体专用规则
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
# 1. Windscribe 节点提取 (免验证开户 + 序号去重)
# ==========================================
def get_windscribe_nodes():
    print("[1/4] 正在获取 Windscribe 节点...")
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

        t2 = int(time.time())
        c_hash2 = hashlib.md5((SECRET + str(t2)).encode()).hexdigest()
        q = urllib.parse.urlencode({"client_auth_hash": c_hash2, "session_auth_hash": session_hash, "time": str(t2)})
        cred_req = urllib.request.Request(f"https://api.windscribe.com/ServerCredentials?{q}", headers=headers)
        with urllib.request.urlopen(cred_req, timeout=15) as r:
            cred_data = json.loads(r.read().decode()).get("data", {})
            proxy_user = base64.b64decode(cred_data.get("username", "")).decode()
            proxy_pass = base64.b64decode(cred_data.get("password", "")).decode()

        serv_req = urllib.request.Request(f"https://assets.windscribe.com/serverlist/chrome/0/{loc_hash}", headers=headers)
        with urllib.request.urlopen(serv_req, timeout=15) as r:
            serv_data = json.loads(r.read().decode()).get("data", [])
            
        CC_MAP = {"HK": "香港", "US-W": "美国西", "CA": "加拿大", "DE": "德国", "GB": "英国"}
        cc_count = {}
        for c in serv_data:
            short = c.get("short_name")
            if short in CC_MAP and not c.get("premium_only"):
                c_name = CC_MAP[short]
                for group in c.get("groups", []):
                    for host in group.get("hosts", []):
                        hostname = host.get("hostname")
                        if hostname:
                            cc_count[c_name] = cc_count.get(c_name, 0) + 1
                            nodes.append({
                                "name": f"Windscribe-{c_name}{cc_count[c_name]}",
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
        print(f"  [!] Windscribe 提取异常: {e}")

    print(f"  -> Windscribe 提取到 {len(nodes)} 个节点")
    return nodes

# ==========================================
# 2. Opera 节点提取 (免账号 HTTPS 代理)
# ==========================================
def get_opera_nodes(binary_path="./opera-proxy"):
    print("[2/4] 正在获取 Opera 节点...")
    nodes = []
    if not os.path.exists(binary_path):
        print(f"  [!] 未找到辅助二进制 {binary_path}，跳过 Opera")
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
            
    print(f"  -> Opera 提取到 {len(nodes)} 个节点")
    return nodes

# ==========================================
# 3. Proton 节点提取 (WireGuard 协议)
# ==========================================
async def get_proton_nodes():
    print("[3/4] 正在获取 Proton WireGuard 节点...")
    nodes = []
    user = os.environ.get("PROTON_USER")
    pwd = os.environ.get("PROTON_PASS")
    if not user or not pwd:
        print("  [!] 缺少 PROTON_USER / PROTON_PASS，跳过 Proton")
        return nodes

    try:
        from proton.session import Session
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        s = Session(appversion="linux-vpn@4.8.2", user_agent="ProtonVPN/4.8.2 (Linux; Ubuntu/24.04)")
        if not await s.async_authenticate(user, pwd):
            print("  [!] Proton 登录失败")
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
        print(f"  [!] Proton 提取异常: {e}")
        
    print(f"  -> Proton 提取到 {len(nodes)} 个节点")
    return nodes

# ==========================================
# 4. Psiphon 节点提取 (免账号 / 公共服务器池)
# ==========================================
def get_psiphon_nodes():
    print("[4/4] 正在获取 Psiphon (赛风) 节点...")
    nodes = []
    # 赛风公开的前端同步与发现源（基于去中心化维护清单）
    url = "https://raw.githubusercontent.com/Psiphon-Labs/psiphon-tunnel-core/master/ServerList/server_list.embedded"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    
    CC_MAP = {"US": "美国", "JP": "日本", "SG": "新加坡", "GB": "英国", "NL": "荷兰", "CA": "加拿大", "DE": "德国"}
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            content = r.read().decode()
            cc_count = {}
            for line in content.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    # 提取其暴露的 Web / HTTP 代理入口或对外网关
                    ip = data.get("ipAddress")
                    cc = data.get("country")
                    # 支持的端口清单 (取常见 443 / 80 / 53)
                    protocols = data.get("protocols", [])
                    if ip and cc in CC_MAP:
                        c_name = CC_MAP[cc]
                        if cc_count.get(c_name, 0) < 2:
                            cc_count[c_name] = cc_count.get(c_name, 0) + 1
                            nodes.append({
                                "name": f"Psiphon-{c_name}{cc_count[c_name]}",
                                "type": "http",
                                "server": ip,
                                "port": 443,
                                "tls": True,
                                "skip-cert-verify": True
                            })
                except Exception:
                    continue
    except Exception as e:
        print(f"  [!] Psiphon 提取异常: {e}")

    print(f"  -> Psiphon 提取到 {len(nodes)} 个节点")
    return nodes

# ==========================================
# 组装完整的 Clash / mihomo 配置
# ==========================================
async def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "dist"
    os.makedirs(outdir, exist_ok=True)

    all_nodes = []
    all_nodes.extend(get_windscribe_nodes())
    all_nodes.extend(get_opera_nodes())
    all_nodes.extend(await get_proton_nodes())
    all_nodes.extend(get_psiphon_nodes())

    if not all_nodes:
        sys.exit("错误: 未抓取到任何可用节点！")

    names = [n["name"] for n in all_nodes]
    
    RS = "https://raw.githubusercontent.com"
    rule_providers = {
        "LocalAreaNetwork": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": f"{RS}/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list",
            "path": "./ruleset/LocalAreaNetwork.list"
        },
        "BanAD": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": f"{RS}/ACL4SSR/ACL4SSR/master/Clash/BanAD.list",
            "path": "./ruleset/BanAD.list"
        },
        "OpenAi": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OpenAi.list",
            "path": "./ruleset/OpenAi.list"
        },
        "Telegram": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Telegram.list",
            "path": "./ruleset/Telegram.list"
        },
        "YouTube": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/YouTube.list",
            "path": "./ruleset/YouTube.list"
        },
        "ChinaDomain": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": f"{RS}/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list",
            "path": "./ruleset/ChinaDomain.list"
        },
        "ChinaCompanyIp": {
            "type": "http", "behavior": "classical", "format": "text", "interval": 86400,
            "url": f"{RS}/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list",
            "path": "./ruleset/ChinaCompanyIp.list"
        }
    }

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "unified-delay": True,
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:1053",
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"],
            "nameserver-policy": {
                "geosite:cn,private": ["https://223.5.5.5/dns-query", "https://1.12.12.12/dns-query"],
                "geosite:geolocation-!cn": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
            }
        },
        "proxies": all_nodes,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择", "🔄 故障转移"] + names
            },
            {
                "name": "🤖 AI服务",
                "type": "select",
                "proxies": ["🚀 节点选择", "♻️ 自动选择"] + names
            },
            {
                "name": "📹 国际媒体",
                "type": "select",
                "proxies": ["🚀 节点选择", "♻️ 自动选择"] + names
            },
            {
                "name": "📲 电报信息",
                "type": "select",
                "proxies": ["🚀 节点选择", "♻️ 自动选择"] + names
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
            },
            {
                "name": "🎯 全球直连",
                "type": "select",
                "proxies": ["DIRECT"]
            },
            {
                "name": "🛑 全球拦截",
                "type": "select",
                "proxies": ["REJECT", "DIRECT"]
            }
        ],
        "rule-providers": rule_providers,
        "rules": [
            "RULE-SET,LocalAreaNetwork,🎯 全球直连",
            "RULE-SET,BanAD,🛑 全球拦截",
            "RULE-SET,OpenAi,🤖 AI服务",
            "RULE-SET,YouTube,📹 国际媒体",
            "RULE-SET,Telegram,📲 电报信息",
            "RULE-SET,ChinaDomain,🎯 全球直连",
            "RULE-SET,ChinaCompanyIp,🎯 全球直连",
            "GEOIP,CN,🎯 全球直连",
            "MATCH,🚀 节点选择"
        ]
    }

    yaml_path = os.path.join(outdir, "free-nodes.yaml")
    with open(yaml_path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    print(f"\n[OK] 提取完成，共收集 {len(all_nodes)} 个节点，已生成配置: {yaml_path}")

if __name__ == "__main__":
    asyncio.run(main())
