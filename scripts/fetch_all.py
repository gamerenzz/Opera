#!/usr/bin/env python3
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
import subprocess
import asyncio

# ==========================================
# 1. Urban VPN 节点提取 (免登录 HTTP 代理)
# ==========================================
def get_urban_nodes():
    print("[1/4] 正在获取 Urban VPN 节点...")
    nodes = []
    # 常用挑选的地区代码
    WANT_CC = {"US": "美国", "JP": "日本", "HK": "香港", "SG": "新加坡", "GB": "英国", "DE": "德国", "KR": "韩国"}
    url = "https://api.urban-vpn.com/api/servers"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
            # Urban API 返回国家与对应的代理服务器
            for country in data.get("countries", []):
                cc = country.get("country_code")
                if cc in WANT_CC:
                    c_name = WANT_CC[cc]
                    servers = country.get("servers", [])
                    for idx, s in enumerate(servers[:2]): # 每国挑2台
                        ip = s.get("ip")
                        port = s.get("port", 80)
                        if ip:
                            nodes.append({
                                "name": f"Urban-{c_name}{idx+1}",
                                "type": "http",
                                "server": ip,
                                "port": port,
                                "username": "urban",
                                "password": "vpn", # Urban 扩展公开基础鉴权
                            })
    except Exception as e:
        print(f"Urban VPN 提取失败: {e}")
    print(f"  -> Urban VPN 提取到 {len(nodes)} 个节点")
    return nodes

# ==========================================
# 2. TunnelBear 节点提取 (临时开户 HTTP 代理)
# ==========================================
def get_tunnelbear_nodes():
    print("[2/4] 正在获取 TunnelBear 节点...")
    nodes = []
    # 随机生成凭证直接开户，免邮箱验证
    rand_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    email = f"tb_{rand_id}@gmail.com"
    pwd = f"TbPass_{rand_id}!1"

    login_url = "https://api.tunnelbear.com/core/web/api/login"
    data = urllib.parse.urlencode({"username": email, "password": pwd, "action": "register"}).encode()
    req = urllib.request.Request(login_url, data=data, headers={"User-Agent": "TunnelBear Chrome Extension"})
    
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            res = json.loads(r.read().decode())
            if res.get("result") != "PASS":
                print("TunnelBear 注册未返回 PASS")
                return nodes
            auth_token = res.get("details", {}).get("proxyAuthToken")
            
        # 挑选热门落地域名
        tb_servers = {
            "日本": "jp.lazerbear.net",
            "美国": "us.lazerbear.net",
            "英国": "uk.lazerbear.net",
            "德国": "de.lazerbear.net",
            "新加坡": "sg.lazerbear.net"
        }
        for c_name, host in tb_servers.items():
            nodes.append({
                "name": f"TunnelBear-{c_name}",
                "type": "http",
                "server": host,
                "port": 443,
                "username": "user",
                "password": auth_token,
                "tls": True,
                "skip-cert-verify": False
            })
    except Exception as e:
        print(f"TunnelBear 提取失败: {e}")
    print(f"  -> TunnelBear 提取到 {len(nodes)} 个节点")
    return nodes

# ==========================================
# 3. Opera 节点提取 (通过原项目脚本/编译物获取)
# ==========================================
def get_opera_nodes(binary_path="./opera-proxy"):
    print("[3/4] 正在获取 Opera 节点...")
    nodes = []
    if not os.path.exists(binary_path):
        print(f"未找到 {binary_path}，跳过 Opera")
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
            print(f"Opera {code} 提取失败: {e}")
    print(f"  -> Opera 提取到 {len(nodes)} 个节点")
    return nodes

# ==========================================
# 4. Proton 节点提取 (WireGuard)
# ==========================================
async def get_proton_nodes():
    print("[4/4] 正在获取 Proton WireGuard 节点...")
    nodes = []
    user = os.environ.get("PROTON_USER")
    pwd = os.environ.get("PROTON_PASS")
    if not user or not pwd:
        print("未配置 PROTON_USER / PROTON_PASS，跳过 Proton 抓取")
        return nodes

    try:
        from proton.session import Session
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        s = Session(appversion="linux-vpn@4.8.2", user_agent="ProtonVPN/4.8.2 (Linux; Ubuntu/24.04)")
        if not await s.async_authenticate(user, pwd):
            print("Proton 登录失败")
            return nodes

        # 证书生成与 Clamp 计算 WG 私钥
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
        
        WANT_CC = {"JP": "日本", "SG": "新加坡", "US": "美国", "NL": "荷兰", "DE": "德国"}
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
        print(f"Proton 提取失败: {e}")
    print(f"  -> Proton 提取到 {len(nodes)} 个节点")
    return nodes

# ==========================================
# 5. 生成标准 Clash/mihomo YAML
# ==========================================
def build_clash_yaml(all_nodes):
    names = [n["name"] for n in all_nodes]
    indented_names = "\n".join([f"      - \"{name}\"" for name in names])

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": all_nodes
    }
    
    # 手工拼接 YAML 避免引用破坏
    yaml_text = f"""# 纯白嫖直连节点聚合（无套娃/无MASQUE）
# 包含: Urban VPN / TunnelBear / Opera / Proton
# 更新时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC

mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
unified-delay: true

proxies:
{json.dumps(all_nodes, ensure_ascii=False, indent=2).replace('{\\n', '').replace('\\n}', '')} # 将由标准加载替换

proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - ♻️ 自动选择
      - 🔄 故障转移
{indented_names}

  - name: ♻️ 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
{indented_names}

  - name: 🔄 故障转移
    type: fallback
    url: http://www.gstatic.com/generate_204
    interval: 180
    proxies:
{indented_names}

rules:
  - GEOIP,LAN,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择
"""
    return yaml_text

async def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "dist"
    os.makedirs(outdir, exist_ok=True)

    all_nodes = []
    all_nodes.extend(get_urban_nodes())
    all_nodes.extend(get_tunnelbear_nodes())
    all_nodes.extend(get_opera_nodes())
    all_nodes.extend(await get_proton_nodes())

    if not all_nodes:
        sys.exit("未获取到任何节点，终止操作")

    import yaml
    # 直接组装纯 YAML
    names = [n["name"] for n in all_nodes]
    final_dict = {
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
        yaml.dump(final_dict, f, allow_unicode=True, sort_keys=False)

    print(f"\n全部完成！共提取 {len(all_nodes)} 个直连节点，已保存至: {yaml_path}")

if __name__ == "__main__":
    asyncio.run(main())
