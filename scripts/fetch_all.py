#!/usr/bin/env python3
"""
Opera 纯直连节点提取器
免账号、无限流量、自带亚洲/欧洲/美洲落地
集成 ACL4SSR 国内分流白名单、广告拦截、防污染 DNS
"""
import os
import sys
import subprocess
import re
import yaml

# ==========================================
# 1. Opera 节点提取 (免账号 HTTPS 代理)
# ==========================================
def get_opera_nodes(binary_path="./opera-proxy"):
    print("[*] 正在获取 Opera 落地节点...")
    nodes = []
    if not os.path.exists(binary_path):
        sys.exit(f"错误: 未找到辅助程序 {binary_path}！")

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
            print(f"  [!] 获取 {code} 区域异常: {e}")
            
    print(f"  -> 成功提取到 {len(nodes)} 个 Opera 节点")
    return nodes

# ==========================================
# 2. 组装精细分流配置
# ==========================================
def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "dist"
    os.makedirs(outdir, exist_ok=True)

    nodes = get_opera_nodes()
    if not nodes:
        sys.exit("未获取到任何可用节点，终止操作")

    names = [n["name"] for n in nodes]

    # 分区筛选组
    asia_names = [n["name"] for n in nodes if "亚洲" in n["name"]]
    europe_names = [n["name"] for n in nodes if "欧洲" in n["name"]]
    america_names = [n["name"] for n in nodes if "美洲" in n["name"]]

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
        "proxies": nodes,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["♻️ 自动选择", "🌏 亚洲节点", "🌍 欧洲节点", "🌎 美洲节点", "🔄 故障转移"] + names
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
                "name": "🌏 亚洲节点",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": asia_names if asia_names else names
            },
            {
                "name": "🌍 欧洲节点",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": europe_names if europe_names else names
            },
            {
                "name": "🌎 美洲节点",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": america_names if america_names else names
            },
            {
                "name": "🤖 AI服务",
                "type": "select",
                "proxies": ["🚀 节点选择", "🌏 亚洲节点", "🌎 美洲节点"] + names
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

    print(f"\n[OK] 纯净版生成完毕，共 {len(nodes)} 个可用 Opera 直连节点: {yaml_path}")

if __name__ == "__main__":
    main()
