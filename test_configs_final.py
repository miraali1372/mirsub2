import socket
import time
import urllib.parse
import sys
import os
import requests
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

XRAY_PATH = os.path.abspath("./xray")

def setup():
    if not os.path.exists(XRAY_PATH):
        os.system("curl -L -o xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip")
        os.system("unzip -o xray.zip xray && rm xray.zip && chmod +x xray")

def parse_vless(url):
    try:
        u = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(u.query)
        return {
            "id": u.username, "addr": u.hostname, "port": u.port or 443,
            "sni": q.get('sni', [u.hostname])[0], "sec": q.get('security', ['none'])[0],
            "type": q.get('type', ['tcp'])[0], "pbk": q.get('pbk', [''])[0],
            "sid": q.get('sid', [''])[0], "path": q.get('path', [''])[0],
            "flow": q.get('flow', [''])[0]
        }
    except: return None

def test_vless(url, index):
    d = parse_vless(url)
    if not d: return None
    l_port = 20000 + (index % 500)
    c_file = f"cfg_{l_port}.json"
    
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": l_port, "protocol": "socks", "settings": {"udp": True}, "listen": "127.0.0.1"}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": d['addr'], "port": d['port'], "users": [{"id": d['id'], "encryption": "none", "flow": d['flow']}]}]},
            "streamSettings": {
                "network": d['type'], "security": d['sec'],
                "tlsSettings": {"serverName": d['sni'], "allowInsecure": True} if d['sec'] == "tls" else {},
                "realitySettings": {"serverName": d['sni'], "fingerprint": "chrome", "publicKey": d['pbk'], "shortId": d['sid']} if d['sec'] == "reality" else {},
                "wsSettings": {"path": d['path']} if d['type'] == "ws" else {}
            }
        }]
    }

    proc = None
    try:
        with open(c_file, 'w') as f: json.dump(cfg, f)
        proc = subprocess.Popen([XRAY_PATH, "-c", c_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3) # فرصت به هسته برای استقرار
        
        proxies = {"http": f"socks5://127.0.0.1:{l_port}", "https": f"socks5://127.0.0.1:{l_port}"}
        # تست با IP مستقیم کلودفلر برای دور زدن مشکلات DNS
        r = requests.get("http://1.1.1.1", proxies=proxies, timeout=8)
        
        if r.status_code == 200:
            return url
    except: pass
    finally:
        if proc:
            proc.terminate()
            proc.wait()
        if os.path.exists(c_file): os.remove(c_file)
    return None

def main():
    setup()
    input_f, output_f = sys.argv[1], sys.argv[2]
    with open(input_f, 'r') as f:
        lines = [l.strip() for l in f if l.startswith('vless://')]

    print(f"🚀 Heavy testing {len(lines)} configs...")
    valid = []
    # کاهش Worker ها به ۵ عدد برای جلوگیری از بلاک شدن توسط GitHub
    with ThreadPoolExecutor(max_workers=5) as exe:
        futs = [exe.submit(test_vless, url, i) for i, url in enumerate(lines)]
        for f in as_completed(futs):
            res = f.result()
            if res:
                valid.append(f"{res.split('#')[0]}#🚩 mirsub")

    with open(output_f, 'w') as f:
        f.write('\n'.join(valid))
    print(f"✅ Finished. {len(valid)} configs saved.")

if __name__ == "__main__":
    main()
