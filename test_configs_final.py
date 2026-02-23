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
            "sid": q.get('sid', [''])[0], "path": q.get('path', [''])[0]
        }
    except: return None

def test_vless(url, index):
    d = parse_vless(url)
    if not d: return None
    l_port = 20000 + (index % 500)
    c_file = f"cfg_{l_port}.json"
    
    # تنظیمات فوق پایداری برای رانر گیت‌هاب
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": l_port, "protocol": "http", "settings": {"timeout": 10}}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": d['addr'], "port": d['port'], "users": [{"id": d['id'], "encryption": "none"}]}]},
            "streamSettings": {
                "network": d['type'], "security": d['sec'],
                "tlsSettings": {"serverName": d['sni'], "allowInsecure": True} if d['sec'] == "tls" else {},
                "realitySettings": {"serverName": d['sni'], "fingerprint": "chrome", "publicKey": d['pbk'], "shortId": d['sid']} if d['sec'] == "reality" else {},
                "wsSettings": {"path": d['path']} if d['type'] == "ws" else {},
                "sockopt": {"mark": 255, "tcpFastOpen": True}
            },
            "mux": {"enabled": True, "concurrency": 8}
        }]
    }

    proc = None
    try:
        with open(c_file, 'w') as f: json.dump(cfg, f)
        proc = subprocess.Popen([XRAY_PATH, "-c", c_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(4) # زمان بیشتر برای ایجاد دست‌بوسی TLS
        
        # استفاده از HTTP Proxy به جای SOCKS برای پایداری در رانر
        proxies = {"http": f"http://127.0.0.1:{l_port}", "https": f"http://127.0.0.1:{l_port}"}
        
        # تست با یک وب‌سایت عمومی که به دیتاسنترها نزدیک‌تر است
        r = requests.get("http://www.cloudflare.com/cdn-cgi/trace", proxies=proxies, timeout=10)
        
        if r.status_code == 200 and "h=" in r.text:
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
        # تست روی ۱۰۰ تای اول (چون همگی TCP سالم داشتند)
        lines = [l.strip() for l in f if l.startswith('vless://')][:100]

    print(f"📡 Deep probing {len(lines)} configs via Cloudflare Edge...")
    valid = []
    # استفاده از تعداد ورکر خیلی کم برای جلوگیری از تداخل شبکه ای
    with ThreadPoolExecutor(max_workers=4) as exe:
        futs = [exe.submit(test_vless, url, i) for i, url in enumerate(lines)]
        for f in as_completed(futs):
            res = f.result()
            if res:
                valid.append(f"{res.split('#')[0]}#🚩 mirsub")

    with open(output_f, 'w') as f:
        f.write('\n'.join(valid))
    print(f"🏁 Done! {len(valid)} configs passed the real-world test.")

if __name__ == "__main__":
    main()
