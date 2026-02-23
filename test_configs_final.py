import socket
import time
import urllib.parse
import sys
import os
import requests
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# تنظیمات
XRAY_PATH = os.path.abspath("./xray")

def get_flag(code):
    return "🚩" # برای سادگی فعلاً پرچم ثابت می‌گذاریم تا خروجی بگیریم

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
    l_port = 20000 + (index % 1000)
    
    # ساخت کانفیگ به صورت Inline
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": l_port, "protocol": "socks", "settings": {"udp": True}, "listen": "127.0.0.1"}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": d['addr'], "port": d['port'], "users": [{"id": d['id'], "encryption": "none"}]}]},
            "streamSettings": {
                "network": d['type'], "security": d['sec'],
                "tlsSettings": {"serverName": d['sni']} if d['sec'] == "tls" else {},
                "realitySettings": {"serverName": d['sni'], "publicKey": d['pbk'], "shortId": d['sid']} if d['sec'] == "reality" else {},
                "wsSettings": {"path": d['path']} if d['type'] == "ws" else {}
            }
        }]
    }

    c_file = f"temp_{l_port}.json"
    with open(c_file, 'w') as f: json.dump(cfg, f)
    
    proc = subprocess.Popen([XRAY_PATH, "-c", c_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    
    res = None
    try:
        start = time.perf_counter()
        # تست با یک آدرس مستقیم IP برای حذف مشکل DNS
        r = requests.get("http://1.1.1.1", proxies={"http": f"socks5://127.0.0.1:{l_port}"}, timeout=5)
        if r.status_code == 200:
            res = int((time.perf_counter() - start) * 1000)
    except: pass
    
    proc.terminate()
    if os.path.exists(c_file): os.remove(c_file)
    return res

def main():
    setup()
    input_f, output_f = sys.argv[1], sys.argv[2]
    
    with open(input_f, 'r') as f:
        lines = list(set([l.strip() for l in f if l.startswith('vless://')]))[:150] # محدود به ۱۵۰ تا برای سرعت

    print(f"🚀 Testing {len(lines)} configs...")
    final = []
    
    with ThreadPoolExecutor(max_workers=10) as exe:
        fut_to_url = {exe.submit(test_vless, url, i): url for i, url in enumerate(lines)}
        for fut in as_completed(fut_to_url):
            delay = fut.result()
            if delay:
                url = fut_to_url[fut]
                # فرمت درخواستی شما
                final.append(f"{url.split('#')[0]}#🚩 mirsub")

    with open(output_f, 'w') as f:
        f.write('\n'.join(final))
    print(f"✅ Saved {len(final)} working configs.")

if __name__ == "__main__":
    main()
