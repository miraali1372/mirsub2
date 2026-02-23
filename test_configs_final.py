import socket
import time
import urllib.parse
import sys
import os
import requests
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- تنظیمات پایه ---
XRAY_PATH = os.path.abspath("./xray")

def setup():
    if not os.path.exists(XRAY_PATH):
        print("📥 Downloading Xray Core...")
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
    c_file = f"config_{l_port}.json"
    
    # ساخت فایل کانفیگ مینیمال
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

    try:
        with open(c_file, 'w') as f: json.dump(cfg, f)
        # اجرای Xray و صبر برای لود شدن
        proc = subprocess.Popen([XRAY_PATH, "-c", c_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        
        # تست از طریق پروکسی ساکس
        proxies = {"http": f"socks5://127.0.0.1:{l_port}", "https": f"socks5://127.0.0.1:{l_port}"}
        # تست مستقیم IP برای حذف لایه DNS
        r = requests.get("http://1.1.1.1", proxies=proxies, timeout=5)
        
        proc.terminate()
        proc.wait()
        if os.path.exists(c_file): os.remove(c_file)
        
        if r.status_code == 200:
            return url
    except:
        if 'proc' in locals(): proc.terminate()
        if os.path.exists(c_file): os.remove(c_file)
    return None

def main():
    setup()
    input_f, output_f = sys.argv[1], sys.argv[2]
    
    with open(input_f, 'r') as f:
        # فقط ۵۰ تا از بهترین‌های اول رو فعلاً تست می‌کنیم برای اطمینان
        lines = list(set([l.strip() for l in f if l.startswith('vless://')]))[:50]

    print(f"🚀 Testing {len(lines)} configs with direct Xray execution...")
    valid_configs = []
    
    with ThreadPoolExecutor(max_workers=5) as exe:
        futures = [exe.submit(test_vless, url, i) for i, url in enumerate(lines)]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                # فرمت دقیق درخواستی شما (بدون پرچم فعلاً برای تست خروجی)
                valid_configs.append(f"{res.split('#')[0]}#🚩 mirsub")

    with open(output_f, 'w') as f:
        f.write('\n'.join(valid_configs))
    
    print(f"✅ Finished. {len(valid_configs)} configs saved.")

if __name__ == "__main__":
    main()
