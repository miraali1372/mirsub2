import socket
import time
import urllib.parse
import sys
import os
import requests
import json
import subprocess
import geoip2.database
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- تنظیمات سیستم ---
XRAY_PATH = os.path.abspath("./xray")
GEO_DB_PATH = os.path.abspath("geoip.mmdb")

def get_flag(code):
    """تبدیل کد کشور به ایموجی پرچم"""
    if not code or code == "mirsub": return "🚩"
    try:
        return "".join(chr(ord(c) + 127397) for c in code.upper())
    except: return "🚩"

def setup_environment():
    """دانلود ابزارهای مورد نیاز"""
    if not os.path.exists(XRAY_PATH):
        os.system("curl -L -o xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip")
        os.system("unzip -o xray.zip xray && rm xray.zip && chmod +x xray")
    
    if not os.path.exists(GEO_DB_PATH):
        url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
        r = requests.get(url, timeout=30)
        with open(GEO_DB_PATH, "wb") as f: f.write(r.content)

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

def test_vless(url, index, reader):
    d = parse_vless(url)
    if not d: return None
    l_port = 20000 + (index % 1000)
    c_file = f"cfg_{l_port}.json"
    
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
                "wsSettings": {"path": d['path']} if d['type'] == "ws" else {}
            },
            "mux": {"enabled": True, "concurrency": 8}
        }]
    }

    proc = None
    try:
        with open(c_file, 'w') as f: json.dump(cfg, f)
        proc = subprocess.Popen([XRAY_PATH, "-c", c_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3) # سرعت تست بیشتر شد
        
        proxies = {"http": f"http://127.0.0.1:{l_port}", "https": f"http://127.0.0.1:{l_port}"}
        r = requests.get("http://www.cloudflare.com/cdn-cgi/trace", proxies=proxies, timeout=8)
        
        if r.status_code == 200 and "h=" in r.text:
            try:
                ip_addr = socket.gethostbyname(d['addr'])
                country_code = reader.country(ip_addr).country.iso_code
            except: country_code = "mirsub"
            return f"{url.split('#')[0]}#{get_flag(country_code)} mirsub"
    except: pass
    finally:
        if proc:
            proc.terminate()
            proc.wait()
        if os.path.exists(c_file): os.remove(c_file)
    return None

def main():
    if len(sys.argv) < 3: sys.exit(1)
    input_f, output_f = sys.argv[1], sys.argv[2]
    setup_environment()
    reader = geoip2.database.Reader(GEO_DB_PATH)
    
    with open(input_f, 'r') as f:
        lines = list(set([l.strip() for l in f if l.startswith('vless://')]))

    print(f"🚀 Testing {len(lines)} configs with 8 parallel workers...")
    valid = []
    # افزایش تعداد ورکرها به ۸ برای سرعت بالاتر
    with ThreadPoolExecutor(max_workers=8) as exe:
        futs = [exe.submit(test_vless, url, i, reader) for i, url in enumerate(lines)]
        for f in as_completed(futs):
            res = f.result()
            if res:
                valid.append(res)
                print(f"✅ Found: {len(valid)} working", end='\r')

    with open(output_f, 'w') as f:
        f.write('\n'.join(valid))
    reader.close()
    print(f"\n🏁 Finished. {len(valid)} configs saved.")

if __name__ == "__main__":
    main()
