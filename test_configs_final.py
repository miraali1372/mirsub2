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

# --- تنظیمات سخت‌گیرانه برای جلوگیری از توقف ---
MAX_WORKERS_TCP = 40
MAX_WORKERS_XRAY = 6 # تعداد کم برای جلوگیری از کرش رانر
XRAY_PATH = os.path.abspath("./xray")
GEO_DB_PATH = os.path.abspath("geoip.mmdb")

def get_flag(code):
    if not code or code == "mirsub": return "🚩"
    try:
        return "".join(chr(ord(c) + 127397) for c in code.upper())
    except: return "🚩"

def setup_environment():
    if not os.path.exists(XRAY_PATH):
        print("📥 Downloading Xray...")
        os.system("curl -L -o xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip")
        os.system("unzip -o xray.zip xray && rm xray.zip && chmod +x xray")
    
    if not os.path.exists(GEO_DB_PATH):
        print("🌍 Downloading GeoIP...")
        try:
            r = requests.get("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb", timeout=20)
            with open(GEO_DB_PATH, "wb") as f: f.write(r.content)
        except: print("⚠️ GeoIP Download Failed")

def parse_vless(url):
    try:
        u = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(u.query)
        return {
            "uuid": u.username,
            "addr": u.hostname,
            "port": u.port or 443,
            "sni": q.get('sni', [u.hostname])[0],
            "sec": q.get('security', ['none'])[0],
            "type": q.get('type', ['tcp'])[0],
            "pbk": q.get('pbk', [''])[0],
            "sid": q.get('sid', [''])[0],
            "path": q.get('path', [''])[0],
            "fp": q.get('fp', ['chrome'])[0]
        }
    except: return None

def get_real_delay(vless_url, index):
    d = parse_vless(vless_url)
    if not d: return None
    
    l_port = 20000 + (index % 1000)
    c_path = os.path.abspath(f"c_{l_port}.json")
    
    stream = {"network": d['type'], "security": d['sec']}
    if d['sec'] == "tls": stream["tlsSettings"] = {"serverName": d['sni'], "fingerprint": d['fp']}
    elif d['sec'] == "reality": stream["realitySettings"] = {"serverName": d['sni'], "fingerprint": d['fp'], "publicKey": d['pbk'], "shortId": d['sid']}
    if d['type'] == "ws": stream["wsSettings"] = {"path": d['path']}

    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": l_port, "protocol": "socks", "settings": {"udp": True}, "listen": "127.0.0.1"}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": d['addr'], "port": d['port'], "users": [{"id": d['uuid'], "encryption": "none"}]}]},
            "streamSettings": stream
        }]
    }

    proc = None
    try:
        with open(c_path, "w") as f: json.dump(cfg, f)
        proc = subprocess.Popen([XRAY_PATH, "-c", c_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # زمان انتظار کوتاه برای شروع
        time.sleep(2)
        
        proxies = {"http": f"socks5://127.0.0.1:{l_port}", "https": f"socks5://127.0.0.1:{l_port}"}
        start = time.perf_counter()
        # تست با دامین معتبر
        r = requests.get("http://www.google.com/gen_204", proxies=proxies, timeout=5)
        
        if r.status_code in [200, 204]:
            return int((time.perf_counter() - start) * 1000)
    except: pass
    finally:
        if proc:
            proc.terminate()
            try: proc.wait(timeout=2)
            except: proc.kill()
        if os.path.exists(c_path): os.remove(c_path)
    return None

def main():
    if len(sys.argv) < 3: sys.exit(1)
    input_f, output_f, threshold = sys.argv[1], sys.argv[2], int(sys.argv[3])

    setup_environment()
    reader = None
    try: reader = geoip2.database.Reader(GEO_DB_PATH)
    except: pass

    with open(input_f, 'r') as f:
        lines = [l.strip() for l in f if l.startswith('vless://')]

    print(f"🔍 Phase 1: Quick TCP Check on {len(lines)}...")
    alive = []
    seen_ips = set()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_TCP) as exe:
        def check_tcp(l):
            d = parse_vless(l)
            if not d or d['addr'] in seen_ips: return None
            try:
                with socket.create_connection((d['addr'], d['port']), timeout=2):
                    seen_ips.add(d['addr'])
                    return l
            except: return None
        
        futs = [exe.submit(check_tcp, l) for l in lines]
        for f in as_completed(futs):
            res = f.result()
            if res: alive.append(res)

    print(f"🚀 Phase 2: Xray Real Test on {len(alive)}...")
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_XRAY) as exe:
        f_to_c = {exe.submit(get_real_delay, c, i): c for i, c in enumerate(alive)}
        for f in as_completed(f_to_c):
            delay = f.result()
            if delay and delay < threshold:
                c = f_to_c[f]
                d = parse_vless(c)
                try:
                    ip = socket.gethostbyname(d['addr'])
                    cc = reader.country(ip).country.iso_code or "mirsub"
                except: cc = "mirsub"
                results.append(f"{c.split('#')[0]}#{get_flag(cc)} mirsub")

    with open(output_f, 'w') as f:
        f.write('\n'.join(results) + '\n')
    
    if reader: reader.close()
    print(f"✅ Finished. {len(results)} saved.")

if __name__ == "__main__":
    main()
