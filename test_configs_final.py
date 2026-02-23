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

# --- تنظیمات بهینه شده ---
MAX_WORKERS_TCP = 50
MAX_WORKERS_XRAY = 8 # کاهش تعداد برای جلوگیری از افت کیفیت تست در گیت‌هاب
XRAY_PATH = "./xray"
GEO_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
GEO_DB_PATH = "geoip.mmdb"

# نگاشت کد کشور به ایموجی پرچم
def get_flag(code):
    if not code or code == "mirsub": return "🚩"
    OFFSET = 127397
    return "".join(chr(ord(c) + OFFSET) for c in code.upper())

def setup_environment():
    if not os.path.exists(XRAY_PATH):
        print("📥 Downloading Xray Core...")
        os.system("curl -L -o xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip")
        os.system("unzip -o xray.zip xray && rm xray.zip && chmod +x xray")
    
    if not os.path.exists(GEO_DB_PATH):
        print("🌍 Downloading GeoIP database...")
        try:
            r = requests.get(GEO_DB_URL, timeout=30)
            with open(GEO_DB_PATH, "wb") as f: f.write(r.content)
        except: print("⚠️ GeoIP download failed.")

def get_country_code(reader, host):
    try:
        ip = socket.gethostbyname(host)
        code = reader.country(ip).country.iso_code
        return code.upper() if code else "mirsub"
    except: return "mirsub"

def parse_vless(url):
    try:
        u = urllib.parse.urlparse(url)
        q = urllib.parse.parse_qs(u.query)
        return {
            "uuid": u.username,
            "host": u.hostname,
            "port": u.port or 443,
            "sni": q.get('sni', [u.hostname])[0],
            "security": q.get('security', ['none'])[0],
            "fp": q.get('fp', ['chrome'])[0],
            "type": q.get('type', ['tcp'])[0],
            "path": q.get('path', [''])[0],
            "pbk": q.get('pbk', [''])[0],
            "sid": q.get('sid', [''])[0],
            "flow": q.get('flow', [''])[0]
        }
    except: return None

def get_real_delay(vless_url, index):
    d = parse_vless(vless_url)
    if not d: return None
    
    l_port = 20000 + (index % 5000)
    conf_file = f"c_{l_port}.json"
    
    # ساخت ساختار Outbound بر اساس نوع امنیت
    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{"address": d['host'], "port": d['port'], "users": [{"id": d['uuid'], "encryption": "none", "flow": d['flow']}]}]
        },
        "streamSettings": {
            "network": d['type'],
            "security": d['security'],
            "tcpSettings": {"header": {"type": "http"}} if d['type'] == "tcp" and not d['security'] else {}
        }
    }

    if d['security'] == "tls":
        outbound["streamSettings"]["tlsSettings"] = {"serverName": d['sni'], "fingerprint": d['fp']}
    elif d['security'] == "reality":
        outbound["streamSettings"]["realitySettings"] = {
            "serverName": d['sni'], "fingerprint": d['fp'],
            "publicKey": d['pbk'], "shortId": d['sid']
        }
    
    if d['type'] == "ws":
        outbound["streamSettings"]["wsSettings"] = {"path": d['path']}

    full_config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": l_port, "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound]
    }

    try:
        with open(conf_file, "w") as f: json.dump(full_config, f)
        
        proc = subprocess.Popen([XRAY_PATH, "-c", conf_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3) # فرصت کافی برای Handshake
        
        proxies = {"http": f"socks5://127.0.0.1:{l_port}", "https": f"socks5://127.0.0.1:{l_port}"}
        start = time.perf_counter()
        # تست با دامین معتبر و Timeout بالاتر
        r = requests.get("http://www.google.com/gen_204", proxies=proxies, timeout=10)
        delay = int((time.perf_counter() - start) * 1000)
        
        proc.terminate()
        proc.wait()
        os.remove(conf_file)
        
        if r.status_code in [200, 204]: return delay
    except:
        if 'proc' in locals(): proc.terminate()
        if os.path.exists(conf_file): os.remove(conf_file)
    return None

def main():
    if len(sys.argv) < 3: sys.exit(1)
    input_f, output_f, threshold = sys.argv[1], sys.argv[2], int(sys.argv[3])

    setup_environment()
    reader = None
    try: reader = geoip2.database.Reader(GEO_DB_PATH)
    except: pass

    with open(input_f, 'r') as f:
        raw_lines = [l.strip() for l in f if l.startswith('vless://')]

    print(f"🔍 Phase 1: TCP Filtering...")
    alive_configs = []
    seen = set()
    for l in raw_lines:
        d = parse_vless(l)
        if d:
            key = f"{d['host']}:{d['port']}"
            if key not in seen:
                try:
                    with socket.create_connection((d['host'], d['port']), timeout=2):
                        alive_configs.append(l)
                        seen.add(key)
                except: pass

    print(f"🚀 Phase 2: Xray Real Test on {len(alive_configs)} configs...")
    final_results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_XRAY) as exe:
        f_to_c = {exe.submit(get_real_delay, c, i): c for i, c in enumerate(alive_configs)}
        for f in as_completed(f_to_c):
            conf = f_to_c[f]
            delay = f.result()
            if delay and delay < threshold:
                d = parse_vless(conf)
                cc = get_country_code(reader, d['host'])
                flag = get_flag(cc)
                final_results.append(f"{conf.split('#')[0]}#{flag} mirsub | {delay}ms")

    with open(output_f, 'w') as f:
        f.write('\n'.join(sorted(final_results)) + '\n')
    
    if reader: reader.close()
    print(f"✅ Finished. {len(final_results)} configs saved.")

if __name__ == "__main__":
    main()
