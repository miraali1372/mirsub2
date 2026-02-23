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

# --- تنظیمات ---
MAX_WORKERS_TCP = 50
MAX_WORKERS_XRAY = 10
XRAY_PATH = "./xray"
GEO_DB_PATH = "geoip.mmdb"

def get_flag(code):
    if not code or code == "mirsub": return "🚩"
    return "".join(chr(ord(c) + 127397) for c in code.upper())

def setup_environment():
    if not os.path.exists(XRAY_PATH):
        os.system("curl -L -o xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip")
        os.system("unzip -o xray.zip xray && rm xray.zip && chmod +x xray")
    
    if not os.path.exists(GEO_DB_PATH):
        url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
        r = requests.get(url, timeout=30)
        with open(GEO_DB_PATH, "wb") as f: f.write(r.content)

def parse_vless(url):
    try:
        if not url.startswith("vless://"): return None
        parts = url.split("://")[1].split("@")
        uuid = parts[0]
        rest = parts[1].split("?")
        host_port = rest[0].split(":")
        address = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443
        
        query = urllib.parse.parse_qs(rest[1]) if len(rest) > 1 else {}
        def get_q(key): return query.get(key, [''])[0].split('#')[0]

        return {
            "uuid": uuid, "address": address, "port": port,
            "security": get_q('security') or 'none',
            "sni": get_q('sni') or address,
            "type": get_q('type') or 'tcp',
            "pbk": get_q('pbk'), "sid": get_q('sid'),
            "path": get_q('path'), "fp": get_q('fp') or 'chrome'
        }
    except: return None

def get_real_delay(vless_url, index):
    d = parse_vless(vless_url)
    if not d: return None
    
    l_port = 20000 + (index % 1000)
    conf_file = f"config_{l_port}.json"
    
    # ساخت دقيق Outbound برای Xray
    stream_settings = {
        "network": d['type'],
        "security": d['security'],
    }
    
    if d['security'] == "tls":
        stream_settings["tlsSettings"] = {"serverName": d['sni'], "fingerprint": d['fp']}
    elif d['security'] == "reality":
        stream_settings["realitySettings"] = {
            "serverName": d['sni'], "fingerprint": d['fp'],
            "publicKey": d['pbk'], "shortId": d['sid']
        }
    
    if d['type'] == "ws":
        stream_settings["wsSettings"] = {"path": d['path']}

    xray_config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": l_port, "protocol": "socks", "settings": {"udp": True}, "listen": "127.0.0.1"}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": d['address'], "port": d['port'], "users": [{"id": d['uuid'], "encryption": "none"}]}]},
            "streamSettings": stream_settings
        }]
    }

    try:
        with open(conf_file, "w") as f: json.dump(xray_config, f)
        
        # اجرای Xray با آدرس مطلق
        proc = subprocess.Popen([os.path.abspath(XRAY_PATH), "-c", os.path.abspath(conf_file)], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3.5)
        
        proxies = {"http": f"socks5://127.0.0.1:{l_port}", "https": f"socks5://127.0.0.1:{l_port}"}
        start = time.perf_counter()
        # تست با یک آدرس بسیار سبک
        r = requests.get("http://www.google.com/gen_204", proxies=proxies, timeout=10)
        delay = int((time.perf_counter() - start) * 1000)
        
        proc.terminate()
        proc.wait()
        os.remove(conf_file)
        
        if r.status_code in [200, 204]:
            return delay
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

    print(f"🔍 Phase 1: TCP Check...")
    alive = []
    seen = set()
    for l in raw_lines:
        d = parse_vless(l)
        if d and d['address'] not in seen:
            try:
                with socket.create_connection((d['address'], d['port']), timeout=2):
                    alive.append(l)
                    seen.add(d['address'])
            except: pass

    print(f"🚀 Phase 2: Xray Real Test on {len(alive)} configs...")
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_XRAY) as exe:
        future_to_conf = {exe.submit(get_real_delay, c, i): c for i, c in enumerate(alive)}
        for f in as_completed(future_to_conf):
            delay = f.result()
            if delay and delay < threshold:
                conf = future_to_conf[f]
                d = parse_vless(conf)
                try:
                    ip = socket.gethostbyname(d['address'])
                    cc = reader.country(ip).country.iso_code or "mirsub"
                except: cc = "mirsub"
                
                flag = get_flag(cc)
                results.append(f"{conf.split('#')[0]}#{flag} mirsub")

    with open(output_f, 'w') as f:
        f.write('\n'.join(results) + '\n')
    
    if reader: reader.close()
    print(f"✅ Saved {len(results)} working configs.")

if __name__ == "__main__":
    main()
