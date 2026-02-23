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

# تنظیمات
MAX_WORKERS_TCP = 50
MAX_WORKERS_XRAY = 15
XRAY_PATH = "./xray"
GEO_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
GEO_DB_PATH = "geoip.mmdb"

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

def get_country(reader, host):
    try:
        ip = socket.gethostbyname(host)
        code = reader.country(ip).country.iso_code
        return code if code else "mirsub"
    except: return "mirsub"

def get_real_delay(vless_url, index):
    port = 20000 + (index % 1000)
    conf_file = f"c_{port}.json"
    
    try:
        parsed = urllib.parse.urlparse(vless_url)
        netloc = parsed.netloc.split('@')[-1]
        host = netloc.split(':')[0]
        v_port = int(netloc.split(':')[-1].split('?')[0])
        uuid = parsed.netloc.split('@')[0]
        
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": port, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": host, "port": v_port, "users": [{"id": uuid, "encryption": "none"}]}]}
            }]
        }
        
        with open(conf_file, "w") as f: json.dump(config, f)
        
        proc = subprocess.Popen([XRAY_PATH, "-c", conf_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        
        proxies = {"http": f"socks5://127.0.0.1:{port}", "https": f"socks5://127.0.0.1:{port}"}
        start = time.perf_counter()
        r = requests.get("http://www.google.com/gen_204", proxies=proxies, timeout=5)
        delay = int((time.perf_counter() - start) * 1000)
        
        proc.terminate()
        proc.wait()
        if os.path.exists(conf_file): os.remove(conf_file)
        
        if r.status_code in [200, 204]: return delay
    except:
        if os.path.exists(conf_file): os.remove(conf_file)
    return None

def test_tcp(line, threshold, seen):
    try:
        parsed = urllib.parse.urlparse(line)
        netloc = parsed.netloc.split('@')[-1].split('/')[0].split('?')[0]
        host = netloc.split(':')[0] if ':' in netloc else netloc
        port = int(netloc.split(':')[-1]) if ':' in netloc else 443
        
        server_key = f"{host}:{port}"
        if server_key in seen: return None
        seen.add(server_key)
        
        s = socket.create_connection((host, port), timeout=2)
        s.close()
        return line
    except: return None

def main():
    if len(sys.argv) < 3: sys.exit(1)
    input_f, output_f = sys.argv[1], sys.argv[2]
    threshold = int(sys.argv[3])

    setup_environment()
    reader = None
    try: reader = geoip2.database.Reader(GEO_DB_PATH)
    except: pass

    with open(input_f, 'r') as f:
        raw_lines = [l.strip() for l in f if l.startswith('vless://')]

    print(f"🔍 Phase 1: TCP Filtering...")
    alive_configs = []
    seen = set()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_TCP) as exe:
        futs = [exe.submit(test_tcp, l, threshold, seen) for l in raw_lines]
        for f in as_completed(futs):
            res = f.result()
            if res: alive_configs.append(res)

    print(f"🚀 Phase 2: Xray Real Test on {len(alive_configs)} configs...")
    final_results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_XRAY) as exe:
        # نگهداری نگاشت کانفیگ به فیوچر
        future_to_config = {exe.submit(get_real_delay, conf, i): conf for i, conf in enumerate(alive_configs)}
        
        for future in as_completed(future_to_config):
            config = future_to_config[future]
            delay = future.result()
            if delay and delay < threshold:
                host = urllib.parse.urlparse(config).netloc.split('@')[-1].split(':')[0]
                cc = get_country(reader, host)
                final_results.append(f"{config.split('#')[0]}#{cc}-Real:{delay}ms")

    with open(output_f, 'w') as f:
        f.write('\n'.join(sorted(final_results)) + '\n')
    
    if reader: reader.close()
    print(f"✅ Finished. {len(final_results)} configs saved.")

if __name__ == "__main__":
    main()
