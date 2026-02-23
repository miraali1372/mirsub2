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
MAX_WORKERS_XRAY = 10 # تست واقعی سنگین است، تعداد کمتر برای پایداری
XRAY_PATH = "./xray"
GEO_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
GEO_DB_PATH = "geoip.mmdb"

def setup_environment():
    """دانلود هسته Xray و دیتابیس لوکیشن"""
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
        return reader.country(ip).country.iso_code or "??"
    except: return "??"

def get_real_delay(vless_url, index):
    """تست واقعی با Xray Core"""
    port = 20000 + index
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": "", "port": 443, "users": [{"id": "", "encryption": "none"}]}]}
        }]
    }
    
    try:
        parsed = urllib.parse.urlparse(vless_url)
        netloc = parsed.netloc.split('@')[-1]
        host = netloc.split(':')[0]
        v_port = int(netloc.split(':')[-1].split('?')[0])
        uuid = parsed.netloc.split('@')[0]
        
        config["outbounds"][0]["settings"]["vnext"][0]["address"] = host
        config["outbounds"][0]["settings"]["vnext"][0]["port"] = v_port
        config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"] = uuid
        
        conf_file = f"c_{port}.json"
        with open(conf_file, "w") as f: json.dump(config, f)
        
        proc = subprocess.Popen([XRAY_PATH, "-c", conf_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5) # زمان برای لود شدن هسته
        
        proxies = {"http": f"socks5://127.0.0.1:{port}", "https": f"socks5://127.0.0.1:{port}"}
        start = time.perf_counter()
        # تست با یک سایت سبک و معتبر
        r = requests.get("http://www.google.com/gen_204", proxies=proxies, timeout=4)
        delay = int((time.perf_counter() - start) * 1000)
        
        proc.terminate()
        os.remove(conf_file)
        if r.status_code in [200, 204]: return delay
    except:
        try: proc.terminate()
        except: pass
    return None

def test_tcp(line, threshold, seen):
    """مرحله اول: تست زنده بودن پورت"""
    try:
        parsed = urllib.parse.urlparse(line)
        netloc = parsed.netloc.split('@')[-1].split('/')[0].split('?')[0]
        host = netloc.split(':')[0] if ':' in netloc else netloc
        port = int(netloc.split(':')[-1]) if ':' in netloc else 443
        
        if f"{host}:{port}" in seen: return None
        seen.add(f"{host}:{port}")
        
        start = time.perf_counter()
        s = socket.create_connection((host, port), timeout=threshold/1000)
        s.close()
        return line
    except: return None

def main():
    if len(sys.argv) < 3: sys.exit(1)
    input_f, output_f = sys.argv[1], sys.argv[2]
    threshold = int(sys.argv[3]) if len(sys.argv) >= 4 else 150

    setup_environment()
    reader = None
    try: reader = geoip2.database.Reader(GEO_DB_PATH)
    except: pass

    with open(input_f, 'r') as f:
        raw_lines = [l.strip() for l in f if l.startswith('vless://')]

    # مرحله ۱: TCP Ping
    print(f"🔍 Phase 1: TCP Filtering {len(raw_lines)} configs...")
    alive_configs = []
    seen = set()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_TCP) as exe:
        futs = [exe.submit(test_tcp, l, threshold, seen) for l in raw_lines]
        for f in as_completed(futs):
            if f.result(): alive_configs.append(f.result())

    # مرحله ۲: Xray Real Delay
    print(f"🚀 Phase 2: Xray Real Test on {len(alive_configs)} configs...")
    final_configs = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_XRAY) as exe:
        # ارسال ایندکس برای جلوگیری از تداخل پورت‌های لوکال
        futs = [exe.submit(get_real_delay, l, i) for i, l in enumerate(alive_configs)]
        for i, f in enumerate(as_completed(futs)):
            delay = f.result()
            if delay and delay < threshold:
                config = alive_configs[i]
                host = urllib.parse.urlparse(config).netloc.split('@')[-1].split(':')[0]
                cc = get_country(reader, host)
                final_configs.append(f"{config.split('#')[0]}#{cc}-Real:{delay}ms")

    with open(output_f, 'w') as f:
        f.write('\n'.join(sorted(final_configs)) + '\n')
    
    if reader: reader.close()
    print(f"✅ Finished. Final count: {len(final_configs)}")

if __name__ == "__main__":
    main()
