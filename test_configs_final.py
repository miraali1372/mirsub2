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
MAX_WORKERS_XRAY = 10
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

def parse_vless(url):
    """استخراج دقیق اطلاعات VLESS"""
    try:
        parsed = urllib.parse.urlparse(url)
        uuid = parsed.username
        # مدیریت آدرس‌هایی که پورت دارند یا ندارند
        netloc_parts = parsed.hostname
        port = parsed.port if parsed.port else 443
        
        # پارامترهای اضافی مثل sni, security و غیره
        query = urllib.parse.parse_qs(parsed.query)
        sni = query.get('sni', [None])[0]
        security = query.get('security', ['none'])[0]
        fp = query.get('fp', [''])[0]
        type_net = query.get('type', ['tcp'])[0]

        return {
            "uuid": uuid,
            "host": netloc_parts,
            "port": port,
            "sni": sni if sni else netloc_parts,
            "security": security,
            "fp": fp,
            "type": type_net
        }
    except:
        return None

def get_real_delay(vless_url, index):
    data = parse_vless(vless_url)
    if not data: return None
    
    port = 20000 + (index % 1000)
    conf_file = f"c_{port}.json"
    
    try:
        # ساخت کانفیگ استاندارد Xray
        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": port, "protocol": "socks", "settings": {"udp": True}}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": data['host'],
                        "port": data['port'],
                        "users": [{"id": data['uuid'], "encryption": "none"}]
                    }]
                },
                "streamSettings": {
                    "network": data['type'],
                    "security": data['security'],
                    "tlsSettings": {"serverName": data['sni'], "fingerprint": data['fp']} if data['security'] == "tls" else {},
                    "realitySettings": {"serverName": data['sni'], "fingerprint": data['fp']} if data['security'] == "reality" else {}
                }
            }]
        }
        
        with open(conf_file, "w") as f: json.dump(config, f)
        
        proc = subprocess.Popen([XRAY_PATH, "-c", conf_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2) # افزایش زمان برای پایداری در رانر گیت‌هاب
        
        proxies = {"http": f"socks5://127.0.0.1:{port}", "https": f"socks5://127.0.0.1:{port}"}
        start = time.perf_counter()
        # استفاده از یک URL جایگزین برای تست سریع‌تر
        r = requests.get("http://www.google.com/gen_204", proxies=proxies, timeout=7)
        delay = int((time.perf_counter() - start) * 1000)
        
        proc.terminate()
        proc.wait()
        if os.path.exists(conf_file): os.remove(conf_file)
        
        if r.status_code in [200, 204]: return delay
    except:
        if 'proc' in locals(): proc.terminate()
        if os.path.exists(conf_file): os.remove(conf_file)
    return None

def test_tcp(line, seen):
    try:
        data = parse_vless(line)
        if not data: return None
        
        server_key = f"{data['host']}:{data['port']}"
        if server_key in seen: return None
        seen.add(server_key)
        
        s = socket.create_connection((data['host'], data['port']), timeout=3)
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
        futs = [exe.submit(test_tcp, l, seen) for l in raw_lines]
        for f in as_completed(futs):
            res = f.result()
            if res: alive_configs.append(res)

    print(f"🚀 Phase 2: Xray Real Test on {len(alive_configs)} configs...")
    final_results = []
    # فاز دوم را کمی آرام‌تر انجام می‌دهیم تا CPU رانر کم نیاورد
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_XRAY) as exe:
        future_to_config = {exe.submit(get_real_delay, conf, i): conf for i, conf in enumerate(alive_configs)}
        
        for future in as_completed(future_to_config):
            config = future_to_config[future]
            delay = future.result()
            if delay and delay < threshold:
                data = parse_vless(config)
                cc = get_country(reader, data['host'])
                final_results.append(f"{config.split('#')[0]}#{cc}-Real:{delay}ms")

    with open(output_f, 'w') as f:
        f.write('\n'.join(sorted(final_results)) + '\n')
    
    if reader: reader.close()
    print(f"✅ Finished. {len(final_results)} configs saved.")

if __name__ == "__main__":
    main()
