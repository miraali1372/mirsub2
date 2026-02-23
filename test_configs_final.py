import socket
import time
import urllib.parse
import sys
import os
import requests
import geoip2.database
from concurrent.futures import ThreadPoolExecutor, as_completed

# تنظیمات
MAX_WORKERS = 50
GEO_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
GEO_DB_PATH = "new_geoip.mmdb" # تغییر نام برای رفع کش

def download_geoip_db():
    if not os.path.exists(GEO_DB_PATH):
        print("🌍 Downloading GeoIP database...")
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(GEO_DB_URL, headers=headers, timeout=60)
            if response.status_code == 200:
                with open(GEO_DB_PATH, "wb") as f:
                    f.write(response.content)
                print(f"✅ Downloaded: {len(response.content)} bytes")
            else:
                print(f"⚠️ HTTP Error: {response.status_code}")
        except Exception as e:
            print(f"⚠️ Download error: {e}")

def get_country_code(reader, host):
    if reader is None: return "??"
    try:
        ip = socket.gethostbyname(host)
        return reader.country(ip).country.iso_code or "??"
    except:
        return "??"

def extract_info(vless_url):
    try:
        parsed = urllib.parse.urlparse(vless_url)
        netloc = parsed.netloc.split('@')[-1].split('/')[0].split('?')[0]
        if '[' in netloc:
            host = netloc[netloc.find('[')+1:netloc.find(']')]
            port = int(netloc.split(']')[-1][1:]) if ':' in netloc.split(']')[-1] else 443
        elif ':' in netloc:
            host, port = netloc.split(':', 1)
            port = int(port)
        else:
            host, port = netloc, 443
        return host, port, f"{host}:{port}"
    except:
        return None

def test_one_config(line, threshold_ms, reader, seen_servers):
    info = extract_info(line)
    if not info: return None
    host, port, server_id = info
    if server_id in seen_servers: return None
    seen_servers.add(server_id)

    try:
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(threshold_ms / 1000.0 + 0.5)
        sock.connect((host, port))
        sock.close()
        latency = (time.perf_counter() - start) * 1000
        
        if latency < threshold_ms:
            country = get_country_code(reader, host)
            return f"{line.split('#')[0]}#{country}"
    except:
        return None

def main():
    if len(sys.argv) < 3: sys.exit(1)
    input_file, output_file = sys.argv[1], sys.argv[2]
    threshold_ms = int(sys.argv[3]) if len(sys.argv) >= 4 else 150

    download_geoip_db()
    
    reader = None
    if os.path.exists(GEO_DB_PATH):
        try:
            reader = geoip2.database.Reader(GEO_DB_PATH)
            print("📖 Database loaded successfully.")
        except Exception as e:
            print(f"⚠️ DB Error: {e}. Cleaning up...")
            if os.path.exists(GEO_DB_PATH): os.remove(GEO_DB_PATH)
            reader = None # ادامه کار بدون دیتابیس

    with open(input_file, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip().startswith('vless://')]

    valid_configs = []
    seen_servers = set()
    
    print(f"🚀 Testing {len(lines)} configs...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_one_config, l, threshold_ms, reader, seen_servers) for l in lines]
        for fut in as_completed(futures):
            res = fut.result()
            if res: valid_configs.append(res)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(valid_configs)) + '\n')

    if reader: reader.close()
    print(f"✅ Done. Found {len(valid_configs)} configs.")

if __name__ == "__main__":
    main()