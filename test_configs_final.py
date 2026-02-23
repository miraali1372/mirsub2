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
# استفاده از یک لینک مستقیم و بسیار پایدار
GEO_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
GEO_DB_PATH = "geoip.mmdb"

def download_geoip_db():
    """دانلود دیتابیس با متد امن‌تر"""
    if not os.path.exists(GEO_DB_PATH):
        print("🌍 Downloading GeoIP database...")
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(GEO_DB_URL, headers=headers, timeout=60)
            if response.status_code == 200:
                with open(GEO_DB_PATH, "wb") as f:
                    f.write(response.content)
                print(f"✅ GeoIP database downloaded ({len(response.content)} bytes).")
            else:
                print(f"⚠️ Download failed. Status: {response.status_code}")
        except Exception as e:
            print(f"⚠️ Error downloading DB: {e}")

def get_country_code(reader, host):
    if not reader:
        return "??"
    try:
        ip = socket.gethostbyname(host)
        response = reader.country(ip)
        return response.country.iso_code if response.country.iso_code else "??"
    except:
        return "??"

def extract_info(vless_url):
    try:
        parsed = urllib.parse.urlparse(vless_url)
        netloc = parsed.netloc.split('@')[-1].split('/')[0].split('?')[0]
        if '[' in netloc:
            host = netloc[netloc.find('[')+1:netloc.find(']')]
            port_part = netloc.split(']')[-1]
            port = int(port_part[1:]) if ':' in port_part else 443
        elif ':' in netloc:
            host, port = netloc.split(':', 1)
            port = int(port)
        else:
            host = netloc
            port = 443
        return host, port, f"{host}:{port}"
    except:
        return None

def test_one_config(line, threshold_ms, reader, seen_servers):
    info = extract_info(line)
    if not info: return None
    host, port, server_identity = info

    if server_identity in seen_servers: return None
    seen_servers.add(server_identity)

    try:
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(threshold_ms / 1000.0 + 0.5)
        sock.connect((host, port))
        sock.close()
        latency = (time.perf_counter() - start) * 1000
        
        if latency < threshold_ms:
            country = get_country_code(reader, host)
            base = line.split('#')[0]
            return f"{base}#{country}"
    except:
        pass
    return None

def main():
    if len(sys.argv) < 3:
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    threshold_ms = int(sys.argv[3]) if len(sys.argv) >= 4 else 150

    download_geoip_db()
    
    reader = None
    if os.path.exists(GEO_DB_PATH):
        try:
            reader = geoip2.database.Reader(GEO_DB_PATH)
        except Exception as e:
            print(f"⚠️ Could not open MaxMind DB: {e}. Continuing without country codes.")

    with open(input_file, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip() and line.startswith('vless://')]

    valid_configs = []
    seen_servers = set()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(test_one_config, line, threshold_ms, reader, seen_servers) for line in lines]
        for future in as_completed(futures):
            result = future.result()
            if result:
                valid_configs.append(result)

    valid_configs.sort()
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_configs) + '\n')

    if reader: reader.close()
    print(f"✅ Task finished. {len(valid_configs)} configs saved.")

if __name__ == "__main__":
    main()