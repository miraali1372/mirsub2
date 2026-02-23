import socket
import time
import urllib.parse
import sys
import os
import gzip
import shutil
import requests
import geoip2.database
from concurrent.futures import ThreadPoolExecutor, as_completed

# تنظیمات
MAX_WORKERS = 50
# استفاده از دیتابیس رایگان DB-IP که نیاز به لایسنس ندارد
GEO_DB_URL = "https://download.db-ip.com/free/dbip-country-lite-2024-05.mmdb.gz"
GEO_DB_PATH = "geoip.mmdb"

def download_geoip_db():
    """دانلود خودکار دیتابیس کشورها در صورت عدم وجود"""
    if not os.path.exists(GEO_DB_PATH):
        print("🌍 Downloading GeoIP database...")
        try:
            # ایجاد یک یوزر-اجنت برای جلوگیری از مسدود شدن توسط سرور دانلود
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(GEO_DB_URL, headers=headers, stream=True, timeout=30)
            with open("geoip.mmdb.gz", "wb") as f:
                shutil.copyfileobj(response.raw, f)
            
            with gzip.open("geoip.mmdb.gz", "rb") as f_in:
                with open(GEO_DB_PATH, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            os.remove("geoip.mmdb.gz")
            print("✅ GeoIP database ready.")
        except Exception as e:
            print(f"❌ Failed to download GeoIP DB: {e}")

def get_country_code(reader, host):
    """یافتن کد کشور با استفاده از دیتابیس آفلاین"""
    if not reader:
        return "??"
    try:
        ip = socket.gethostbyname(host)
        response = reader.country(ip)
        return response.country.iso_code if response.country.iso_code else "??"
    except:
        return "??"

def extract_info(vless_url):
    """استخراج آدرس، پورت و شناسه‌ی یکتا برای حذف تکراری‌ها"""
    try:
        parsed = urllib.parse.urlparse(vless_url)
        # بخش بعد از @ و قبل از پورت/مسیر
        netloc = parsed.netloc.split('@')[-1].split('/')[0].split('?')[0]
        
        if '[' in netloc: # پشتیبانی از IPv6
            host = netloc[netloc.find('[')+1:netloc.find(']')]
            port_part = netloc.split(']')[-1]
            port = int(port_part[1:]) if ':' in port_part else 443
        elif ':' in netloc:
            host, port = netloc.split(':', 1)
            port = int(port)
        else:
            host = netloc
            port = 443
        
        # شناسه‌ی یکتا بر اساس آدرس و پورت (برای حذف دابلیکیت‌های واقعی)
        server_identity = f"{host}:{port}"
        return host, port, server_identity
    except:
        return None

def test_one_config(line, threshold_ms, reader, seen_servers):
    info = extract_info(line)
    if not info:
        return None
    
    host, port, server_identity = info

    # جلوگیری از پردازش سرورهای تکراری
    if server_identity in seen_servers:
        return None
    seen_servers.add(server_identity)

    try:
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(threshold_ms / 1000.0 + 0.5) # زمان انتظار متناسب با آستانه
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
        print("Usage: python script.py <input> <output> <threshold>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    threshold_ms = int(sys.argv[3]) if len(sys.argv) >= 4 else 150

    download_geoip_db()
    
    reader = None
    if os.path.exists(GEO_DB_PATH):
        reader = geoip2.database.Reader(GEO_DB_PATH)

    if not os.path.exists(input_file):
        print(f"File {input_file} not found")
        return

    with open(input_file, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip() and line.startswith('vless://')]

    valid_configs = []
    seen_servers = set() # مجموعه برای ذخیره سرورهای یونیک در طول اجرا
    
    print(f"🚀 Testing {len(lines)} configs (Threshold: {threshold_ms}ms)...")

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
    print(f"✅ Success! {len(valid_configs)} high-quality unique configs saved.")

if __name__ == "__main__":
    main()