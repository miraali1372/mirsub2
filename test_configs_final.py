#!/usr/bin/env python3
"""Test VLESS share links with isolated Xray processes and write stable results.

Usage:
    python3 test_configs_final.py unique.txt subscription.txt

Environment variables:
    MAX_WORKERS       Number of concurrent Xray processes (default: 24)
    TEST_ATTEMPTS     HTTPS attempts per config (default: 2)
    STARTUP_TIMEOUT   Seconds to wait for Xray's local HTTP proxy (default: 5)
    CONNECT_TIMEOUT   Requests connect timeout in seconds (default: 5)
    READ_TIMEOUT      Requests read timeout in seconds (default: 8)
    MAX_DELAY_MS      Reject successful requests slower than this (default: 10000)
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

XRAY_PATH = Path(os.path.abspath("./xray"))
XRAY_DOWNLOAD_URL = (
    "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
)
TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"

MAX_WORKERS = max(1, int(os.getenv("MAX_WORKERS", "24")))
TEST_ATTEMPTS = max(1, int(os.getenv("TEST_ATTEMPTS", "2")))
STARTUP_TIMEOUT = max(1.0, float(os.getenv("STARTUP_TIMEOUT", "5")))
CONNECT_TIMEOUT = max(1.0, float(os.getenv("CONNECT_TIMEOUT", "5")))
READ_TIMEOUT = max(1.0, float(os.getenv("READ_TIMEOUT", "8")))
MAX_DELAY_MS = max(1, int(os.getenv("MAX_DELAY_MS", "10000")))

SUPPORTED_NETWORKS = {
    "tcp",
    "raw",
    "ws",
    "websocket",
    "grpc",
    "httpupgrade",
    "xhttp",
    "kcp",
    "mkcp",
    "http",
    "h2",
}
SUPPORTED_SECURITY = {"none", "tls", "reality"}

_PRINT_LOCK = threading.Lock()


class ConfigError(ValueError):
    """Raised when a VLESS share link cannot be represented safely."""


@dataclass(frozen=True)
class VlessLink:
    source_url: str
    base_url: str
    user_id: str
    address: str
    port: int
    encryption: str
    flow: str
    network: str
    security: str
    sni: str
    fingerprint: str
    alpn: tuple[str, ...]
    host: str
    path: str
    service_name: str
    authority: str
    mode: str
    header_type: str
    seed: str
    reality_password: str
    short_id: str
    spider_x: str
    mldsa65_verify: str
    ech_config_list: str
    pinned_peer_cert_sha256: str
    verify_peer_cert_by_name: str
    xhttp_extra: dict[str, Any] | None
    finalmask: dict[str, Any] | None
    mtu: int | None
    tti: int | None


@dataclass(frozen=True)
class TestResult:
    output_url: str
    delay_ms: int
    country_code: str
    outbound_ip: str


class PortAllocator:
    """Allocate ports that are unique among this script's active workers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: set[int] = set()

    def acquire(self) -> int:
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = int(sock.getsockname()[1])

            with self._lock:
                if port not in self._active:
                    self._active.add(port)
                    return port

    def release(self, port: int) -> None:
        with self._lock:
            self._active.discard(port)


PORTS = PortAllocator()


def log(message: str) -> None:
    with _PRINT_LOCK:
        print(message, flush=True)


def get_flag(country_code: str) -> str:
    code = (country_code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return "🚩"
    return "".join(chr(ord(char) + 127397) for char in code)


def first_param(params: dict[str, list[str]], *names: str, default: str = "") -> str:
    for name in names:
        values = params.get(name)
        if values:
            return values[0]
    return default


def optional_int(value: str, field_name: str) -> int | None:
    if not value:
        return None
    try:
        result = int(value)
    except ValueError as exc:
        raise ConfigError(f"invalid integer in {field_name}") from exc
    if result <= 0:
        raise ConfigError(f"{field_name} must be positive")
    return result


def parse_json_object(value: str, field_name: str) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in {field_name}") from exc
    if not isinstance(parsed, dict):
        raise ConfigError(f"{field_name} must be a JSON object")
    return parsed


def canonical_connection_key(url: str) -> tuple[Any, ...]:
    """Deduplicate equivalent links while ignoring name fragments and query order."""

    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme.lower() != "vless":
        raise ConfigError("not a VLESS link")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigError("invalid port") from exc

    if not parsed.username or not parsed.hostname or port is None:
        raise ConfigError("missing UUID, host, or port")

    query = tuple(sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
    return (
        urllib.parse.unquote(parsed.username).lower(),
        parsed.hostname.lower(),
        port,
        query,
    )


def parse_vless(url: str) -> VlessLink:
    source_url = url.strip()
    parsed = urllib.parse.urlsplit(source_url)

    if parsed.scheme.lower() != "vless":
        raise ConfigError("unsupported scheme")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigError("invalid port") from exc

    user_id = urllib.parse.unquote(parsed.username or "").strip()
    address = (parsed.hostname or "").strip()

    if not user_id or not address or port is None or not 1 <= port <= 65535:
        raise ConfigError("missing or invalid UUID, address, or port")

    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    network = first_param(params, "type", default="tcp").strip().lower() or "tcp"
    if network not in SUPPORTED_NETWORKS:
        raise ConfigError(f"unsupported transport: {network}")

    security = first_param(params, "security", default="none").strip().lower() or "none"
    if security not in SUPPORTED_SECURITY:
        raise ConfigError(f"unsupported transport security: {security}")

    encryption = first_param(params, "encryption", default="none").strip() or "none"
    flow = first_param(params, "flow").strip()
    sni = first_param(params, "sni", default=address).strip() or address
    fingerprint = first_param(params, "fp", "fingerprint", default="chrome").strip() or "chrome"
    alpn_raw = first_param(params, "alpn").strip()
    alpn = tuple(part.strip() for part in alpn_raw.split(",") if part.strip())

    path = first_param(params, "path", default="/") or "/"
    host = first_param(params, "host").strip()
    service_name = first_param(params, "serviceName", "service_name").strip()
    authority = first_param(params, "authority").strip()
    mode = first_param(params, "mode", default="auto").strip() or "auto"
    header_type = first_param(params, "headerType", default="none").strip() or "none"
    seed = first_param(params, "seed").strip()

    reality_password = first_param(params, "pbk", "password", "publicKey").strip()
    short_id = first_param(params, "sid", "shortId").strip()
    spider_x = first_param(params, "spx", "spiderX").strip()
    mldsa65_verify = first_param(params, "pqv", "mldsa65Verify").strip()

    if security == "reality" and not reality_password:
        raise ConfigError("REALITY link has no pbk/password")

    ech_config_list = first_param(params, "ech").strip()
    pinned_peer_cert_sha256 = first_param(params, "pcs").strip()
    verify_peer_cert_by_name = first_param(params, "vcn").strip()

    xhttp_extra = parse_json_object(first_param(params, "extra"), "extra")
    finalmask = parse_json_object(first_param(params, "fm"), "fm")
    mtu = optional_int(first_param(params, "mtu"), "mtu")
    tti = optional_int(first_param(params, "tti"), "tti")

    base_url = urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path, parsed.query, "")
    )

    return VlessLink(
        source_url=source_url,
        base_url=base_url,
        user_id=user_id,
        address=address,
        port=port,
        encryption=encryption,
        flow=flow,
        network=network,
        security=security,
        sni=sni,
        fingerprint=fingerprint,
        alpn=alpn,
        host=host,
        path=path,
        service_name=service_name,
        authority=authority,
        mode=mode,
        header_type=header_type,
        seed=seed,
        reality_password=reality_password,
        short_id=short_id,
        spider_x=spider_x,
        mldsa65_verify=mldsa65_verify,
        ech_config_list=ech_config_list,
        pinned_peer_cert_sha256=pinned_peer_cert_sha256,
        verify_peer_cert_by_name=verify_peer_cert_by_name,
        xhttp_extra=xhttp_extra,
        finalmask=finalmask,
        mtu=mtu,
        tti=tti,
    )


def build_stream_settings(link: VlessLink, legacy_reality_key: bool = False) -> dict[str, Any]:
    network_aliases = {
        "tcp": "raw",
        "raw": "raw",
        "ws": "websocket",
        "websocket": "websocket",
        "kcp": "mkcp",
        "mkcp": "mkcp",
        "h2": "http",
    }
    network = network_aliases.get(link.network, link.network)

    stream: dict[str, Any] = {
        "network": network,
        "security": link.security,
    }

    if network == "raw":
        stream["rawSettings"] = {
            "header": {"type": link.header_type},
        }
    elif network == "websocket":
        ws_settings: dict[str, Any] = {"path": link.path}
        if link.host:
            ws_settings["host"] = link.host
            ws_settings["headers"] = {"Host": link.host}
        stream["wsSettings"] = ws_settings
    elif network == "grpc":
        grpc_settings: dict[str, Any] = {
            "serviceName": link.service_name,
            "multiMode": link.mode.lower() == "multi",
        }
        if link.authority:
            grpc_settings["authority"] = link.authority
        stream["grpcSettings"] = grpc_settings
    elif network == "httpupgrade":
        upgrade_settings: dict[str, Any] = {"path": link.path}
        if link.host:
            upgrade_settings["host"] = link.host
            upgrade_settings["headers"] = {"Host": link.host}
        stream["httpupgradeSettings"] = upgrade_settings
    elif network == "xhttp":
        xhttp_settings: dict[str, Any] = {
            "path": link.path,
            "mode": link.mode,
        }
        if link.host:
            xhttp_settings["host"] = link.host
        if link.xhttp_extra is not None:
            xhttp_settings["extra"] = link.xhttp_extra
        stream["xhttpSettings"] = xhttp_settings
    elif network == "mkcp":
        kcp_settings: dict[str, Any] = {
            "header": {"type": link.header_type},
        }
        if link.seed:
            kcp_settings["seed"] = link.seed
        if link.mtu is not None:
            kcp_settings["mtu"] = link.mtu
        if link.tti is not None:
            kcp_settings["tti"] = link.tti
        stream["kcpSettings"] = kcp_settings
    elif network == "http":
        http_settings: dict[str, Any] = {"path": link.path}
        if link.host:
            http_settings["host"] = [link.host]
        stream["httpSettings"] = http_settings

    if link.security == "tls":
        tls_settings: dict[str, Any] = {
            "serverName": link.sni,
            "fingerprint": link.fingerprint,
        }
        if link.alpn:
            tls_settings["alpn"] = list(link.alpn)
        if link.ech_config_list:
            tls_settings["echConfigList"] = link.ech_config_list
        if link.pinned_peer_cert_sha256:
            tls_settings["pinnedPeerCertSha256"] = link.pinned_peer_cert_sha256
        if link.verify_peer_cert_by_name:
            tls_settings["verifyPeerCertByName"] = link.verify_peer_cert_by_name
        stream["tlsSettings"] = tls_settings

    elif link.security == "reality":
        reality_settings: dict[str, Any] = {
            "serverName": link.sni,
            "fingerprint": link.fingerprint,
            "shortId": link.short_id,
            "spiderX": link.spider_x,
        }
        reality_settings["publicKey" if legacy_reality_key else "password"] = (
            link.reality_password
        )
        if link.mldsa65_verify:
            reality_settings["mldsa65Verify"] = link.mldsa65_verify
        stream["realitySettings"] = reality_settings

    if link.finalmask is not None:
        stream["finalmask"] = link.finalmask

    return stream


def build_xray_config(
    link: VlessLink,
    local_port: int,
    legacy_reality_key: bool = False,
) -> dict[str, Any]:
    user: dict[str, Any] = {
        "id": link.user_id,
        "encryption": link.encryption,
        "level": 0,
    }
    if link.flow:
        user["flow"] = link.flow

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": local_port,
                "protocol": "http",
                "settings": {},
                "tag": "local-http",
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "address": link.address,
                    "port": link.port,
                    "id": user["id"],
                    "encryption": user["encryption"],
                    "level": user["level"],
                    **({"flow": user["flow"]} if "flow" in user else {}),
                },
                "streamSettings": build_stream_settings(link, legacy_reality_key),
                "mux": {"enabled": False},
                "tag": "proxy",
            }
        ],
    }


def terminate_process(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass


def wait_for_local_proxy(proc: subprocess.Popen[bytes], port: int) -> bool:
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def start_xray(
    link: VlessLink,
    local_port: int,
    work_dir: Path,
) -> tuple[subprocess.Popen[bytes] | None, str]:
    attempts = [False]
    if link.security == "reality":
        attempts.append(True)

    last_error = "Xray did not start"

    for legacy_reality_key in attempts:
        config_path = work_dir / (
            "config-legacy.json" if legacy_reality_key else "config.json"
        )
        stderr_path = work_dir / (
            "xray-legacy.stderr" if legacy_reality_key else "xray.stderr"
        )

        config = build_xray_config(link, local_port, legacy_reality_key)
        config_path.write_text(
            json.dumps(config, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )

        with stderr_path.open("wb") as stderr_file:
            proc = subprocess.Popen(
                [str(XRAY_PATH), "run", "-c", str(config_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                cwd=work_dir,
            )

        if wait_for_local_proxy(proc, local_port):
            return proc, ""

        terminate_process(proc)
        try:
            last_error = stderr_path.read_text(
                encoding="utf-8", errors="replace"
            ).strip()[-1000:]
        except OSError:
            last_error = "unable to read Xray error output"

    return None, last_error


def parse_cloudflare_trace(body: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in body.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def test_vless(link: VlessLink) -> TestResult | None:
    local_port = PORTS.acquire()
    proc: subprocess.Popen[bytes] | None = None

    try:
        with tempfile.TemporaryDirectory(prefix="xray-vless-") as temp_dir:
            work_dir = Path(temp_dir)
            proc, _startup_error = start_xray(link, local_port, work_dir)
            if proc is None:
                return None

            proxy_url = f"http://127.0.0.1:{local_port}"
            proxies = {"http": proxy_url, "https": proxy_url}
            successful_delays: list[float] = []
            best_trace: dict[str, str] = {}

            for _ in range(TEST_ATTEMPTS):
                try:
                    with requests.Session() as session:
                        session.trust_env = False
                        started = time.perf_counter()
                        response = session.get(
                            TEST_URL,
                            proxies=proxies,
                            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                            allow_redirects=False,
                            headers={
                                "User-Agent": "mirsub-xray-tester/2.0",
                                "Accept": "text/plain",
                                "Cache-Control": "no-cache",
                                "Connection": "close",
                            },
                        )
                        elapsed_ms = (time.perf_counter() - started) * 1000
                        trace = parse_cloudflare_trace(response.text)

                    if (
                        response.status_code == 200
                        and trace.get("ip")
                        and trace.get("loc")
                        and elapsed_ms <= MAX_DELAY_MS
                    ):
                        successful_delays.append(elapsed_ms)
                        if not best_trace or elapsed_ms <= min(successful_delays):
                            best_trace = trace
                except requests.RequestException:
                    continue

            if not successful_delays:
                return None

            # Median is less sensitive to one noisy GitHub runner measurement.
            delay_ms = round(statistics.median(successful_delays))
            country_code = best_trace.get("loc", "XX").upper()
            outbound_ip = best_trace.get("ip", "")
            label = f"{get_flag(country_code)} {country_code} | {delay_ms}ms | mirsub"
            encoded_label = urllib.parse.quote(label, safe="")
            output_url = f"{link.base_url}#{encoded_label}"

            return TestResult(
                output_url=output_url,
                delay_ms=delay_ms,
                country_code=country_code,
                outbound_ip=outbound_ip,
            )
    finally:
        terminate_process(proc)
        PORTS.release(local_port)


def download_xray() -> None:
    if XRAY_PATH.is_file() and os.access(XRAY_PATH, os.X_OK):
        try:
            subprocess.run(
                [str(XRAY_PATH), "version"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            return
        except (OSError, subprocess.SubprocessError):
            XRAY_PATH.unlink(missing_ok=True)

    log("⬇️ Downloading the latest official Xray-core...")

    with tempfile.TemporaryDirectory(prefix="xray-download-") as temp_dir:
        zip_path = Path(temp_dir) / "xray.zip"
        with requests.get(
            XRAY_DOWNLOAD_URL,
            stream=True,
            timeout=(15, 120),
            headers={"User-Agent": "mirsub-xray-tester/2.0"},
        ) as response:
            response.raise_for_status()
            with zip_path.open("wb") as output:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        output.write(chunk)

        if not zipfile.is_zipfile(zip_path):
            raise RuntimeError("downloaded Xray file is not a valid ZIP archive")

        with zipfile.ZipFile(zip_path) as archive:
            member = next(
                (
                    name
                    for name in archive.namelist()
                    if Path(name).name == "xray" and not name.endswith("/")
                ),
                None,
            )
            if member is None:
                raise RuntimeError("xray executable was not found in the archive")

            temp_binary = Path(temp_dir) / "xray"
            with archive.open(member) as source, temp_binary.open("wb") as target:
                shutil.copyfileobj(source, target)

        temp_binary.chmod(0o755)
        shutil.move(str(temp_binary), XRAY_PATH)
        XRAY_PATH.chmod(0o755)

    subprocess.run(
        [str(XRAY_PATH), "version"],
        check=True,
        timeout=10,
    )


def load_unique_links(input_path: Path) -> tuple[list[VlessLink], int]:
    deduplicated: dict[tuple[Any, ...], str] = {}
    rejected = 0

    with input_path.open("r", encoding="utf-8", errors="ignore") as source:
        for raw_line in source:
            line = raw_line.strip()
            if not line.lower().startswith("vless://"):
                continue
            try:
                key = canonical_connection_key(line)
            except ConfigError:
                rejected += 1
                continue
            deduplicated.setdefault(key, line)

    links: list[VlessLink] = []
    for line in deduplicated.values():
        try:
            links.append(parse_vless(line))
        except ConfigError:
            rejected += 1

    links.sort(key=lambda item: item.base_url)
    return links, rejected


def write_results_atomically(output_path: Path, results: list[TestResult]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.tmp")
    content = "\n".join(result.output_url for result in results) + "\n"
    temporary_path.write_text(content, encoding="utf-8")
    os.replace(temporary_path, output_path)


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "Usage: python3 test_configs_final.py INPUT_FILE OUTPUT_FILE",
            file=sys.stderr,
        )
        return 64

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    if not input_path.is_file():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 66

    download_xray()
    links, parse_rejected = load_unique_links(input_path)

    if not links:
        print("No valid, supported VLESS links were found.", file=sys.stderr)
        return 2

    log(
        f"🚀 Testing {len(links)} unique VLESS configs with "
        f"{MAX_WORKERS} workers and {TEST_ATTEMPTS} HTTPS attempt(s) each..."
    )

    results: list[TestResult] = []
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures: dict[Future[TestResult | None], VlessLink] = {
            executor.submit(test_vless, link): link for link in links
        }

        for future in as_completed(futures):
            completed += 1
            try:
                result = future.result()
            except Exception as exc:  # Keep one broken config from killing the whole run.
                result = None
                log(f"⚠️ Worker error: {type(exc).__name__}: {exc}")

            if result is not None:
                results.append(result)
                if len(results) <= 10 or len(results) % 10 == 0:
                    log(
                        f"✅ {len(results)} working | {completed}/{len(links)} tested | "
                        f"{result.country_code} {result.delay_ms}ms"
                    )
            if completed % 100 == 0 or completed == len(links):
                log(f"… {completed}/{len(links)} tested | {len(results)} working")

    # Stable output: fastest first, then URL. Remove any final duplicates defensively.
    unique_results: dict[str, TestResult] = {}
    for result in sorted(results, key=lambda item: (item.delay_ms, item.output_url)):
        base = result.output_url.split("#", 1)[0]
        unique_results.setdefault(base, result)

    final_results = list(unique_results.values())

    if not final_results:
        print(
            "No working configs were found; the previous output file was left untouched.",
            file=sys.stderr,
        )
        return 2

    write_results_atomically(output_path, final_results)

    log(
        f"🏁 Finished: {len(final_results)} working configs saved; "
        f"{parse_rejected} malformed/unsupported links skipped."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
