# ioc_feed.py — populates Redis threat_intel:iocs from local + remote IOC sources.
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import redis

REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
IOC_SET = "threat_intel:iocs"
MANUAL_SET = "threat_intel:manual"
LAST_UPDATED_KEY = "threat_intel:last_updated"

REFRESH_HOURS = float(os.getenv('IOC_REFRESH_HOURS', '1'))
IOC_FEEDS = [f.strip() for f in os.getenv('IOC_FEEDS', 'local,urlhaus,feodo,threatfox').split(',') if f.strip()]
THREATFOX_API_KEY = os.getenv('THREATFOX_API_KEY', '')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BASELINE_FILE = os.path.join(BASE_DIR, 'iocs', 'baseline.txt')

TIMEOUT = 15
RETRIES = 3


def fetch_text(url):
    last_err = None
    for attempt in range(RETRIES):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'xdr-brain-ioc-feed/1.0'})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.read().decode('utf-8', errors='replace')
        except (urllib.error.URLError, OSError) as e:
            last_err = e
            time.sleep(2 ** attempt)
    print(f"  [WARN] fetch failed for {url}: {last_err}")
    return None


def ip_is_private(ip):
    try:
        a, b = (int(p) for p in ip.split('.')[:2])
    except ValueError:
        return False
    if a == 10 or a == 127:
        return True
    if a == 169 and b == 254:
        return True
    if a == 192 and b == 168:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 0 or a == 255:
        return True
    return False


def normalize(raw):
    ioc = str(raw).strip()
    if not ioc or ioc.startswith('#'):
        return None
    ioc = ioc.lower()
    ioc = re.sub(r'\s+', ' ', ioc)
    if len(ioc) < 3 or len(ioc) > 128:
        return None
    m = re.match(r'https?://([^/]+)', ioc)
    if m:
        ioc = m.group(1)
    ioc = ioc.split('/')[0].rstrip('.')
    if ioc in ('http', 'https', 'localhost', 'example.com'):
        return None
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ioc) and ip_is_private(ioc):
        return None
    return ioc


def provider_local():
    iocs = set()
    try:
        with open(BASELINE_FILE, encoding='utf-8') as f:
            for line in f:
                ioc = normalize(line)
                if ioc:
                    iocs.add(ioc)
    except OSError as e:
        print(f"  [WARN] baseline file unreadable: {e}")
    return iocs


def provider_urlhaus():
    body = fetch_text('https://urlhaus.abuse.ch/downloads/text/')
    if body is None:
        return set()
    return {ioc for line in body.splitlines() if (ioc := normalize(line))}


def provider_feodo():
    body = fetch_text('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt')
    if body is None:
        return set()
    return {ioc for line in body.splitlines() if (ioc := normalize(line))}


def provider_threatfox():
    if not THREATFOX_API_KEY:
        print("  [WARN] no THREATFOX_API_KEY set; skipping threatfox feed (needs a key now).")
        return set()
    payload = {'query': 'get_iocs', 'days': 7}
    if THREATFOX_API_KEY:
        payload['api_key'] = THREATFOX_API_KEY
    req = urllib.request.Request(
        'https://threatfox-api.abuse.ch/api/v1/',
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json', 'User-Agent': 'xdr-brain-ioc-feed/1.0'},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode('utf-8', errors='replace'))
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"  [WARN] threatfox fetch failed: {e}")
        return set()
    if data.get('query_status') != 'ok':
        print(f"  [WARN] threatfox query_status: {data.get('query_status')}")
        return set()
    iocs = set()
    for item in data.get('data', []):
        if not isinstance(item, dict):
            continue
        if item.get('ioc_type') not in ('ip', 'domain', 'url'):
            continue
        ioc = normalize(item.get('ioc', ''))
        if ioc:
            iocs.add(ioc)
    return iocs


PROVIDERS = {
    'local': provider_local,
    'urlhaus': provider_urlhaus,
    'feodo': provider_feodo,
    'threatfox': provider_threatfox,
}


def collect():
    iocs = set()
    for name in IOC_FEEDS:
        fn = PROVIDERS.get(name)
        if fn is None:
            print(f"  [WARN] unknown feed '{name}' (check IOC_FEEDS)")
            continue
        print(f"  [feed] {name} ...", flush=True)
        try:
            got = fn()
        except Exception as e:
            print(f"  [WARN] {name} errored: {e}")
            continue
        print(f"  [feed] {name}: {len(got)} IOCs", flush=True)
        iocs |= got
    return iocs


def write_iocs(iocs):
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
    r.ping()
    manual = set()
    try:
        manual = r.smembers(MANUAL_SET)
    except redis.RedisError:
        manual = set()
    pipe = r.pipeline()
    pipe.delete(IOC_SET)
    if iocs:
        pipe.sadd(IOC_SET, *iocs)
    if manual:
        pipe.sadd(IOC_SET, *manual)
    pipe.set(LAST_UPDATED_KEY, datetime.now(timezone.utc).isoformat(timespec='seconds'))
    pipe.execute()
    return len(iocs), len(manual)


def run_once():
    print(f"[ioc_feed] feeds: {', '.join(IOC_FEEDS)}", flush=True)
    iocs = collect()
    try:
        fed, manual = write_iocs(iocs)
    except redis.RedisError as e:
        print(f"  [ERROR] Redis unreachable ({e}); IOCs not written.")
        sys.exit(1)
    print(f"[ioc_feed] OK: {fed + manual} IOCs in {IOC_SET} (feed={fed}, manual={manual})", flush=True)


def run_loop():
    interval_s = max(60, int(REFRESH_HOURS * 3600))
    print(f"[ioc_feed] scheduler: refresh every {interval_s}s", flush=True)
    while True:
        run_once()
        time.sleep(interval_s)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Dataset-driven IOC feed for the XDR brain.')
    ap.add_argument('--once', action='store_true', help='Run a single refresh and exit')
    ap.add_argument('--refresh', action='store_true', help='Run the periodic refresh loop (default)')
    args = ap.parse_args()
    if args.once:
        run_once()
    else:
        run_loop()