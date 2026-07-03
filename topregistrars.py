#!/usr/bin/env python3
"""
topregistrars.py

Fetch the Tranco top-1M list and, for the top N domains, determine:
  * the domain's registrar  (via RDAP, e.g. "MarkMonitor")
  * where the domain's DNS is hosted (via a live NS lookup, e.g. "Amazon Route 53")

Writes the results to a JSON file (default: data.json) that the bundled
dashboard.html renders as an interactive dashboard.

Usage:
  python3 topregistrars.py                 # top 10,000 (default)
  python3 topregistrars.py --limit 1000    # only the top 1,000
  python3 topregistrars.py --limit 50000 --concurrency 32

The list download and every per-domain result are cached on disk, so re-running
(or resuming after an interrupt) is cheap.
"""

import argparse
import concurrent.futures
import csv
import io
import json
import os
import random
import re
import sys
import threading
import time
import zipfile
from datetime import datetime, timezone

import requests

try:
    import dns.resolver
    import dns.exception
    _HAVE_DNSPYTHON = True
except ImportError:  # pragma: no cover
    _HAVE_DNSPYTHON = False


TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_ORG_FALLBACK = "https://rdap.org/domain/"
USER_AGENT = "topregistrars/1.0 (+https://github.com/; research script)"

# TLDs that are missing from IANA's RDAP bootstrap file but nonetheless have a
# working RDAP server that exposes registrar data. Without these, rdap.org 404s
# them and the registrar comes back "Unknown". (Many ccTLDs — .ru .jp .de .cn
# .edu .es .co .eu .it — are WHOIS-only or privacy-redacted and simply cannot be
# resolved to a registrar via RDAP; they are not listed here.)
_IDENTITY_DIGITAL = "https://rdap.identitydigital.services/rdap/"
SUPPLEMENTAL_RDAP = {
    t: _IDENTITY_DIGITAL
    for t in ("io", "me", "sh", "ac", "ag", "bz", "gi", "mn", "pr", "sc",
              "gd", "lc", "vc", "cx", "vg")  # Identity Digital ccTLDs
}

# ---------------------------------------------------------------------------
# DNS provider fingerprints.  Each nameserver hostname is matched (substring,
# case-insensitive) against these patterns, first match wins, so put the more
# specific patterns first.
# ---------------------------------------------------------------------------
DNS_PROVIDERS = [
    ("awsdns", "Amazon Route 53"),
    ("ns-cloud-", "Google Cloud DNS"),
    ("googledomains.com", "Google Domains"),
    ("google.com", "Google Cloud DNS"),
    ("cloudflare", "Cloudflare"),
    ("domaincontrol.com", "GoDaddy"),
    ("azure-dns", "Azure DNS"),
    ("nsone.net", "NS1 (IBM)"),
    ("ultradns", "UltraDNS (Vercara)"),
    ("dynect.net", "Dyn (Oracle)"),
    ("akam.net", "Akamai"),
    ("akamaiedge", "Akamai"),
    ("akamai", "Akamai"),
    ("dnsmadeeasy", "DNS Made Easy"),
    ("dnsimple", "DNSimple"),
    ("registrar-servers.com", "Namecheap"),
    ("name-services.com", "eNom"),
    ("worldnic.com", "Network Solutions"),
    ("he.net", "Hurricane Electric"),
    ("wixdns.net", "Wix"),
    ("squarespacedns.com", "Squarespace"),
    ("shopifydns", "Shopify"),
    ("shopify", "Shopify"),
    ("wordpress.com", "Automattic (WordPress.com)"),
    ("wpengine", "WP Engine"),
    ("vercel-dns", "Vercel"),
    ("netlify", "Netlify"),
    ("fastly", "Fastly"),
    ("bunny.net", "Bunny CDN"),
    ("incapdns", "Imperva Incapsula"),
    ("cscdns.net", "CSC"),
    ("markmonitor", "MarkMonitor DNS"),
    ("nstld.com", "Verisign"),
    ("verisigndns", "Verisign Managed DNS"),
    ("gandi.net", "Gandi"),
    ("ovh.net", "OVH"),
    ("ovh.ca", "OVH"),
    ("1and1", "IONOS (1&1)"),
    ("ui-dns", "IONOS"),
    ("ionos", "IONOS"),
    ("hetzner", "Hetzner"),
    ("digitalocean.com", "DigitalOcean"),
    ("linode.com", "Linode (Akamai)"),
    ("dreamhost.com", "DreamHost"),
    ("bluehost.com", "Bluehost"),
    ("hostgator", "HostGator"),
    ("rackspace", "Rackspace"),
    ("transip", "TransIP"),
    ("cloudns.net", "ClouDNS"),
    ("constellix", "Constellix"),
    ("nextdns", "NextDNS"),
    ("alidns.com", "Alibaba Cloud DNS"),
    ("alibabadns", "Alibaba Cloud DNS"),
    ("aliyun", "Alibaba Cloud DNS"),
    ("hichina.com", "Alibaba Cloud (HiChina)"),
    ("oraclecloud", "Oracle Cloud (Dyn)"),
    ("amzndns", "Amazon DNS"),
    ("dnsv", "DNSPod (Tencent)"),
    ("dnspod", "DNSPod (Tencent)"),
    ("qcloud", "Tencent Cloud"),
    ("myqcloud", "Tencent Cloud"),
    ("yandex", "Yandex"),
    ("sakura.ne.jp", "Sakura Internet"),
    ("value-domain.com", "Value Domain (GMO)"),
    ("onamae.com", "Onamae (GMO)"),
    ("gmoserver", "GMO"),
    ("gmo-dns", "GMO"),
    ("github.io", "GitHub Pages"),
    ("herokudns", "Heroku"),
    ("nsall", "Namecheap"),
    ("registrar.eu", "OpenProvider"),
    ("openprovider", "OpenProvider"),
    ("stackpath", "StackPath"),
    ("cdn77", "CDN77"),
]

# A small set of multi-label public suffixes so the "unknown provider" fallback
# (which uses the registrable domain of the nameserver) doesn't mistake e.g.
# "co.uk" for the registrable domain.
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "ne.jp", "or.jp", "com.au",
    "net.au", "org.au", "co.nz", "com.br", "com.cn", "net.cn", "com.tr",
    "co.za", "co.in", "co.kr", "com.mx", "com.ar", "com.tw", "co.il",
}

# Registrar display-name normalisation.  RDAP names are messy; collapse the big
# players to a stable label.  Substring match, case-insensitive, first wins.
REGISTRAR_ALIASES = [
    ("markmonitor", "MarkMonitor"),
    ("csc corporate domains", "CSC Corporate Domains"),
    ("corporation service company", "CSC Corporate Domains"),
    ("godaddy", "GoDaddy"),
    ("wild west domains", "GoDaddy (Wild West Domains)"),
    ("namecheap", "Namecheap"),
    ("namesilo", "NameSilo"),
    ("tucows", "Tucows"),
    ("enom", "eNom (Tucows)"),
    ("cloudflare", "Cloudflare"),
    ("gandi", "Gandi"),
    ("google llc", "Google"),
    ("squarespace domains", "Squarespace"),
    ("amazon registrar", "Amazon Registrar"),
    ("network solutions", "Network Solutions"),
    ("web.com", "Web.com"),
    ("register.com", "Register.com"),
    ("1&1", "IONOS"),
    ("1and1", "IONOS"),
    ("ionos", "IONOS"),
    ("ovh", "OVH"),
    ("gname", "Gname"),             # Gname.com Pte. Ltd. — 'name.com' would misclaim it
    ("trustname", "Trustname"),     # Trustname.com — 'name.com' would misclaim it
    ("name.com", "Name.com"),
    ("dynadot", "Dynadot"),
    ("porkbun", "Porkbun"),
    ("hostinger", "Hostinger"),
    ("wordpress", "Automattic (WordPress.com)"),
    ("automattic", "Automattic"),
    ("alibaba", "Alibaba Cloud"),
    ("hichina", "Alibaba Cloud (HiChina)"),
    ("west263", "West.cn"),
    ("xin net", "Xin Net"),
    ("chengdu west", "West.cn"),
    ("dnspod", "DNSPod (Tencent)"),
    ("tencent", "Tencent Cloud"),
    ("gmo internet", "GMO Internet"),
    ("onamae", "GMO Internet (Onamae)"),
    ("key-systems", "Key-Systems"),
    ("realtime register", "Realtime Register"),
    ("openprovider", "OpenProvider"),
    ("public interest registry", "PIR"),
    ("nom-iq", "Com Laude"),
    ("com laude", "Com Laude"),
    ("wixpress", "Wix"),
    ("wix.com", "Wix"),
    ("register.it", "Register.it"),
    ("safenames", "SafeNames"),     # 'ename' substring wrongly matched "SafeNames Ltd."
    ("ename", "Ename"),
    ("bizcn", "Bizcn"),
    ("epik", "Epik"),
    ("dreamhost", "DreamHost"),
    ("hostgator", "HostGator"),
    ("bluehost", "Bluehost"),
    ("newfold", "Newfold Digital"),
    ("fastdomain", "Newfold Digital"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_thread_local = threading.local()


def session() -> requests.Session:
    """One requests.Session per worker thread."""
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"})
        _thread_local.session = s
    return s


def resolver() -> "dns.resolver.Resolver":
    r = getattr(_thread_local, "resolver", None)
    if r is None:
        r = dns.resolver.Resolver(configure=True)
        r.lifetime = 8.0
        r.timeout = 4.0
        _thread_local.resolver = r
    return r


def tld_of(domain: str) -> str:
    return domain.rsplit(".", 1)[-1].lower() if "." in domain else domain.lower()


def registrable_of_ns(host: str) -> str:
    """Best-effort registrable domain of a nameserver hostname."""
    host = host.strip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def dns_provider_for(nameservers) -> str:
    """Map a set of nameserver hostnames to a provider label."""
    if not nameservers:
        return "Unknown"
    votes = {}
    for ns in nameservers:
        host = ns.strip(".").lower()
        label = None
        for pat, name in DNS_PROVIDERS:
            if pat in host:
                label = name
                break
        if label is None:
            # Unknown provider: group by the nameserver's registrable domain,
            # which is usually the hosting company / self-hosted zone.
            label = registrable_of_ns(host)
        votes[label] = votes.get(label, 0) + 1
    # Most common label across the nameserver set.
    return max(votes.items(), key=lambda kv: (kv[1], kv[0]))[0]


def normalize_registrar(name: str) -> str:
    if not name:
        return "Unknown"
    low = name.lower()
    for pat, canon in REGISTRAR_ALIASES:
        if pat in low:
            return canon
    # Trim common corporate suffixes / boilerplate (Anglo + common EU forms, so
    # "Nameshield SAS" and "NAMESHIELD" collapse to one registrar).
    cleaned = re.sub(
        r"[,\.]?\s*(inc\.?|llc\.?|ltd\.?|limited|gmbh|corp\.?|co\.,? ?ltd\.?|co\.?|"
        r"s\.?a\.?s\.?u?|sarl|s\.?r\.?l\.?|s\.?p\.?a\.?|s\.a\.?|b\.v\.?|pty|plc)\b.*$",
        "",
        name.strip(),
        flags=re.IGNORECASE,
    ).strip(" ,.-")
    return cleaned or name.strip()


def merge_case_variants(records):
    """Collapse registrar labels that differ only by letter case into one display
    form. Registries hand back the same registrar in different casing (e.g.
    "EURODNS" vs "EuroDNS", "NAMESHIELD" vs "Nameshield SAS"), which would
    otherwise split one registrar across two buckets. Prefer a mixed-case form,
    then the most common, then the shortest."""
    from collections import Counter, defaultdict
    groups = defaultdict(Counter)
    for r in records:
        groups[r["registrar"].lower()][r["registrar"]] += 1
    canon = {}
    for key, forms in groups.items():
        if len(forms) > 1:
            canon[key] = max(forms.items(),
                             key=lambda it: (not it[0].isupper() and not it[0].islower(),
                                             it[1], -len(it[0])))[0]
    for r in records:
        c = canon.get(r["registrar"].lower())
        if c:
            r["registrar"] = c


# ---------------------------------------------------------------------------
# Tranco list
# ---------------------------------------------------------------------------
def fetch_tranco(limit: int, cache_path: str, list_url: str) -> list:
    """Return [(rank, domain), ...] for the top `limit`, caching the CSV."""
    csv_bytes = None
    if os.path.exists(cache_path):
        with open(cache_path, "rb") as fh:
            csv_bytes = fh.read()
        print(f"[list] using cached list: {cache_path}", file=sys.stderr)
    else:
        print(f"[list] downloading {list_url} ...", file=sys.stderr)
        resp = requests.get(list_url, headers={"User-Agent": USER_AGENT}, timeout=120)
        resp.raise_for_status()
        if list_url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                name = zf.namelist()[0]
                csv_bytes = zf.read(name)
        else:
            csv_bytes = resp.content
        with open(cache_path, "wb") as fh:
            fh.write(csv_bytes)
        print(f"[list] cached to {cache_path}", file=sys.stderr)

    rows = []
    reader = csv.reader(io.StringIO(csv_bytes.decode("utf-8", "replace")))
    for row in reader:
        if len(row) < 2:
            continue
        try:
            rank = int(row[0])
        except ValueError:
            continue
        rows.append((rank, row[1].strip().lower()))
        if len(rows) >= limit:
            break
    return rows


# ---------------------------------------------------------------------------
# RDAP
# ---------------------------------------------------------------------------
def load_rdap_bootstrap(cache_path: str) -> dict:
    """Map TLD -> RDAP base URL using IANA's bootstrap file (cached)."""
    data = None
    if os.path.exists(cache_path):
        try:
            with open(cache_path) as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            data = None
    if data is None:
        try:
            resp = requests.get(RDAP_BOOTSTRAP_URL, headers={"User-Agent": USER_AGENT}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            with open(cache_path, "w") as fh:
                json.dump(data, fh)
        except requests.RequestException as exc:
            print(f"[rdap] WARNING: could not fetch bootstrap ({exc}); using rdap.org only", file=sys.stderr)
            return {}

    tld_map = {}
    for service in data.get("services", []):
        tlds, urls = service[0], service[1]
        base = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
        if not base:
            continue
        for tld in tlds:
            tld_map[tld.lower()] = base.rstrip("/") + "/"
    # Fill gaps with known-good endpoints the bootstrap omits (bootstrap wins).
    for tld, base in SUPPLEMENTAL_RDAP.items():
        tld_map.setdefault(tld, base)
    return tld_map


def _vcard_field(vcard_array, field):
    try:
        for item in vcard_array[1]:
            if item[0] == field:
                return item[3]
    except (IndexError, TypeError):
        pass
    return None


def _extract_registrar(rdap_json):
    """Return (registrar_name, iana_id) from an RDAP domain response."""
    def scan(entities):
        for ent in entities or []:
            roles = ent.get("roles", []) or []
            if "registrar" in roles:
                name = _vcard_field(ent.get("vcardArray"), "fn")
                iana_id = None
                for pid in ent.get("publicIds", []) or []:
                    if "iana" in (pid.get("type", "").lower()):
                        iana_id = pid.get("identifier")
                return name, iana_id
            # occasionally the registrar is nested one level deep
            nested = scan(ent.get("entities"))
            if nested:
                return nested
        return None

    got = scan(rdap_json.get("entities"))
    if got:
        return got
    return None, None


def rdap_lookup(domain: str, tld_map: dict, timeout: float, max_retries: int = 3):
    """Return dict with registrar info (best effort)."""
    tld = tld_of(domain)
    bases = []
    if tld in tld_map:
        bases.append(tld_map[tld] + "domain/" + domain)
    bases.append(RDAP_ORG_FALLBACK + domain)  # fallback / redirector

    last_err = "no rdap endpoint"
    for base_url in bases:
        for attempt in range(max_retries):
            try:
                resp = session().get(base_url, timeout=timeout, allow_redirects=True)
                if resp.status_code == 200:
                    name, iana_id = _extract_registrar(resp.json())
                    return {
                        "registrar_raw": name,
                        "registrar": normalize_registrar(name) if name else "Unknown",
                        "iana_id": iana_id,
                    }
                if resp.status_code in (429, 500, 502, 503):
                    time.sleep((2 ** attempt) + random.uniform(0, 0.75))
                    continue
                if resp.status_code == 404:
                    last_err = "not found (404)"
                    break  # try next base
                last_err = f"http {resp.status_code}"
                break
            except (requests.RequestException, ValueError) as exc:
                last_err = str(exc)[:120]
                time.sleep((2 ** attempt) * 0.5 + random.uniform(0, 0.5))
    return {"registrar_raw": None, "registrar": "Unknown", "iana_id": None, "error": last_err}


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
def dns_lookup(domain: str):
    """Return (nameservers, provider_label)."""
    if not _HAVE_DNSPYTHON:
        return [], "Unknown (no dnspython)"
    try:
        answer = resolver().resolve(domain, "NS")
        nameservers = sorted({r.target.to_text().strip(".").lower() for r in answer})
        return nameservers, dns_provider_for(nameservers)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return [], "None / No NS"
    except (dns.exception.DNSException, Exception):  # noqa: BLE001 - keep worker alive
        return [], "Unknown (lookup failed)"


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def process_domain(rank, domain, tld_map, timeout):
    reg = rdap_lookup(domain, tld_map, timeout)
    nameservers, dns_host = dns_lookup(domain)
    rec = {
        "rank": rank,
        "domain": domain,
        "tld": tld_of(domain),
        "registrar": reg["registrar"],
        "registrar_raw": reg.get("registrar_raw"),
        "iana_id": reg.get("iana_id"),
        "dns_host": dns_host,
        "nameservers": nameservers,
    }
    if reg.get("error"):
        rec["error"] = reg["error"]
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit", type=int, default=10000,
                    help="How far down the Tranco list to check (default: 10000).")
    ap.add_argument("--concurrency", type=int, default=24,
                    help="Number of concurrent workers (default: 24).")
    ap.add_argument("--timeout", type=float, default=15.0, help="Per-RDAP-request timeout in seconds.")
    ap.add_argument("--output", default="data.json", help="Output JSON path (default: data.json).")
    ap.add_argument("--cache-dir", default=".cache", help="Directory for caches (default: .cache).")
    ap.add_argument("--list-url", default=TRANCO_URL, help="Tranco list URL.")
    ap.add_argument("--no-resume", action="store_true", help="Ignore any cached per-domain results.")
    ap.add_argument("--flush-every", type=int, default=200, help="Persist cache every N completed domains.")
    args = ap.parse_args()

    if not _HAVE_DNSPYTHON:
        print("WARNING: dnspython not installed — DNS hosting will be 'Unknown'. "
              "Install with: pip install dnspython", file=sys.stderr)

    os.makedirs(args.cache_dir, exist_ok=True)
    list_cache = os.path.join(args.cache_dir, "tranco-top1m.csv")
    bootstrap_cache = os.path.join(args.cache_dir, "rdap-bootstrap.json")
    results_cache = os.path.join(args.cache_dir, "results.json")

    rows = fetch_tranco(args.limit, list_cache, args.list_url)
    print(f"[list] {len(rows)} domains to process (limit={args.limit})", file=sys.stderr)

    tld_map = load_rdap_bootstrap(bootstrap_cache)
    print(f"[rdap] bootstrap covers {len(tld_map)} TLDs", file=sys.stderr)

    # Resume: load prior results keyed by domain.
    cache = {}
    if not args.no_resume and os.path.exists(results_cache):
        try:
            with open(results_cache) as fh:
                for rec in json.load(fh).get("domains", []):
                    cache[rec["domain"]] = rec
            print(f"[cache] resuming with {len(cache)} cached results", file=sys.stderr)
        except (json.JSONDecodeError, OSError, KeyError):
            cache = {}

    todo = [(rank, dom) for rank, dom in rows if dom not in cache]
    results = {dom: cache[dom] for _, dom in rows if dom in cache}

    lock = threading.Lock()
    done = len(results)
    total = len(rows)
    start = time.time()

    def flush():
        ordered = [results[dom] for _, dom in rows if dom in results]
        tmp = results_cache + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"domains": ordered}, fh)
        os.replace(tmp, results_cache)

    if todo:
        print(f"[run] processing {len(todo)} domains with {args.concurrency} workers...", file=sys.stderr)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = {pool.submit(process_domain, rank, dom, tld_map, args.timeout): dom
                       for rank, dom in todo}
            try:
                for fut in concurrent.futures.as_completed(futures):
                    dom = futures[fut]
                    try:
                        rec = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        rec = {"rank": None, "domain": dom, "tld": tld_of(dom),
                               "registrar": "Unknown", "dns_host": "Unknown",
                               "nameservers": [], "error": str(exc)[:120]}
                    with lock:
                        results[dom] = rec
                        done += 1
                        if done % 25 == 0 or done == total:
                            rate = done / max(time.time() - start, 1e-6)
                            eta = (total - done) / max(rate, 1e-6)
                            print(f"\r[run] {done}/{total}  ({rate:4.1f}/s, ETA {eta/60:5.1f}m)",
                                  end="", file=sys.stderr, flush=True)
                        if done % args.flush_every == 0:
                            flush()
            except KeyboardInterrupt:
                print("\n[run] interrupted — flushing partial results...", file=sys.stderr)
                with lock:
                    flush()
                raise
        print("", file=sys.stderr)

    flush()

    ordered = [results[dom] for _, dom in rows if dom in results]
    merge_case_variants(ordered)
    out = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "list_url": args.list_url,
        "limit": args.limit,
        "count": len(ordered),
        "domains": ordered,
    }
    with open(args.output, "w") as fh:
        json.dump(out, fh, indent=None, separators=(",", ":"))
    print(f"[done] wrote {len(ordered)} records to {args.output}", file=sys.stderr)

    # Quick console summary.
    from collections import Counter
    reg_counts = Counter(r["registrar"] for r in ordered)
    dns_counts = Counter(r["dns_host"] for r in ordered)
    print("\nTop 10 registrars:", file=sys.stderr)
    for name, n in reg_counts.most_common(10):
        print(f"  {n:6d}  {name}", file=sys.stderr)
    print("\nTop 10 DNS hosts:", file=sys.stderr)
    for name, n in dns_counts.most_common(10):
        print(f"  {n:6d}  {name}", file=sys.stderr)


if __name__ == "__main__":
    main()
