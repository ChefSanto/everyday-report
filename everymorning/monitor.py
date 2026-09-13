#!/usr/bin/env python3
"""Daily site health monitor — GitHub Actions + Telegram.

v1: per-page HTTP status, keyword, latency; SSL expiry; Telegram report.
v2: broken internal-link detection + content-change tracking (state file).

Checks, per page: HTTP status, expected keyword, response time.
Per site: SSL expiry, broken internal links. Content hashes are recorded
per page (optional, per-page `track: true`) and changes are flagged.
Retries once before declaring failure. sites.yml drives everything.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlparse

import requests
import yaml

TIMEOUT = 15            # seconds per request
SLOW_MS = 3000          # flag pages slower than this
RETRY_WAIT = 10         # seconds between attempts
SSL_WARN_DAYS = 14      # warn when cert expires within this many days
LINK_TIMEOUT = 10       # seconds per broken-link probe
MAX_LINKS = 25          # max internal links probed per page (runtime guard)

HEADERS = {"User-Agent": "SiteHealthBot/2.0 (+github-actions)"}


# ─────────────────────────────── config ───────────────────────────────

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_state(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_state(path, state):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)


# ─────────────────────────────── checks ───────────────────────────────

def check_page(url, keyword=None, keep_html=False):
    """Fetch a page (up to 2 attempts). Returns result dict."""
    last = {}
    for attempt in range(2):
        try:
            start = time.monotonic()
            r = requests.get(url, timeout=TIMEOUT, headers=HEADERS, allow_redirects=True)
            latency_ms = int((time.monotonic() - start) * 1000)
            ok = r.status_code == 200
            problem = None if ok else f"HTTP {r.status_code}"
            if ok and keyword and keyword not in r.text:
                ok = False
                problem = f"keyword '{keyword}' not found"
            last = {"url": url, "ok": ok, "status": r.status_code,
                    "latency_ms": latency_ms, "slow": latency_ms > SLOW_MS,
                    "problem": problem}
            if keep_html:
                last["html"] = r.text
        except requests.RequestException as e:
            last = {"url": url, "ok": False, "status": None, "latency_ms": None,
                    "slow": False, "problem": f"{type(e).__name__}: {e}"}
        if last["ok"] and not last["slow"]:
            return last
        if attempt == 0:
            time.sleep(RETRY_WAIT)
    return last


def ssl_days_remaining(hostname, port=443):
    """Days until the site's TLS certificate expires, or None."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                exp = ssock.getpeercert()["notAfter"]
        expiry = datetime.datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
        return (expiry - datetime.datetime.utcnow()).days
    except Exception:
        return None


# ─────────────────────────── broken links ─────────────────────────────

class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.links.append(v)


def extract_internal_links(page_url, html):
    """Unique absolute http(s) links on the same host as page_url."""
    parser = _LinkParser()
    parser.feed(html)
    host = urlparse(page_url).hostname
    seen, out = set(), []
    for href in parser.links:
        href = href.strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        full = urldefrag(urljoin(page_url, href))[0]
        p = urlparse(full)
        if p.scheme in ("http", "https") and p.hostname == host and full not in seen:
            seen.add(full)
            out.append(full)
    return out


def probe_link(url):
    """HTTP status for a URL (HEAD, falling back to GET). None on error."""
    try:
        r = requests.head(url, timeout=LINK_TIMEOUT, headers=HEADERS, allow_redirects=True)
        if r.status_code in (405, 501):  # HEAD not allowed
            r = requests.get(url, timeout=LINK_TIMEOUT, headers=HEADERS, stream=True)
            r.close()
        return r.status_code
    except requests.RequestException:
        return None


def find_broken_links(page_url, html):
    """Probe internal links found in html; return [(url, status_or_None)]."""
    broken = []
    for link in extract_internal_links(page_url, html)[:MAX_LINKS]:
        status = probe_link(link)
        if status is None or status >= 400:
            broken.append((link, status))
    return broken


# ───────────────────────── content tracking ───────────────────────────

def content_hash(html, strip_patterns):
    normalized = html
    for pat in strip_patterns or []:
        normalized = re.sub(pat, "", normalized)
    return hashlib.sha256(normalized.encode("utf-8", "ignore")).hexdigest()


def track_change(url, html, strip_patterns, state):
    """Compare content hash against state; update state. Returns info string or None."""
    today = datetime.date.today().isoformat()
    digest = content_hash(html, strip_patterns)
    prev = state.get(url)
    state[url] = {"sha256": digest, "date": today}
    if prev is None:
        return f"baseline recorded ({today})"
    if prev.get("sha256") != digest:
        return f"CHANGED since {prev.get('date', 'unknown')}"
    return None


# ─────────────────────────────── site ─────────────────────────────────

def check_site(site, state):
    base_url = site["url"].rstrip("/")
    name = site.get("name") or urlparse(base_url).hostname
    pages = site.get("pages") or [{"path": "/", "keyword": None}]
    check_links = bool(site.get("check_links"))

    results, notes = [], []
    for p in pages:
        path = p.get("path", "/")
        url = path if path.startswith("http") else base_url + (path if path.startswith("/") else "/" + path)
        want_html = check_links or p.get("track")
        r = check_page(url, p.get("keyword"), keep_html=want_html)

        if r["ok"] and p.get("track") and r.get("html"):
            info = track_change(url, r["html"], p.get("strip"), state)
            if info:
                notes.append((url, info))

        if r["ok"] and check_links and r.get("html"):
            broken = find_broken_links(url, r["html"])
            for link, status in broken:
                notes.append((url, f"broken link: {link} ({status or 'timeout'})"))

        r.pop("html", None)  # keep result dicts light
        results.append(r)

    ssl_days = ssl_days_remaining(urlparse(base_url).hostname)
    ok_pages = sum(1 for r in results if r["ok"])
    healthy = ok_pages == len(results) and (ssl_days is None or ssl_days > SSL_WARN_DAYS)
    return {"name": name, "base_url": base_url, "pages": results,
            "ssl_days": ssl_days, "healthy": healthy, "notes": notes}


# ─────────────────────────────── report ───────────────────────────────

def short(url):
    return url.replace("https://", "").replace("http://", "")


def fmt_page_line(r):
    if not r["ok"]:
        icon, detail = "❌", r["problem"]
    elif r["slow"]:
        icon, detail = "⚠️", f"slow ({r['latency_ms']/1000:.1f}s)"
    else:
        icon, detail = "✅", f"{r['latency_ms']}ms"
    return f"{icon} {short(r['url'])} — {detail}"


def build_report(sites, when):
    lines = [f"🌐 *Site Health Report* — {when:%a %d %b %Y, %H:%M}", ""]
    total_ok = total_pages = 0
    for s in sites:
        ok = sum(1 for r in s["pages"] if r["ok"])
        total_ok += ok
        total_pages += len(s["pages"])
        icon = "✅" if s["healthy"] else "❌"
        lines.append(f"{icon} *{s['name']}* — {ok}/{len(s['pages'])} pages OK")
        if s["ssl_days"] is not None:
            warn = " ⚠️" if s["ssl_days"] <= SSL_WARN_DAYS else ""
            lines.append(f"   🔒 SSL expires in {s['ssl_days']}d{warn}")
        for r in s["pages"]:
            if not r["ok"] or r["slow"]:
                lines.append(f"   {fmt_page_line(r)}")
        for url, note in s["notes"]:
            lines.append(f"   📝 {short(url)}: {note}")
    lines.append("")
    lines.append("All systems healthy ✅" if total_ok == total_pages
                 else f"{total_ok}/{total_pages} pages healthy — attention needed ❗")
    return "\n".join(lines), total_ok == total_pages


# ───────────────────────────── Telegram ───────────────────────────────

def send_telegram(token, chat_id, text):
    r = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown",
              "disable_web_page_preview": True},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()["ok"]


# ─────────────────────────────── main ─────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="sites.yml")
    ap.add_argument("--state", default="monitor-state.json")
    args = ap.parse_args()

    config = load_config(args.config)
    state = load_state(args.state)
    when = datetime.datetime.now()

    sites = [check_site(s, state) for s in config["sites"]]
    save_state(args.state, state)

    report, all_ok = build_report(sites, when)
    print(report)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write("## 🌐 Site Health Report\n\n```\n" + report + "\n```\n")

    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    default_chat = os.environ.get("TELEGRAM_CHAT_ID")
    if token:
        for site_cfg, result in zip(config["sites"], sites):
            override = site_cfg.get("notify")
            if override and not result["healthy"]:
                send_telegram(token, override,
                              f"❗ *{result['name']}* has a problem:\n" +
                              "\n".join("  " + fmt_page_line(r) for r in result["pages"]))
        if default_chat:
            try:
                send_telegram(token, default_chat, report)
            except requests.RequestException as e:
                print(f"Telegram delivery failed: {e}", file=sys.stderr)

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
