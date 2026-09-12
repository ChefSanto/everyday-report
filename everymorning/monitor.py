#!/usr/bin/env python3
"""Daily site health monitor — runs via GitHub Actions, reports to Telegram + job summary.

Checks, per page: HTTP status, expected keyword, response time.
Per site: SSL certificate expiry.
Retries once before declaring failure. One config file (sites.yml) drives everything.
"""
import argparse
import datetime
import os
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

import requests
import yaml

TIMEOUT = 15            # seconds per request
SLOW_MS = 3000          # flag pages slower than this
RETRY_WAIT = 10         # seconds between attempts
SSL_WARN_DAYS = 14      # warn when cert expires within this many days

HEADERS = {"User-Agent": "SiteHealthBot/1.0 (+github-actions)"}


def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def check_page(url, keyword=None):
    """Fetch a page once per attempt (up to 2 attempts). Returns result dict."""
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
            slow = latency_ms > SLOW_MS
            last = {"url": url, "ok": ok, "status": r.status_code,
                    "latency_ms": latency_ms, "slow": slow, "problem": problem}
        except requests.RequestException as e:
            last = {"url": url, "ok": False, "status": None, "latency_ms": None,
                    "slow": False, "problem": f"{type(e).__name__}: {e}"}
        if last["ok"] and not last["slow"]:
            return last
        if attempt == 0:
            time.sleep(RETRY_WAIT)
    return last


def ssl_days_remaining(hostname, port=443):
    """Days until the site's TLS certificate expires, or None if it can't be checked."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                exp = ssock.getpeercert()["notAfter"]  # e.g. 'Mar 15 08:00:00 2027 GMT'
        expiry = datetime.datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
        return (expiry - datetime.datetime.utcnow()).days
    except Exception:
        return None


def check_site(site):
    base_url = site["url"].rstrip("/")
    name = site.get("name") or urlparse(base_url).hostname
    pages = site.get("pages") or [{"path": "/", "keyword": None}]

    results = []
    for p in pages:
        path = p.get("path", "/")
        url = path if path.startswith("http") else base_url + (path if path.startswith("/") else "/" + path)
        results.append(check_page(url, p.get("keyword")))

    hostname = urlparse(base_url).hostname
    ssl_days = ssl_days_remaining(hostname)

    ok_pages = sum(1 for r in results if r["ok"])
    healthy = ok_pages == len(results) and (ssl_days is None or ssl_days > SSL_WARN_DAYS)
    return {"name": name, "base_url": base_url, "pages": results,
            "ssl_days": ssl_days, "healthy": healthy}


def fmt_page_line(r):
    if not r["ok"]:
        icon = "❌"
        detail = r["problem"]
    elif r["slow"]:
        icon = "⚠️"
        detail = f"slow ({r['latency_ms']/1000:.1f}s)"
    else:
        icon = "✅"
        detail = f"{r['latency_ms']}ms"
    short = r["url"].replace("https://", "").replace("http://", "")
    return f"{icon} {short} — {detail}"


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
    lines.append("")
    status = "All systems healthy ✅" if total_ok == total_pages else f"{total_ok}/{total_pages} pages healthy — attention needed ❗"
    lines.append(status)
    return "\n".join(lines), total_ok == total_pages


def send_telegram(token, chat_id, text):
    r = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown",
              "disable_web_page_preview": True},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return r.json()["ok"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="sites.yml")
    args = ap.parse_args()

    config = load_config(args.config)
    when = datetime.datetime.now()
    sites = [check_site(s) for s in config["sites"]]
    report, all_ok = build_report(sites, when)
    print(report)

    # Always write to the GitHub job summary (visible on the workflow run page)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write("## 🌐 Site Health Report\n\n```\n" + report + "\n```\n")

    # Send per-site failure alerts to override chats, if configured
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
