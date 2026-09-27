from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit
from .model import Record, canonical, digest, resolve_candidate


def tool_lines(db, run, argv, input_text=None, timeout=180):
    name = argv[0]
    if not shutil.which(name):
        db.event(run, name, "unavailable", "Install optional tool to enable this stage")
        return []
    try:
        proc = subprocess.run(argv, input=input_text, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        db.event(run, name, "timeout", f"Exceeded {timeout}s; output not ingested")
        return []
    if proc.returncode:
        # stderr may contain URLs, tokens or credentials. Keep it out of shared reports.
        db.event(run, name, "failed", f"exit={proc.returncode}")
        return []
    db.event(run, name, "complete", f"lines={len(proc.stdout.splitlines())}")
    return proc.stdout.splitlines()


def passive_collect(db, run, scope, config):
    hosts = set()
    for rule in scope.include:
        if rule.startswith("*."):
            for host in tool_lines(db, run, ["subfinder", "-d", rule[2:], "-silent"]):
                if scope.allows("https://" + host.strip()):
                    hosts.add(host.strip())
        elif scope.allows("https://" + rule):
            hosts.add(rule)
    for host in sorted(hosts):
        db.asset(run, host)
        for name, argv in (("gau", ["gau", "--threads", "1"]), ("waybackurls", ["waybackurls"])):
            if name not in config.get("collectors", ["gau", "waybackurls"]):
                continue
            for line in tool_lines(db, run, argv, host + "\n"):
                if scope.allows(line):
                    db.add(run, Record(line, name))
    return sorted(hosts)


def ingest_katana(db, run, path, scope):
    """Import text or JSONL from a separately budgeted Katana run."""
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            req = item.get("request", {})
            url = req.get("endpoint", "")
            method = req.get("method", "UNKNOWN")
        except ValueError:
            url, method = line.strip(), "UNKNOWN"
        if scope.allows(url):
            db.add(run, Record(url, "katana", method, evidence={"line": n}))


def js_analyze(db, run, path, source_url, scope, state_dir, page_url="", verify=False):
    event_start = db.conn.execute("SELECT COALESCE(MAX(rowid),0) FROM events").fetchone()[0]
    lines = tool_lines(db, run, ["jsluice", "urls", str(path)])
    for n, line in enumerate(lines, 1):
        try:
            data = json.loads(line)
            url, resolution = resolve_candidate(data["url"], source_url, page_url)
            if scope.allows(url):
                method = str(data.get("method", "UNKNOWN")).upper()
                params = [{"in": "query", "name": p} for p in data.get("queryParams", []) if isinstance(p, str)]
                db.add(run, Record(url, "jsluice", method, params, evidence={"resolution": resolution, "line": n}, source_url=source_url))
        except (ValueError, KeyError, TypeError):
            db.event(run, "jsluice", "unresolved", "Relative/dynamic URL or unsupported result retained only in original JS")
    keyfile = Path(state_dir) / "secret_fingerprint.key"
    if not keyfile.exists():
        fd = os.open(keyfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
    key = keyfile.read_bytes()
    argv = ["trufflehog", "filesystem", str(path), "--json", "--no-update"]
    if not verify:
        argv.append("--no-verification")
    secret_lines = tool_lines(db, run, argv)
    for line in secret_lines:
        try:
            data = json.loads(line)
            raw = str(data.get("Raw", ""))
            if not raw:
                continue
            fingerprint = hmac.new(key, raw.encode(), hashlib.sha256).hexdigest()
            meta = data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
            verification = "verified" if data.get("Verified") else "verification_error" if data.get("VerificationError") else "unverified"
            db.finding(run, data.get("DetectorName", "unknown"), source_url, str(meta.get("line", "")), fingerprint, verification)
        except (ValueError, TypeError):
            db.event(run, "trufflehog", "parse_error", "Invalid result")
    failed = db.conn.execute("SELECT 1 FROM events WHERE rowid>? AND stage IN ('jsluice','trufflehog') AND state IN ('failed','timeout','unavailable','parse_error') LIMIT 1", (event_start,)).fetchone()
    return failed is None and shutil.which("jsluice") is not None and shutil.which("trufflehog") is not None


def download_js(db, run, url, fetcher, scope, state_dir, verify=False, page_url=""):
    previous = db.conn.execute("SELECT * FROM js_versions WHERE url=? ORDER BY last_run DESC LIMIT 1", (url,)).fetchone()
    headers = {}
    if previous and Path(previous["path"]).exists():
        if previous["etag"]:
            headers["If-None-Match"] = previous["etag"]
        if previous["modified"]:
            headers["If-Modified-Since"] = previous["modified"]
    result, body, response_headers = fetcher.fetch(url, headers)
    if result.get("status") == 304 and previous and Path(previous["path"]).exists():
        path, content_hash = Path(previous["path"]), previous["hash"]
    elif result.get("state") == "observed" and result.get("status") == 200:
        if "html" in response_headers.get("content-type", "").lower() or body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
            db.event(run, "js", "rejected", "HTML response is not JavaScript")
            return
        content_hash = digest(body)
        path = Path(state_dir) / "js" / (digest(url) + "_" + content_hash + ".js")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    else:
        db.event(run, "js", result["state"], "Download not analyzed")
        return
    needs_analysis = db.js_version(run, url, content_hash, path, response_headers.get("etag", previous["etag"] if previous else ""),
                                   response_headers.get("last-modified", previous["modified"] if previous else ""))
    if needs_analysis and js_analyze(db, run, path, url, scope, state_dir, page_url=page_url, verify=verify):
        db.analyzed(url, content_hash)


def crawl(db, run, seeds, fetcher, scope, depth=2, max_pages=20):
    """Bounded static HTML discovery sharing the global request budget."""
    from collections import deque
    from html.parser import HTMLParser
    from urllib.parse import urljoin

    class Links(HTMLParser):
        def __init__(self):
            super().__init__()
            self.urls = []
            self.base = ""
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "base" and attrs.get("href") and not self.base:
                self.base = attrs["href"]
            if tag == "a" and attrs.get("href"):
                self.urls.append((attrs["href"], "link"))
            if tag == "script" and attrs.get("src"):
                self.urls.append((attrs["src"], "script"))

    queue = deque((url, 0) for url in seeds)
    seen = set()
    while queue and len(seen) < max_pages:
        url, level = queue.popleft()
        if url in seen or not scope.allows(url):
            continue
        seen.add(url)
        result, body, _ = fetcher.fetch(url)
        key = db.add(run, Record(url, "crawler", "GET"))
        db.observe(run, key, result)
        if result.get("state") != "observed" or "html" not in result.get("content_type", ""):
            continue
        parser = Links()
        parser.feed(body.decode("utf-8", errors="replace"))
        base = urljoin(url, parser.base) if parser.base else url
        for value, kind in parser.urls:
            try:
                target = canonical(urljoin(base, value))
            except ValueError:
                continue
            if not scope.allows(target):
                continue
            db.add(run, Record(target, "crawler", "GET", evidence={"page_url": base, "kind": kind}, source_url=url))
            if kind == "link" and level < depth:
                queue.append((target, level + 1))
    if queue:
        db.event(run, "crawler", "deferred", "Page cap reached; discovered endpoints preserved")
