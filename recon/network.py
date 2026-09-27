from __future__ import annotations
import gzip
import html
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from collections import defaultdict
from urllib.parse import urlsplit, urljoin, parse_qsl
from .model import Scope, UNSAFE_PATH, canonical, digest, SECRET_KEY


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Fetcher:
    """Single coordinator: one host budget shared by probes and JS downloads."""
    def __init__(self, scope: Scope, config: dict, clock=time.monotonic, sleep=time.sleep):
        self.scope, self.config, self.clock, self.sleep = scope, config, clock, sleep
        self.last = defaultdict(float)
        self.count = defaultdict(int)
        self.total = 0
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def fetch(self, url, headers=None):
        if not self.scope.allows(url):
            return {"state": "excluded", "error": "out-of-scope"}, b"", {}
        p = urlsplit(url)
        if UNSAFE_PATH.search(p.path) or any(SECRET_KEY.search(k) for k, _ in parse_qsl(p.query)):
            return {"state": "excluded", "error": "sensitive URL requires manual review"}, b"", {}
        if "{" in url or "}" in url:
            return {"state": "not_probed", "error": "unresolved URL template"}, b"", {}
        host = p.hostname
        attempts = 1 + int(self.config.get("retries", 1))
        result, content, response_headers = {"state": "failed"}, b"", {}
        for attempt in range(attempts):
            if self.count[host] >= self.config.get("max_requests_per_host", 100) or self.total >= self.config.get("max_requests_total", 1000):
                return {"state": "deferred", "error": "request budget exhausted"}, b"", {}
            delay = self.last[host] - self.clock()
            if delay > 0:
                self.sleep(delay)
            self.count[host] += 1
            self.total += 1
            self.last[host] = self.clock() + 1 / max(float(self.config.get("requests_per_second", 1)), 0.01)
            request_headers = {"User-Agent": "PassiveScanV9/9.0 (authorized reconnaissance)", "Accept-Encoding": "identity", **(headers or {})}
            req = urllib.request.Request(canonical(url), headers=request_headers, method="GET")
            try:
                try:
                    response = self.opener.open(req, timeout=self.config.get("timeout", 10))
                except urllib.error.HTTPError as exc:
                    response = exc  # 3xx/4xx/5xx are observations, not transport failures.
                with response:
                    response_headers = {k.lower(): v for k, v in response.headers.items()}
                    limit = int(self.config.get("max_body_bytes", 2097152))
                    content = response.read(limit + 1)
                    if len(content) > limit:
                        return {"state": "body_too_large", "status": response.code}, b"", response_headers
                    if response_headers.get("content-encoding", "").lower() == "gzip":
                        import io
                        with gzip.GzipFile(fileobj=io.BytesIO(content)) as gz:
                            content = gz.read(limit + 1)
                        if len(content) > limit:
                            return {"state": "body_too_large", "status": response.code}, b"", response_headers
                    elif response_headers.get("content-encoding", "identity").lower() not in ("identity", ""):
                        return {"state": "unsupported_encoding", "status": response.code}, b"", response_headers
                    result = fingerprint(content, response_headers)
                    result.update(state="observed", status=response.code)
                if result["status"] not in (429, 503):
                    return result, content, response_headers
                retry = response_headers.get("retry-after", "")
                wait = min(2 ** (attempt + 1), 30)
                if retry.isdigit():
                    wait = min(float(retry), 60)
                elif retry:
                    try:
                        wait = max(0, min((parsedate_to_datetime(retry) - datetime.now(timezone.utc)).total_seconds(), 60))
                    except (TypeError, ValueError):
                        pass
                self.last[host] = max(self.last[host], self.clock() + wait)
            except (TimeoutError, socket.timeout):
                result = {"state": "timeout", "error": "request timed out"}
            except urllib.error.URLError as exc:
                if isinstance(exc.reason, ssl.SSLError):
                    result = {"state": "tls_error", "error": "TLS validation failed"}
                elif isinstance(exc.reason, socket.gaierror):
                    result = {"state": "dns_error", "error": "DNS lookup failed"}
                else:
                    result = {"state": "network_error", "error": type(exc.reason).__name__}
            except (OSError, ValueError) as exc:
                result = {"state": "failed", "error": type(exc).__name__}
        return result, content, response_headers


def fingerprint(body, headers):
    text = body.decode("utf-8", errors="replace")
    title = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    normalized = re.sub(r"\s+", " ", text).strip()
    page = "unknown"
    if "text/html" in headers.get("content-type", ""):
        page = "html"
        if re.search(r'(?i)type\s*=\s*[\"\']password', text):
            page = "login_candidate"
        elif re.search(r"(?i)(access denied|request blocked|captcha)", text):
            page = "block_candidate"
    elif "json" in headers.get("content-type", ""):
        page = "json"
    return {"title": html.unescape(re.sub(r"<[^>]+>", "", title.group(1)))[:300] if title else "",
            "content_type": headers.get("content-type", ""), "body_hash": digest(normalized),
            "body_length": len(body), "location": headers.get("location", ""), "page_kind": page,
            "server": headers.get("server", ""), "error": ""}
