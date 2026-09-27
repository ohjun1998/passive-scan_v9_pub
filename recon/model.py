from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

SECRET_KEY = re.compile(r"(?i)(password|passwd|secret|token|authorization|cookie|api.?key|session|jwt|signature|email|phone)")
UUID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
UNSAFE_PATH = re.compile(r"(?i)(?:^|[/_.-])(logout|signout|delete|remove|revoke|destroy)(?:$|[/_.-])")


def digest(value: str | bytes) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def canonical(url: str) -> str:
    p = urlsplit(url.strip())
    if p.scheme.lower() not in {"http", "https"} or not p.hostname or p.username or p.password:
        raise ValueError("Only absolute HTTP(S) URLs without userinfo are accepted")
    if any(ord(c) < 32 for c in url) or "\\" in url or any(c.isspace() for c in url):
        raise ValueError("Invalid URL characters")
    host = p.hostname.encode("idna").decode().lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    port = p.port
    if port and not (p.scheme.lower() == "https" and port == 443 or p.scheme.lower() == "http" and port == 80):
        host += f":{port}"
    # Preserve query order/duplicates and percent encoding: they may carry meaning.
    return urlunsplit((p.scheme.lower(), host, p.path or "/", p.query, ""))


def redact_url(url: str, all_values: bool = False) -> str:
    p = urlsplit(url)
    q = [(k, "[REDACTED]" if all_values or SECRET_KEY.search(k) else v)
         for k, v in parse_qsl(p.query, keep_blank_values=True)]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), ""))


def endpoint_pattern(url: str) -> str:
    p = urlsplit(url)
    parts = ["{uuid}" if UUID.fullmatch(x) else "{id}" if x.isdigit() else x for x in p.path.split("/")]
    return urlunsplit((p.scheme, p.netloc, "/".join(parts), urlencode([(k, "") for k, _ in parse_qsl(p.query, keep_blank_values=True)]), ""))


@dataclass
class Scope:
    include: list[str]
    exclude: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)

    @staticmethod
    def host_matches(host: str, rule: str) -> bool:
        rule = rule.lower().strip().rstrip(".")
        if rule.startswith("*."):
            return host.endswith("." + rule[2:])  # wildcard does not silently include apex
        return host == rule

    def allows(self, url: str) -> bool:
        try:
            p = urlsplit(canonical(url))
            host = p.hostname or ""
            return (any(self.host_matches(host, x) for x in self.include)
                    and not any(self.host_matches(host, x) for x in self.exclude)
                    and not any(re.search(x, p.path) for x in self.exclude_paths))
        except (ValueError, UnicodeError):
            return False


@dataclass
class Record:
    url: str
    source: str
    method: str = "UNKNOWN"
    parameters: list[dict] = field(default_factory=list)
    auth: str = "unknown"
    evidence: dict = field(default_factory=dict)
    source_url: str = ""

    @property
    def key(self) -> str:
        return digest(self.method.upper() + " " + canonical(self.url))


def classify(record: dict) -> list[str]:
    p = urlsplit(record["url"])
    words = set(re.findall(r"[a-z0-9]+", p.path.lower()))
    groups = {
        "admin": {"admin", "internal", "manage", "backoffice", "cms", "console", "debug", "swagger", "actuator"},
        "auth": {"login", "register", "oauth", "sso", "session", "signin", "auth", "mfa", "otp", "password"},
        "money": {"transfer", "checkout", "refund", "coupon", "invoice", "payment", "billing", "wallet", "balance"},
        "file": {"upload", "download", "export", "import", "attachment", "document", "file", "report"},
    }
    tags = [name for name, keys in groups.items() if words & keys]
    keys = [k.lower() for k, _ in parse_qsl(p.query, keep_blank_values=True)]
    for evidence in record.get("evidence", []):
        keys.extend(str(x.get("name", "")).lower() for x in evidence.get("parameters", []))
    if (any(re.search(r"(?:^|_)(id|uuid|idx|seq|tenant|account|user)(?:$|_)", k) or k.endswith("id") for k in keys)
            or any(x.isdigit() or UUID.fullmatch(x) for x in p.path.split("/"))):
        tags.append("object")
    return tags or ["other"]


def priority(record: dict, changed: bool = False) -> dict:
    tags = classify(record)
    score = 10
    reasons = []
    for tag, weight in (("admin", 25), ("money", 25), ("auth", 15), ("object", 20), ("file", 15)):
        if tag in tags:
            score += weight
            reasons.append(f"{tag} 기능 또는 입력이 관찰됨")
    if changed:
        score += 15
        reasons.append("이번 실행에서 신규 또는 변경됨")
    if record.get("status") in (401, 403):
        reasons.append("인증·권한 응답 관찰: 권한별 요청 비교 후보")
    if "object" in tags:
        next_step = "서로 다른 테스트 계정으로 객체 소유권·테넌트 접근 제어 비교"
    else:
        next_step = "원본 요청과 응답을 확인하고 기능·인증 조건을 수동 검증"
    return {"score": min(score, 100), "tags": tags, "reasons": reasons,
            "next_step": next_step, "uncertainty": "우선순위 점수이며 취약점 존재 확률이 아님"}


def resolve_candidate(value: str, source_url: str, page_url: str = "") -> tuple[str, str]:
    if value.startswith(("http://", "https://", "//")):
        return canonical(urljoin(source_url, value)), "explicit"
    # Runtime-relative fetch() resolves against document/baseURI, not the JS asset.
    if page_url:
        return canonical(urljoin(page_url, value)), "page-relative candidate"
    if value.startswith("/") and not value.startswith("//"):
        return canonical(urljoin(source_url, value)), "origin-relative candidate; API base unverified"
    raise ValueError("Relative endpoint requires page/base URL evidence")
