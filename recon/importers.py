"""Offline importers. Never replay imported requests."""
from __future__ import annotations
import base64
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
from .model import Record, canonical


def body_fields(value, prefix=""):
    fields = []
    if isinstance(value, dict):
        for key, val in value.items():
            name = f"{prefix}.{key}" if prefix else key
            fields.append({"in": "body", "name": name, "type": type(val).__name__})
            fields.extend(body_fields(val, name))
    elif isinstance(value, list) and value:
        fields.extend(body_fields(value[0], prefix + "[]"))
    return fields


def request_record(url, method, headers, body, source, evidence):
    params = [{"in": "query", "name": k} for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    header_names = {k.lower() for k in headers}
    auth = "credential-present" if {"authorization", "cookie", "x-api-key"} & header_names else "no-credential-observed"
    if body:
        try:
            params.extend(body_fields(json.loads(body)))
        except (ValueError, TypeError):
            if "application/x-www-form-urlencoded" in headers.get("content-type", ""):
                params.extend({"in": "body", "name": k} for k, _ in parse_qsl(body, keep_blank_values=True))
    # Values/bodies/cookies are intentionally not copied into evidence.
    return Record(canonical(url), source, method.upper(), params, auth, evidence)


def load_har(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for index, entry in enumerate(data.get("log", {}).get("entries", [])):
        req = entry["request"]
        headers = {h["name"].lower(): h["value"] for h in req.get("headers", [])}
        if req.get("cookies"):
            headers.setdefault("cookie", "present")
        post = req.get("postData", {})
        r = request_record(req["url"], req.get("method", "UNKNOWN"), headers, post.get("text", ""), "har", {"file": Path(path).name, "entry": index})
        r.parameters.extend({"in": "body", "name": p["name"]} for p in post.get("params", []))
        response = entry.get("response", {})
        r.evidence["response_status"] = response.get("status")
        content = response.get("content", {})
        try:
            body = content.get("text", "")
            if content.get("encoding") == "base64":
                body = base64.b64decode(body, validate=True).decode("utf-8")
            r.evidence["response_fields"] = body_fields(json.loads(body))
        except (ValueError, UnicodeError):
            pass
        yield r


def load_burp(path):
    # Burp HTTP history: Save items -> XML, with or without base64 messages.
    raw = Path(path).read_bytes()
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("XML entity declarations are not supported")
    root = ET.fromstring(raw)
    for index, item in enumerate(root.findall("item")):
        url = item.findtext("url", "")
        req = item.find("request")
        if req is None:
            continue
        value = req.text or ""
        if req.get("base64") == "true":
            value = base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
        head, _, body = value.replace("\r\n", "\n").partition("\n\n")
        lines = head.splitlines()
        headers = {}
        for line in lines[1:]:
            key, sep, val = line.partition(":")
            if sep:
                headers[key.lower()] = val.strip()
        method = lines[0].split()[0] if lines else item.findtext("method", "UNKNOWN")
        yield request_record(url, method, headers, body, "burp", {"file": Path(path).name, "item": index})


def load_openapi(path):
    raw = Path(path).read_text(encoding="utf-8")
    try:
        spec = json.loads(raw)
    except ValueError:
        import yaml
        spec = yaml.safe_load(raw)
    for route, entry in spec.get("paths", {}).items():
        for method, op in entry.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}:
                continue
            servers = op.get("servers", entry.get("servers", spec.get("servers", [])))
            for server in servers:
                base = server.get("url", "")
                for k, v in server.get("variables", {}).items():
                    base = base.replace("{" + k + "}", str(v.get("default", "")))
                if not base.startswith(("http://", "https://")):
                    continue
                params = [{"in": p.get("in", "unknown"), "name": p.get("name", "unknown")} for p in entry.get("parameters", []) + op.get("parameters", [])]
                for media in op.get("requestBody", {}).get("content", {}).values():
                    params.extend({"in": "body", "name": k, "type": v.get("type", "unknown")} for k, v in media.get("schema", {}).get("properties", {}).items())
                yield Record(canonical(base.rstrip("/") + "/" + route.lstrip("/")), "openapi", method.upper(), params,
                             "declared-security" if op.get("security", spec.get("security")) else "unspecified",
                             {"file": Path(path).name, "operation": op.get("operationId", ""), "template": True})


def load_urls(path, source="import"):
    for index, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Legacy TruffleHog tab records MUST NOT become URLs.
        if "\t" in line:
            raise ValueError(f"Line {index}: legacy mixed records need their dedicated importer")
        yield Record(canonical(line), source, evidence={"file": Path(path).name, "line": index})


def load_v8(path):
    for file in sorted(Path(path).glob("*.txt")):
        match = re.search(r"_(gau|waybackurls|katana)(?:_\d+)?\.txt$", file.name)
        if match:
            yield from load_urls(file, match.group(1))
    # v8 linkfinder records have no reliable source URL; secrets are not URL records.


def load(path, kind):
    return {"har": load_har, "burp": load_burp, "openapi": load_openapi, "urls": load_urls, "v8": load_v8}[kind](path)
