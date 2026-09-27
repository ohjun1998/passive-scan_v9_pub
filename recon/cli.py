from __future__ import annotations
import argparse
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit
from .db import Database
from .model import Scope, Record
from .importers import load
from .collect import passive_collect, ingest_katana, download_js, crawl
from .network import Fetcher
from .report import export


def read_config(path):
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    scope = config.get("scope", {})
    if not scope.get("include"):
        raise ValueError("scope.include must contain at least one hostname or wildcard")
    for rule in scope.get("include", []) + scope.get("exclude", []):
        if not isinstance(rule, str) or not re.fullmatch(r"(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", rule):
            raise ValueError("Scope entries must be hostnames, not URLs or paths")
    for pattern in scope.get("exclude_paths", []):
        re.compile(pattern)
    for key in ("max_requests_per_host", "max_requests_total", "max_body_bytes", "timeout", "requests_per_second"):
        if float(config.get("network", {}).get(key, 1)) <= 0:
            raise ValueError(key + " must be positive")
    return config


def main(argv=None):
    parser = argparse.ArgumentParser(description="Passive Scan v9: evidence and change oriented recon")
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--state", default="state")
    parser.add_argument("--output", default="reports")
    sub = parser.add_subparsers(dest="command", required=True)
    runp = sub.add_parser("run")
    runp.add_argument("--mode", choices=["offline", "collect", "probe", "browser"], default="offline")
    runp.add_argument("--collect", action="store_true", help="Also use third-party archive collectors in probe/browser mode")
    runp.add_argument("--import", dest="imports", action="append", default=[], metavar="KIND:PATH")
    runp.add_argument("--katana", help="Import Katana text/JSONL, without launching another unbudgeted crawler")
    runp.add_argument("--verify-secrets", action="store_true", help="Allow TruffleHog provider validation network calls outside target budget")
    runp.add_argument("--ai", action="store_true", help="Send redacted path features to configured Gemini model")
    sub.add_parser("report")
    review = sub.add_parser("review")
    review.add_argument("id")
    review.add_argument("--status", choices=["unreviewed", "investigating", "false_positive", "reported"], required=True)
    review.add_argument("--owner", default="")
    review.add_argument("--note", default="")
    args = parser.parse_args(argv)
    previous_umask = os.umask(0o077)
    state = Path(args.state)
    state.mkdir(parents=True, exist_ok=True)
    db = Database(state / "recon.db")
    run = None
    try:
        if args.command == "review":
            cursor = db.conn.execute("UPDATE endpoints SET review=?,owner=?,note=? WHERE id=?", (args.status, args.owner, args.note, args.id))
            db.conn.commit()
            if not cursor.rowcount:
                raise ValueError("Endpoint ID not found")
            return 0
        if args.command == "report":
            row = db.conn.execute("SELECT MAX(id) AS id FROM runs").fetchone()
            if row["id"] is None:
                raise ValueError("No previous run")
            export(db, row["id"], args.output)
            return 0
        config = read_config(args.config)
        scope = Scope(**config["scope"])
        if args.mode in {"offline", "collect"} and args.verify_secrets:
            raise ValueError("Secret verification requires probe or browser mode")
        run = db.start(args.mode)
        for spec in args.imports:
            kind, sep, path = spec.partition(":")
            if not sep or kind not in {"har", "burp", "openapi", "urls", "v8"}:
                raise ValueError("Import must be har|burp|openapi|urls|v8:PATH")
            count = rejected = 0
            for record in load(path, kind):
                if scope.allows(record.url):
                    db.add(run, record)
                    db.asset(run, urlsplit(record.url).hostname)
                    count += 1
                else:
                    rejected += 1
            db.event(run, "import:" + kind, "complete", f"accepted={count}; out-of-scope={rejected}")
        if args.katana:
            ingest_katana(db, run, args.katana, scope)
        if args.mode == "collect" or args.collect and args.mode in {"probe", "browser"}:
            passive_collect(db, run, scope, config)
        fetcher = Fetcher(scope, config.get("network", {}))
        if args.mode in {"probe", "browser"}:
            seeds = ["https://" + a["host"] + "/" for a in db.rows("assets") if scope.allows("https://" + a["host"])]
            crawl(db, run, seeds, fetcher, scope, config.get("crawl_depth", 2), config.get("max_crawl_pages", 20))
            # JS is revisited by URL and content hash. Query strings are preserved.
            js_urls = sorted({e["url"] for e in db.rows("endpoints") if urlsplit(e["url"]).path.lower().endswith((".js", ".mjs")) and scope.allows(e["url"])})
            for url in js_urls[:config.get("max_js_files", 200)]:
                source = db.conn.execute("SELECT data FROM evidence WHERE endpoint_id IN (SELECT id FROM endpoints WHERE url=?) AND source='crawler' ORDER BY last_run DESC LIMIT 1", (url,)).fetchone()
                page_url = json.loads(source["data"]).get("page_url", "") if source else ""
                download_js(db, run, url, fetcher, scope, state, verify=args.verify_secrets, page_url=page_url)
            if len(js_urls) > config.get("max_js_files", 200):
                db.event(run, "js", "deferred", f"JS cap reached: {len(js_urls)} candidates preserved")
        from .model import priority
        rows = sorted(db.rows("endpoints"), key=lambda e: (-priority(e)["score"], e["url"], e["method"]))
        for row in rows:
            existing_observation = db.conn.execute("SELECT 1 FROM observations WHERE run_id=? AND endpoint_id=?", (run, row["id"])).fetchone()
            if existing_observation:
                continue
            if not scope.allows(row["url"]):
                result = {"state": "excluded", "error": "outside current scope"}
            elif args.mode not in {"probe", "browser"}:
                result = {"state": "not_probed", "error": "collection-only mode"}
            elif row["method"] not in {"GET", "UNKNOWN"}:
                result = {"state": "not_probed", "error": "imported non-GET request; manual replay only"}
            else:
                result, _, _ = fetcher.fetch(row["url"])
                old = db.conn.execute("SELECT status FROM observations WHERE endpoint_id=? AND state='observed' ORDER BY run_id DESC LIMIT 1", (row["id"],)).fetchone()
                if old and old["status"] != result.get("status") and result.get("state") == "observed" and config.get("confirm_status_changes", True):
                    check, _, _ = fetcher.fetch(row["url"])
                    result["confirmed"] = check.get("state") == "observed" and check.get("status") == result.get("status")
            db.observe(run, row["id"], result)
        if args.mode == "browser":
            from .extras import screenshots
            screenshots(db, run, scope, fetcher, args.output, config.get("max_screenshots", 20))
        data = export(db, run, args.output)
        if args.ai:
            from .extras import ai_rank
            ai_rank(data, args.output, config.get("ai", {}))
        failures = [e for e in db.rows("events") if e["run_id"] == run and e["state"] in {"failed", "timeout", "unavailable", "parse_error"}]
        status = "partial" if failures else "complete"
        db.finish(run, status)
        print(json.dumps({"run": run, "status": status, "endpoints": len(data["endpoints"]), "changes": len(data["changes"]), "report": str(Path(args.output) / "index.html")}))
        return 0
    except Exception as exc:
        if run:
            db.event(run, "pipeline", "failed", type(exc).__name__)
            db.finish(run, "failed")
        raise
    finally:
        db.close()
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
