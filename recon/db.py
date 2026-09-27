from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from .model import Record, canonical, digest, endpoint_pattern


def now():
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, started TEXT, finished TEXT, mode TEXT, status TEXT);
        CREATE TABLE IF NOT EXISTS endpoints(
          id TEXT PRIMARY KEY, url TEXT NOT NULL, method TEXT NOT NULL, pattern TEXT,
          first_seen TEXT, last_seen TEXT, review TEXT DEFAULT 'unreviewed', owner TEXT DEFAULT '', note TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS evidence(
          id TEXT PRIMARY KEY, endpoint_id TEXT REFERENCES endpoints(id), source TEXT, source_url TEXT,
          data TEXT, first_run INTEGER, last_run INTEGER);
        CREATE TABLE IF NOT EXISTS observations(
          run_id INTEGER, endpoint_id TEXT REFERENCES endpoints(id), state TEXT, status INTEGER,
          title TEXT, content_type TEXT, body_hash TEXT, body_length INTEGER, location TEXT, page_kind TEXT,
          server TEXT, error TEXT, PRIMARY KEY(run_id,endpoint_id));
        CREATE TABLE IF NOT EXISTS changes(
          id INTEGER PRIMARY KEY, run_id INTEGER, endpoint_id TEXT, kind TEXT, before_value TEXT, after_value TEXT,
          confirmed INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS js_versions(
          url TEXT, hash TEXT, path TEXT, etag TEXT, modified TEXT, first_run INTEGER, last_run INTEGER,
          analyzed INTEGER DEFAULT 0, PRIMARY KEY(url,hash));
        CREATE TABLE IF NOT EXISTS findings(
          id TEXT PRIMARY KEY, kind TEXT, detector TEXT, source_url TEXT, location TEXT,
          fingerprint TEXT, masked TEXT, verification TEXT, first_run INTEGER, last_run INTEGER,
          review TEXT DEFAULT 'unreviewed');
        CREATE TABLE IF NOT EXISTS events(run_id INTEGER, stage TEXT, state TEXT, detail TEXT);
        CREATE TABLE IF NOT EXISTS assets(host TEXT PRIMARY KEY, first_run INTEGER, last_run INTEGER);
        """)
        self.conn.commit()

    def start(self, mode):
        c = self.conn.execute("INSERT INTO runs(started,mode,status) VALUES(?,?,'running')", (now(), mode))
        self.conn.commit()
        return c.lastrowid

    def finish(self, run, status="complete"):
        self.conn.execute("UPDATE runs SET finished=?,status=? WHERE id=?", (now(), status, run))
        self.conn.commit()

    def event(self, run, stage, state, detail):
        self.conn.execute("INSERT INTO events VALUES(?,?,?,?)", (run, stage, state, detail))
        self.conn.commit()

    def change(self, run, key, kind, before, after, confirmed=False):
        self.conn.execute("INSERT INTO changes(run_id,endpoint_id,kind,before_value,after_value,confirmed) VALUES(?,?,?,?,?,?)",
                          (run, key, kind, str(before), str(after), int(confirmed)))

    def asset(self, run, host):
        self.conn.execute("INSERT INTO assets VALUES(?,?,?) ON CONFLICT(host) DO UPDATE SET last_run=excluded.last_run", (host, run, run))
        self.conn.commit()

    def add(self, run, record: Record):
        url = canonical(record.url)
        key = record.key
        old = self.conn.execute("SELECT id FROM endpoints WHERE id=?", (key,)).fetchone()
        t = now()
        self.conn.execute("INSERT INTO endpoints(id,url,method,pattern,first_seen,last_seen) VALUES(?,?,?,?,?,?) "
                          "ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen",
                          (key, url, record.method.upper(), endpoint_pattern(url), t, t))
        if not old:
            self.change(run, key, "new_endpoint", "", url)
        data = json.dumps({**record.evidence, "parameters": record.parameters, "auth": record.auth}, sort_keys=True, ensure_ascii=False)
        prior = self.conn.execute("SELECT data FROM evidence WHERE endpoint_id=? AND source=? AND last_run<? ORDER BY last_run DESC LIMIT 1", (key, record.source, run)).fetchone()
        if prior:
            before = json.loads(prior["data"])
            current = json.loads(data)
            for field in ("parameters", "response_fields", "auth"):
                left, right = before.get(field), current.get(field)
                if left != right:
                    self.change(run, key, field + "_changed", json.dumps(left, ensure_ascii=False), json.dumps(right, ensure_ascii=False))
        eid = digest(key + record.source + record.source_url + data)
        self.conn.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_run=excluded.last_run",
                          (eid, key, record.source, record.source_url, data, run, run))
        self.conn.commit()
        return key

    def observe(self, run, key, result):
        old = self.conn.execute("SELECT * FROM observations WHERE endpoint_id=? AND run_id<? AND state='observed' ORDER BY run_id DESC LIMIT 1", (key, run)).fetchone()
        if old and result.get("state") == "observed":
            for field in ("status", "body_hash", "title", "content_type", "location", "server"):
                new = result.get(field)
                if old[field] != new:
                    self.change(run, key, field + "_changed", old[field], new, result.get("confirmed", False))
        fields = ("state", "status", "title", "content_type", "body_hash", "body_length", "location", "page_kind", "server", "error")
        self.conn.execute("INSERT OR REPLACE INTO observations VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (run, key, *(result.get(k) for k in fields)))
        self.conn.commit()

    def js_version(self, run, url, content_hash, path, etag="", modified=""):
        old = self.conn.execute("SELECT hash FROM js_versions WHERE url=? ORDER BY last_run DESC LIMIT 1", (url,)).fetchone()
        existing = self.conn.execute("SELECT analyzed FROM js_versions WHERE url=? AND hash=?", (url, content_hash)).fetchone()
        self.conn.execute("INSERT INTO js_versions(url,hash,path,etag,modified,first_run,last_run) VALUES(?,?,?,?,?,?,?) "
                          "ON CONFLICT(url,hash) DO UPDATE SET last_run=excluded.last_run,path=excluded.path,etag=excluded.etag,modified=excluded.modified",
                          (url, content_hash, str(path), etag, modified, run, run))
        if old and old["hash"] != content_hash:
            self.change(run, digest("JS " + url), "js_changed", old["hash"], content_hash)
        self.conn.commit()
        return not existing or not existing["analyzed"]

    def analyzed(self, url, content_hash):
        self.conn.execute("UPDATE js_versions SET analyzed=1 WHERE url=? AND hash=?", (url, content_hash))
        self.conn.commit()

    def finding(self, run, detector, source_url, location, fingerprint, verification):
        fid = digest(detector + source_url + location + fingerprint)
        self.conn.execute("INSERT INTO findings(id,kind,detector,source_url,location,fingerprint,masked,verification,first_run,last_run) "
                          "VALUES(?,'secret',?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_run=excluded.last_run,verification=excluded.verification",
                          (fid, detector, source_url, location, fingerprint, "[REDACTED]", verification, run, run))
        self.conn.commit()

    def rows(self, table):
        if table not in {"endpoints", "evidence", "observations", "changes", "js_versions", "findings", "events", "assets", "runs"}:
            raise ValueError("Invalid table")
        return [dict(r) for r in self.conn.execute(f"SELECT * FROM {table}")]

    def close(self):
        self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.conn.close()
