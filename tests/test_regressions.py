import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from recon.db import Database
from recon.model import Record, Scope, canonical, endpoint_pattern, resolve_candidate
from recon.collect import download_js, ingest_katana, js_analyze
from recon.importers import load_har, load_burp, load_openapi, load_v8
from recon.network import Fetcher, fingerprint
from recon.report import export, clean
from recon.cli import main


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = Database(self.root / "recon.db")
        self.run = self.db.start("offline")
        self.scope = Scope(["example.com", "*.example.com"])

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_seven_distinct_api_paths_survive(self):
        for path in ("login", "profile", "payment", "refund", "export", "admin", "documents"):
            self.db.add(self.run, Record("https://example.com/api/" + path, "gau"))
        self.assertEqual(len(self.db.rows("endpoints")), 7)
        self.assertEqual(len({e["pattern"] for e in self.db.rows("endpoints")}), 7)

    def test_method_and_provenance_preserved(self):
        for method, source in (("POST", "har"), ("POST", "burp"), ("GET", "har")):
            self.db.add(self.run, Record("https://example.com/api", source, method))
        self.assertEqual(len(self.db.rows("endpoints")), 2)
        self.assertEqual(len(self.db.rows("evidence")), 3)

    def test_katana_reaches_probe_inventory(self):
        path = self.root / "katana.jsonl"
        path.write_text(json.dumps({"request": {"endpoint": "https://example.com/katana-only", "method": "GET"}}))
        ingest_katana(self.db, self.run, path, self.scope)
        self.assertEqual(self.db.rows("endpoints")[0]["url"], "https://example.com/katana-only")

    def test_legacy_secret_never_becomes_url(self):
        (self.root / "example.com_trufflehog_00.txt").write_text("app.js\t[AWS] secret-value")
        (self.root / "example.com_katana_00.txt").write_text("https://example.com/ok\n")
        rows = list(load_v8(self.root))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].source, "katana")

    def test_change_and_review_persist(self):
        key = self.db.add(self.run, Record("https://example.com/admin", "gau"))
        self.db.observe(self.run, key, {"state": "observed", "status": 403})
        self.db.conn.execute("UPDATE endpoints SET review='investigating',note='keep' WHERE id=?", (key,))
        self.db.conn.commit()
        run2 = self.db.start("probe")
        self.db.add(run2, Record("https://example.com/admin", "gau"))
        self.db.observe(run2, key, {"state": "observed", "status": 200, "confirmed": True})
        changes = [c for c in self.db.rows("changes") if c["run_id"] == run2]
        self.assertEqual(changes[0]["kind"], "status_changed")
        self.assertEqual(changes[0]["confirmed"], 1)
        self.assertEqual(self.db.rows("endpoints")[0]["note"], "keep")

    def test_api_field_change_detected(self):
        self.db.add(self.run, Record("https://example.com/api", "har", "POST", [{"name": "id", "in": "body"}]))
        run2 = self.db.start("offline")
        self.db.add(run2, Record("https://example.com/api", "har", "POST", [{"name": "id", "in": "body"}, {"name": "tenantId", "in": "body"}]))
        changes = [c for c in self.db.rows("changes") if c["run_id"] == run2]
        self.assertEqual(changes[0]["kind"], "parameters_changed")

    def test_failed_js_analysis_is_retryable(self):
        from recon.collect import tool_lines as original
        with patch("recon.collect.shutil.which", return_value="tool"), patch("recon.collect.subprocess.run") as proc:
            proc.return_value.returncode = 1
            proc.return_value.stdout = ""
            self.assertFalse(js_analyze(self.db, self.run, self.root / "app.js", "https://example.com/app.js", self.scope, self.root))

    def test_js_basename_collision_and_query_preserved(self):
        class Fetch:
            def fetch(self, url, headers):
                return {"state": "observed", "status": 200}, url.encode(), {"content-type": "text/javascript"}
        with patch("recon.collect.js_analyze", return_value=True):
            for url in ("https://example.com/a/app.js?v=1", "https://example.com/b/app.js?v=2"):
                download_js(self.db, self.run, url, Fetch(), self.scope, self.root)
        rows = self.db.rows("js_versions")
        self.assertEqual(len({r["path"] for r in rows}), 2)
        self.assertTrue(all("?v=" in r["url"] for r in rows))

    def test_unchanged_js_skips_reanalysis_but_changed_reanalyzes(self):
        class Fetch:
            content = b"v1"
            def fetch(self, url, headers):
                return {"state": "observed", "status": 200}, self.content, {}
        fetch = Fetch()
        with patch("recon.collect.js_analyze", return_value=True) as analyze:
            for content in (b"v1", b"v1", b"v2"):
                fetch.content = content
                download_js(self.db, self.run, "https://example.com/app.js", fetch, self.scope, self.root)
            self.assertEqual(analyze.call_count, 2)
        self.assertEqual(len(self.db.rows("js_versions")), 2)

    def test_secrets_masked_and_separated(self):
        fake = json.dumps({"DetectorName": "Example", "Raw": "SUPER-SECRET", "Verified": False,
                           "SourceMetadata": {"Data": {"Filesystem": {"line": 5}}}})
        with patch("recon.collect.tool_lines", side_effect=[[], [fake]]), patch("recon.collect.shutil.which", return_value="tool"):
            js_analyze(self.db, self.run, self.root / "app.js", "https://example.com/app.js", self.scope, self.root)
        self.assertEqual(len(self.db.rows("endpoints")), 0)
        row = self.db.rows("findings")[0]
        self.assertEqual(row["verification"], "unverified")
        self.assertNotIn("SUPER-SECRET", json.dumps(row))

    def test_html_and_excel_escape_and_unknown_postman(self):
        self.db.add(self.run, Record("https://example.com/<script>alert(1)</script>?token=private", "gau"))
        self.db.add(self.run, Record("https://example.com/api", "har", "POST", [{"in": "body", "name": "userId"}]))
        out = self.root / "reports"
        data = export(self.db, self.run, out)
        text = (out / "index.html").read_text()
        self.assertNotIn("<script>alert(1)</script>", text)
        self.assertNotIn("token=private", text)
        self.assertTrue((out / "report.xlsx").exists())
        postman = json.loads((out / "postman.json").read_text())
        self.assertEqual(len(postman["item"]), 1)
        self.assertEqual(postman["item"][0]["request"]["method"], "POST")
        self.assertEqual(data["endpoints"][0]["state"], "not_probed")
        self.assertTrue(clean(" =HYPERLINK(1)").startswith("'"))


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()
    def test_har_body_method_auth_without_secret_values(self):
        p = self.root / "sample.har"
        p.write_text(json.dumps({"log": {"entries": [{"request": {"url": "https://example.com/api", "method": "POST", "headers": [{"name": "Authorization", "value": "secret"}], "postData": {"text": '{"userId":123,"password":"private"}'}}}]}}))
        r = list(load_har(p))[0]
        self.assertEqual(r.method, "POST")
        self.assertEqual(r.auth, "credential-present")
        self.assertNotIn("private", str(r.parameters))
        self.assertIn("userId", str(r.parameters))
    def test_burp_base64(self):
        p = self.root / "burp.xml"
        request = base64.b64encode(b"PATCH /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"tenantId\":1}").decode()
        p.write_text(f'<items><item><url>https://example.com/api</url><request base64="true">{request}</request></item></items>')
        r = list(load_burp(p))[0]
        self.assertEqual(r.method, "PATCH")
        self.assertEqual(r.parameters[0]["name"], "tenantId")
    def test_openapi(self):
        p = self.root / "api.json"
        p.write_text(json.dumps({"openapi": "3.0.0", "servers": [{"url": "https://example.com/v1"}], "paths": {"/orders/{id}": {"get": {"parameters": [{"in": "path", "name": "id"}]}}}}))
        r = list(load_openapi(p))[0]
        self.assertEqual(r.url, "https://example.com/v1/orders/{id}")
        self.assertEqual(r.method, "GET")
    def test_offline_cli_never_opens_network(self):
        config = self.root / "config.json"
        config.write_text(json.dumps({"scope": {"include": ["example.com"]}}))
        urls = self.root / "urls.txt"
        urls.write_text("https://example.com/api\nhttps://outside.test/api\n")
        with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network forbidden")):
            result = main(["--config", str(config), "--state", str(self.root / "state"), "--output", str(self.root / "reports"), "run", "--mode", "offline", "--import", "urls:" + str(urls)])
        self.assertEqual(result, 0)
        data = json.loads((self.root / "reports/report.json").read_text())
        self.assertEqual(len(data["endpoints"]), 1)
        self.assertEqual(data["endpoints"][0]["state"], "not_probed")


class PureTests(unittest.TestCase):
    def test_scope_boundaries(self):
        s = Scope(["*.example.com"], ["blocked.example.com"], ["^/private"])
        for url in ("https://example.com", "https://example.com.evil.test", "https://blocked.example.com", "https://a.example.com/private", "https://example.com@evil.test"):
            self.assertFalse(s.allows(url), url)
        self.assertTrue(s.allows("https://a.example.com/public"))
    def test_no_query_loss(self):
        self.assertEqual(canonical("HTTPS://EXAMPLE.COM:443/api?id=1&id=2#x"), "https://example.com/api?id=1&id=2")
    def test_long_paths_not_hashes(self):
        self.assertIn("transactions", endpoint_pattern("https://example.com/api/transactions"))
    def test_relative_context_required(self):
        with self.assertRaises(ValueError):
            resolve_candidate("api/orders", "https://cdn.example.com/app.js")
        url, _ = resolve_candidate("api/orders", "https://cdn.example.com/app.js", "https://app.example.com/dashboard/")
        self.assertEqual(url, "https://app.example.com/dashboard/api/orders")
    def test_scope_checked_before_request(self):
        fetch = Fetcher(Scope(["example.com"]), {})
        with patch.object(fetch.opener, "open", side_effect=AssertionError("must not request")):
            self.assertEqual(fetch.fetch("https://evil.test")[0]["state"], "excluded")
            self.assertEqual(fetch.fetch("https://example.com/delete")[0]["state"], "excluded")
            self.assertEqual(fetch.fetch("https://example.com/api?token=secret")[0]["state"], "excluded")
            self.assertEqual(fetch.fetch("https://example.com/users/{id}")[0]["state"], "not_probed")
    def test_budget_counts_retries(self):
        import urllib.error
        fetch = Fetcher(Scope(["example.com"]), {"max_requests_per_host": 1, "retries": 2}, sleep=lambda _: None)
        with patch.object(fetch.opener, "open", side_effect=urllib.error.URLError("failure")) as open_mock:
            self.assertEqual(fetch.fetch("https://example.com/")[0]["state"], "deferred")
            self.assertEqual(open_mock.call_count, 1)
    def test_response_clusters_and_login_hint(self):
        one = fingerprint(b'<title>Login</title><input type="password">', {"content-type": "text/html"})
        two = fingerprint(b'<title>Login</title><input type="password">', {"content-type": "text/html"})
        self.assertEqual(one["body_hash"], two["body_hash"])
        self.assertEqual(one["page_kind"], "login_candidate")


if __name__ == "__main__":
    unittest.main()
