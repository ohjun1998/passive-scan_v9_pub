"""Local HTTP server exercises real urllib behavior, with no external target."""
import gzip
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from recon.model import Scope
from recon.network import Fetcher


class Handler(BaseHTTPRequestHandler):
    requests = []
    def log_message(self, *args):
        pass
    def do_GET(self):
        self.requests.append(self.path)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://out-of-scope.invalid/")
            self.end_headers()
        elif self.path == "/denied":
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Access denied")
        elif self.path == "/large":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"A" * 1024)
        elif self.path == "/gzip":
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            self.wfile.write(gzip.compress(b"A" * 1024))
        elif self.path == "/rate":
            self.send_response(429)
            self.send_header("Retry-After", "0")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<title>Example</title>ok")


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_port)
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
    def fetcher(self, **options):
        return Fetcher(Scope(["127.0.0.1"]), {"requests_per_second": 10000, "retries": 0, **options})
    def test_redirect_not_followed(self):
        result, _, _ = self.fetcher().fetch(self.base + "/redirect")
        self.assertEqual(result["status"], 302)
        self.assertEqual(result["location"], "https://out-of-scope.invalid/")
    def test_403_is_observation_not_dead(self):
        result, _, _ = self.fetcher().fetch(self.base + "/denied")
        self.assertEqual(result["state"], "observed")
        self.assertEqual(result["status"], 403)
    def test_raw_and_decompressed_size_limit(self):
        for route in ("/large", "/gzip"):
            result, body, _ = self.fetcher(max_body_bytes=100).fetch(self.base + route)
            self.assertEqual(result["state"], "body_too_large")
            self.assertEqual(body, b"")
    def test_429_preserved_and_retry_counted(self):
        f = self.fetcher(retries=1)
        result, _, _ = f.fetch(self.base + "/rate")
        self.assertEqual(result["status"], 429)
        self.assertEqual(f.total, 2)
    def test_success(self):
        result, _, _ = self.fetcher().fetch(self.base + "/")
        self.assertEqual(result["title"], "Example")

