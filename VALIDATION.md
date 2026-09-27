# Validation record

## Locally verified

- Python unittest: 27 tests passed.
- Offline end-to-end example: 9 URLs retained, 9 initial observations marked not_probed.
- HTML, XLSX, JSON and Postman output generated.
- Python compileall and Bash syntax checks passed.
- HTTP tests used a loopback server only: 200, 302 without redirect following, 403,
  429 retry accounting, body limits including decompression.
- Regression tests cover Katana ingestion, 7 distinct sibling APIs, source/method retention,
  JS filename collisions, query preservation, unchanged/changed JS, failed analysis retry,
  secret separation and masking, review persistence, API schema changes, HAR/Burp/OpenAPI,
  output escaping, scope checks and request budgets.

## Not run in this environment

- Real target scanning and authenticated request replay.
- GitHub Actions execution, cache restore and encrypted artifact transfer.
- Full external collector/TruffleHog installation and their live provider integrations.
- Chromium screenshots and Gemini API calls.
- Discord delivery.

Optional integrations are implemented but must be exercised with the user's scoped environment
and credentials before treating the pipeline as production-validated. No target secrets or live
scan results are included in this source package.
