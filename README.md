# optimizely_check: check your Optimizely snippets, project code and CSP

One Python file for sites that use Optimizely Web Experimentation, written after the 16 November 2026 Optimizely
supply chain attack (also called OPTIMJACK). On that day an attacker wrote a loader into the Project JavaScript of
188 customer snippets belonging to 178 organisations, so every page that loaded one also loaded a crypto-address
swapper, a card skimmer and, on iPhones and iPads, an iOS exploit-kit router. It reads; it never changes anything.

This is the code from the TrickyWorld report
[Optimizely supply chain attack hit Zoom and BBC](https://www.trickyworld.in/computer-tricks/cyber-security/optimizely-supply-chain-attack-optimjack/).

Python 3.10 or newer, standard library only.

## The three modes

| Mode | Command | What it does |
|---|---|---|
| Snippet | `python3 optimizely_check.py snippet https://cdn.optimizely.com/js/<project>.js` | Fetches the snippet (or reads a saved file), cuts out the code customers write (Project JavaScript, variation custom code, redirect and locator functions) and checks it for the published indicators, a URL hidden in `atob()`, `eval()`, clipboard and network hooks, and `<script>` tags pointing at hosts you have not listed. `--actions` also fetches the external custom-code files (`/actions/<sha256>.js`) and checks that each file's content matches the SHA-256 in its name. `--baseline file.json` saves a fingerprint on the first run and reports what changed on later runs. |
| CSP | `python3 optimizely_check.py csp https://www.example.com/checkout` | Reads the page's `Content-Security-Policy` headers and `<meta>` policies and tests them against what the November payload needed: load `track.js` from an unknown host, or run an inline copy through `eval`, then send card, cookie and screenshot data out, plus the iOS stage and its hidden frame. It gives the same four verdicts as Report URI's analysis. `--policy "<policy>"` tests a policy string instead. |
| API | `OPTIMIZELY_TOKEN=... python3 optimizely_check.py api` | Reads every active web project through Optimizely's REST API v2: Project JavaScript, experiment and campaign shared code, variation custom code, redirect functions, page activation code and extension code, plus the change history between `--since` and `--until` (default 16 November 00:00 to 17 November 06:00 UTC). Code changes in that window are listed with the user and the source (UI, API or MCP) so you can confirm each one was yours. `--project <id>` limits it to one project. |

Add `--allow-host <host>` (repeatable) for third-party hosts your own code legitimately loads, and `--json` for
machine-readable output.

Exit codes: `0` nothing to act on, `1` at least one HIGH finding (or a CSP that let the payload run and send data
out), `2` MEDIUM items to review (or a CSP that let the payload run but blocked the data theft), `3` nothing could
be checked.

## Example

A copy of a real snippet with the published loader put back into its Project JavaScript, once in plain text and
once hidden in base64 (a plain text search for `1688360` misses the second):

```
[HIGH  ] published attacker host 1688360[.]cc: payload and data-collection host (track.js, card.php, hit.php)
           at monday-plain.js -> Project JavaScript
[HIGH  ] base64 hides published attacker host 1688360[.]cc: ... (decoded: https://1688360[.]cc/track[.]js)
           at monday-base64.js -> Project JavaScript
```

Optimizely's own example policy from its CSP documentation (which includes `'strict-dynamic'` and `'unsafe-eval'`):

```
  Load track.js from 1688360[.]cc                 allowed  'strict-dynamic' in script-src trusts any script the snippet inserts
  Run the inline copy (eval or inline script)     allowed  'unsafe-eval' in script-src
  Send card, cookie and screenshot data to ...    blocked  connect-src blocks it
  Open the hidden iOS exploit frame               blocked  frame-src blocks it
Verdict: Payload ran, but connect-src blocked the data theft (the address swapping still worked)
```

## Reading the result

- **HIGH**: a published indicator (host, IP, wallet address, payload marker or hash), a URL hidden in base64 that
  points at a host you have not listed, or an action file whose content does not match its name. Remove the code from
  the project, rotate the credentials that can write to your Optimizely account, and treat card data typed into your
  own forms and non-HttpOnly cookies on affected pages as exposed.
- **MEDIUM**: needs a human decision, such as a `<script>` from a host you have not listed, `eval()`, `atob()`,
  clipboard or `sendBeacon` use, or a code change during the attack window. Many are legitimate; confirm each one.
- **INFO**: context, such as the snippet revision, Last-Modified time or a saved baseline.

A clean result lowers the odds; it does not prove a page was never served the code. The payload was rebuilt 26 times
on 16 November and the loader came in three versions, so indicators move. A snippet that is clean now may have
carried the loader on Monday: ask Optimizely which of your project IDs were changed, when and how.

## Tests

```bash
python3 -m unittest -v
```

37 tests run offline: the brace matcher, synthetic snippets carrying each loader variant, action-file checks, the
baseline, CSP source matching and verdicts (including Optimizely's documented policies), and the API mode against a
local stand-in that answers with the response shapes in Optimizely's published spec. Two more run when you point
them at files:

```bash
curl -sO https://api.optimizely.com/v2/swagger.json
OPT_SPEC=swagger.json OPT_SNIPPETS=<folder of saved snippets> python3 -m unittest -v
```

`OPT_SPEC` checks every REST path, query parameter and response field the API mode uses against Optimizely's spec.
`OPT_SNIPPETS` checks that real, clean snippets raise no HIGH finding. The API mode has not been run against a live
Optimizely account.

## Sources for every indicator and rule

- [Report URI: World's Largest Brands Infected With Malware Via Optimizely](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/)
  (16 November 2026): the loader variants, timeline, IoC table, wallets and the CSP analysis behind the four verdicts.
- [StepSecurity: OPTIMJACK](https://www.stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer)
  (17 November 2026): payload behaviour, browser artefacts, domains and hashes.
- [Cynet: OPTIMJACK](https://www.cynet.com/blog/optimjack-malicious-web-injection-across-cnn-zoom-salesforce-fox-and-more/)
  (17 November 2026): delivery chain and IoCs.
- [Optimizely status: Web Experimentation Security Incident](https://status.optimizely.com/incidents/ftw0fh9wx43z)
  (17 November 2026, 01:02 UTC).
- [Optimizely: Update your site's Content Security Policies](https://docs.optimizely.com/web-experimentation/docs/update-your-site-s-content-security-policies-csp)
  and the REST API spec at `https://api.optimizely.com/v2/swagger.json`.
- [W3C Content Security Policy Level 3](https://www.w3.org/TR/CSP3/) for source matching and `'strict-dynamic'`.
