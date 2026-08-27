# SiteScope

**A website security evaluation tool for small businesses.**

SiteScope scans a website you own, finds the security weaknesses an attacker
would look for, and explains each one in plain language with step-by-step
instructions for fixing it. It is built for a business owner who does not have
a cybersecurity department and does not want to read a technical report.

Built for **41909 Cybersecurity Capstone Studio** (UTS) by SEDE Studios.

---

## What it does

| | |
|---|---|
| **Scans** | Encryption and certificates, security headers, cookies, exposed files, form security, software versions, server configuration |
| **Explains** | Every finding gets *what it means*, *why it matters to your business*, and numbered fix steps |
| **Rates** | CVSS v3.1 severity, OWASP Top 10 category, and a single security score out of 950 |
| **Reports** | A PDF written for a business owner: score, action plan, findings, methodology and limitations |
| **Tracks** | Scan history, score trend, and per-finding "I have fixed this" so the score improves as you act |

Everything runs on the user's own computer. No account, no cloud service, no
data leaves the machine.

---

## Installing (end users)

Download **`SiteScope-Setup.exe`** from the
[Releases page](../../releases) and run it. It installs per-user, so no
administrator password is needed.

Alternatively download **`SiteScope.exe`** and run it directly — it needs
nothing else installed, not even Python.

**Requirements:** Windows 10 or later, 64-bit.

---

## Building the executable yourself

### Option A — let GitHub build it (no Windows machine needed)

Push to `main`, or push a tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The `Build Windows executable` workflow runs the test suite on Ubuntu, then
builds and smoke-tests `SiteScope.exe` and `SiteScope-Setup.exe` on a Windows
runner. Tagged builds are attached to a GitHub Release; every other build is
available under **Actions → the run → Artifacts**.

### Option B — build locally on Windows

Download the project, open the `build` folder, and **double-click
`build.bat`**. It checks Python is present, sets everything up, builds, and
leaves the window open so you can read the result.

From a terminal instead:

```bat
cd sitescope
build\build.bat
```

Produces `dist\SiteScope.exe`, plus `dist\SiteScope-Setup.exe` if
[Inno Setup 6](https://jrsoftware.org/isdl.php) is installed.

**Requires:** Python 3.10+ with "Add Python to PATH" ticked at install time.

---

## Running from source (development)

```bash
python -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

python run_dev.py                 # http://127.0.0.1:8731/
```

Or run it exactly as the packaged app does, in its own desktop window:

```bash
python -m sitescope
```

Useful flags: `--port N`, `--no-window` (service only), `--browser` (use the
default browser instead of an app window), `--version`.

### Tests

```bash
pytest
```

411 tests covering scoring, the knowledge base, URL handling, every scanner
check against a deliberately insecure local site, and the full API. The
insecure sample site is `tests/vulnerable_target.py`; you can also run it
standalone (`python tests/vulnerable_target.py 8099`) and scan
`http://127.0.0.1:8099/` from the interface to demonstrate the tool safely.

---

## How it is put together

```
main.py                   Entry point PyInstaller builds from (see note below)
CONTRIBUTING.md           How to make a change safely, and where to document it
CHANGELOG.md              What changed between versions, written for the user
sitescope/
├── __main__.py           Desktop launcher: local server + chromeless window
├── app.py                Flask routes and JSON API
├── config.py             Settings and per-user data paths
├── db.py                 SQLite storage for scans, findings, reports
├── models.py             Finding and ScanResult, CVSS severity bands
├── scan_manager.py       Runs a scan on a background thread, streams progress
├── demo.py               Seeded sample data (removable in Settings)
├── scanner/
│   ├── engine.py         ScanEngine interface + BuiltinEngine ("VulnGuard")
│   ├── base.py           ScanContext, Page, rate limiting, BaseCheck
│   ├── crawler.py        Polite same-host crawler, honours robots.txt
│   ├── knowledge.py      The knowledge base: CVSS, OWASP, plain-language advice
│   ├── scoring.py        Security score out of 950 and letter grade
│   └── checks/           One module per family of checks
├── reporting/pdf.py      PDF report generation (reportlab)
└── web/                  Templates, stylesheet, charts, front-end logic
```

### Why a local web interface rather than a desktop widget toolkit

The interface is a Flask service bound to `127.0.0.1`, displayed in a
chromeless Edge or Chrome window (`--app=` mode). Closing the window quits the
application, so it behaves like any other desktop program.

Every dependency ships prebuilt Windows wheels and none of them is a GUI
toolkit, which is what makes the PyInstaller build reproducible on a clean
Windows runner and keeps the executable small — no Qt, no WebView2 runtime,
nothing to install alongside it. It also renders the designed dashboard
identically on every machine.

### Why the build entry point is `main.py`

PyInstaller runs its entry script as `__main__`, which leaves `__package__`
empty — so a script using relative imports fails at startup with *"attempted
relative import with no known parent package"*. `sitescope/__main__.py` uses
relative imports, so building from it directly produces an `.exe` that crashes
the moment it is launched, while `python -m sitescope` keeps working perfectly
during development.

`main.py` exists to avoid that: it is a plain top-level script that imports the
launcher by its absolute package name. `tests/test_packaging.py` runs it as a
script to reproduce the exact packaging condition, so this cannot regress
unnoticed.

### The knowledge base is the product

`scanner/knowledge.py` is where the value lives. Detecting a missing header is
easy; explaining to a bakery owner why it matters and what to do about it is
the hard part. Every entry carries a CVSS base score, an OWASP Top 10 (2021)
category, a jargon-free explanation, a business-impact statement, ordered
remediation steps, a difficulty rating, and a flag for whether a professional
should be involved.

`tests/test_knowledge.py` enforces this: an entry with fewer than two
remediation steps, a thin explanation, or security jargon in its description
fails the build.

### Adding a new check

1. Add an entry to `KNOWLEDGE` in `scanner/knowledge.py`.
2. Add a `BaseCheck` subclass in `scanner/checks/`, returning
   `build_finding("your-check-id", url, evidence=...)`.
3. Register it in `scanner/checks/__init__.py`.
4. Add it to `hiddenimports` in `build/sitescope.spec` — dynamically imported
   modules are invisible to PyInstaller, so without this the check would be
   missing from the packaged app. `tests/test_packaging.py` enforces it.
5. Plant the weakness in `tests/vulnerable_target.py` and add its id to the
   detection test in `tests/test_scanner.py`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow.

### Adding OWASP ZAP later

`ScanEngine` in `scanner/engine.py` is a `Protocol`, and `get_engine()` is the
single place an engine is chosen. A `ZapEngine` would drive a local ZAP daemon
through its REST API and translate ZAP alerts into `Finding` objects using the
same knowledge base. Nothing outside that module changes, because the rest of
the application only ever sees `ScanResult` and `Finding`.

The built-in engine exists so the application is useful with nothing else
installed — ZAP needs Java and a separate ~500 MB install, which is a poor fit
for the audience.

---

## Scanning behaviour and ethics

SiteScope performs a **passive** assessment. It requests pages the way a
browser or search engine would and analyses the responses. It does not inject
payloads, submit data, modify anything, or attempt to access accounts.

Built-in safeguards:

- **Authorisation gate** — a scan cannot start until the user confirms they own
  the site or have written permission. Enforced server-side, not just in the
  interface.
- **Rate limiting** — 5 requests per second by default, so a scan never
  resembles a denial of service.
- **robots.txt** — honoured by default.
- **Same-host only** — the crawler never leaves the target's hostname.
- **Page budget** — 25 pages by default, adjustable in Settings.
- **One scan at a time.**

> Scanning a website without the owner's permission may be unlawful — in
> Australia under Part 10.7 of the Commonwealth *Criminal Code Act 1995*, and
> under comparable legislation elsewhere.

## Known limitations

These are stated in the app and in every PDF report, and they matter:

- Only publicly reachable pages are assessed — not logged-in areas, business
  logic, payment flows, or the security of the server and hosting account.
- Weaknesses that only appear when data is submitted (injection flaws in a
  search or checkout, for example) cannot be detected by a passive scan.
- Version-based findings infer risk from a published version number and are
  marked *Medium* confidence.
- A clear result means nothing was found in the areas SiteScope checks. It is
  not a guarantee that a site is secure. Sites handling payments or sensitive
  personal data should also be assessed by a qualified professional.

---

## Where your data lives

| | |
|---|---|
| Windows | `%LOCALAPPDATA%\SiteScope\` |
| macOS | `~/Library/Application Support/SiteScope/` |
| Linux | `~/.local/share/SiteScope/` |

Contains `sitescope.db` (scans and findings), `reports/` (generated PDFs) and
`settings.json`. The uninstaller deliberately leaves this alone — deleting
someone's security records without asking would be the wrong default. The exact
path is shown in the app under **Settings**.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to set up, make a change, and
where each kind of documentation belongs. Version history is in
[CHANGELOG.md](CHANGELOG.md).

## Licence

MIT — see [LICENSE](LICENSE), including the notice on responsible use.
