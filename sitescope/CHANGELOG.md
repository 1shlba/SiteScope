# Changelog

All notable changes to SiteScope are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/): given
`MAJOR.MINOR.PATCH`, bump

- **PATCH** for a bug fix that changes nothing else (`1.0.0` → `1.0.1`)
- **MINOR** for a new capability that breaks nothing (`1.0.1` → `1.1.0`)
- **PATCH/MINOR** — most student-project changes are one of these
- **MAJOR** only for a change that breaks how the app is used (`1.1.0` → `2.0.0`)

Write entries for the person using SiteScope, not for the person who wrote the
code: *"Scan results now show which issues a professional should handle"*, not
*"added needs_professional to Finding"*.

Group each entry under **Added**, **Changed**, **Fixed**, **Removed**, or
**Security**. Put work that is finished but not yet released under
`[Unreleased]`, then rename that heading when you cut the version.

---

## [Unreleased]

Nothing yet. Add entries here as work merges into `main`.

---

## [1.0.0] — 2026-08-27

First working release. Packaged as a Windows executable and verified on
Windows 11 x64.

### Added

- Website scanning across seven areas: encryption and certificates, HTTP
  security headers, cookie protection, page content and forms, publicly exposed
  files, software version disclosure, and server configuration.
- Plain-language explanation for every finding — what it means, why it matters
  to the business, and numbered steps to fix it, with a difficulty rating and a
  flag for when a professional should be involved.
- Severity rated on the CVSS v3.1 scale and mapped to OWASP Top 10 (2021)
  categories.
- A single security score out of 950 with a letter grade, so a non-technical
  owner can track their posture over time.
- Five screens: Dashboard, New Scan, Scan History, Reports, Settings, plus a
  detailed results view per scan.
- Live scan progress with a streaming log feed, phase, request count and
  elapsed time.
- PDF report generation — executive summary, prioritised action plan, detailed
  findings, and a methodology and limitations section.
- Scan history in a local SQLite database, with per-finding "I have fixed this"
  that recalculates the score.
- Seeded sample data on first run, removable in one click from Settings.
- Windows packaging: `SiteScope.exe` via PyInstaller, `SiteScope-Setup.exe` via
  Inno Setup, and a GitHub Actions workflow that builds both on every push.

### Security

- Scanning is passive only. SiteScope requests pages the way a browser does and
  analyses the responses; it never injects payloads, submits data, modifies
  anything, or attempts to access accounts.
- A scan cannot start until the user confirms they own the target or have
  written permission. Enforced on the server, not only in the interface.
- Rate limited to 5 requests per second by default, restricted to the target's
  own hostname, honouring `robots.txt`, with a page budget and one scan at a
  time.
- Scan databases, generated reports and settings are excluded from version
  control — scan results describe real weaknesses in real websites.

### Fixed

Found by the test suite before the first release:

- Website addresses were not validated before being handed to the HTTP client,
  so input such as `javascript:alert(1)` was accepted.
- The crawler could leave its target: `ww.example.com` and `example.com`
  compared as the same host because a prefix was being stripped character by
  character rather than as a whole.
- The cache-policy check reported any page containing the words "My Account" in
  a navigation link, rather than only pages actually showing account content.
- Two reports generated for the same website within the same second overwrote
  each other.
- The packaged executable would have failed to start at all: PyInstaller runs
  its entry script in a way that breaks relative imports, which never shows up
  when running from source.
- `cryptography` and `Werkzeug` were used at runtime but not declared as
  dependencies, so certificate expiry details would have silently stopped
  working on a clean install.

[Unreleased]: https://github.com/
[1.0.0]: https://github.com/
