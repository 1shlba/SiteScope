# Working on SiteScope

Short guide for the team. The aim is that anyone can pick up the project, make
a change safely, and leave a record of why.

## Get set up

```bat
git clone <this-repo>
cd sitescope
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt

python run_dev.py          http://127.0.0.1:8731/
```

To try a scan without touching a real website, run the deliberately insecure
sample site in a second terminal and point SiteScope at it:

```bat
python tests\vulnerable_target.py 8099
```

Then scan `http://127.0.0.1:8099/`. It produces 24 findings and a grade F.

## Make a change

1. **Branch.** Never commit straight to `main`.

   ```
   feature/zap-adapter        new capability
   fix/cookie-parsing         something is broken
   docs/readme-install        documentation only
   ```

2. **Write the change, and a test for it.** If you are adding a security check,
   plant the weakness in `tests/vulnerable_target.py` and assert it is detected
   in `tests/test_scanner.py`. A check with no test will eventually stop working
   and nobody will notice.

3. **Run the tests before you open the pull request.**

   ```bat
   pytest
   ```

   All 411 must pass. If you added a vulnerability entry, `test_knowledge.py`
   will also check it has real remediation steps and no jargon — that is
   deliberate, not an obstacle.

4. **Commit with a message that says why.** The subject line completes the
   sentence *"This commit will…"*.

   ```
   Add expiry parsing for untrusted certificates
   Stop the cache check firing on navigation links
   ```

   not `update transport.py` or `fixes`.

5. **Open a pull request** and ask someone to review it. The template prompts
   you for what changed and why.

6. **Merge once the checks pass.** GitHub Actions runs the whole suite on your
   pull request before you merge, which is the point of it.

## Where each kind of writing goes

| | |
|---|---|
| **Commit message** | Why this specific change was made |
| **Pull request** | Why this piece of work was done, and the review discussion |
| **Issue** | Something to do or something broken, before anyone works on it |
| **CHANGELOG.md** | What changed between versions, written for the user |
| **README.md** | What the project *is now* — always current, not a history |
| **Code comments** | Why the code is like this, where it is not obvious |
| **LabArchives** | Your own reflection and learning record for assessment |

GitHub holds the engineering record. LabArchives holds the reflection that
points at it — they are not substitutes for each other.

## Adding a security check

1. Add an entry to `KNOWLEDGE` in `sitescope/scanner/knowledge.py`, with a CVSS
   score, OWASP category, plain-language explanation, business impact and
   ordered fix steps.
2. Add a `BaseCheck` subclass in `sitescope/scanner/checks/`.
3. Register it in `sitescope/scanner/checks/__init__.py`.
4. Add it to `hiddenimports` in `build/sitescope.spec` — dynamically imported
   modules are invisible to PyInstaller, and `tests/test_packaging.py` will fail
   until you do. Without it the check would simply never run in the packaged app.
5. Plant the weakness in `tests/vulnerable_target.py` and assert detection in
   `tests/test_scanner.py`.
6. Add a line to `CHANGELOG.md` under `[Unreleased]`.

## Two rules that matter more than the rest

**Never commit scan data.** Databases, generated reports and settings are all
in `.gitignore`. Scan results describe exploitable weaknesses in real websites,
and a repository is the wrong place for them.

**Keep the explanations jargon-free.** The whole product is the difference
between "missing X-Frame-Options" and "someone can put an invisible copy of your
site over their own buttons". If a small business owner could not act on what
you wrote, it is not finished.

## Cutting a release

1. Move `[Unreleased]` entries in `CHANGELOG.md` under a new version heading
   with today's date.
2. Update `__version__` in `sitescope/__init__.py`, and the version numbers in
   `build/version_info.txt` and `build/installer.iss`.
3. Merge to `main`.
4. On GitHub: **Releases → Create a new release**, tag `v1.1.0`, publish. The
   build runs and attaches `SiteScope.exe` and `SiteScope-Setup.exe` to it.
