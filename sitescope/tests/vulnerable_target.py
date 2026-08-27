"""A deliberately insecure website used to exercise the SiteScope scanner.

Run with:  python tests/vulnerable_target.py [port]

It binds to 127.0.0.1 only and serves fabricated content. It exists so the
scanner can be tested end to end without pointing it at anything real.

Issues it intentionally exhibits:
  * no security headers at all
  * cookies without Secure / HttpOnly / SameSite
  * a password form posted over plain HTTP
  * mixed content references
  * an exposed .env and .git/HEAD
  * a browsable /uploads/ directory
  * a phpinfo-style diagnostic page
  * a version-disclosing Server banner and generator meta tag
  * wildcard CORS with credentials
  * developer comments containing a password
  * a visible database error message
"""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = """<!doctype html>
<html><head>
<title>Corner Bakery - Home</title>
<meta name="generator" content="WordPress 5.4.2">
<!-- TODO: remove before launch - staging admin password is Bakery2019! -->
</head>
<body>
<h1>Corner Bakery</h1>
<p>Fresh bread daily. Contact us at orders@cornerbakery.example or accounts@cornerbakery.example</p>
<img src="http://cdn.cornerbakery.example/logo.png" alt="logo">
<script src="http://cdn.cornerbakery.example/tracker.js"></script>
<ul>
  <li><a href="/about">About</a></li>
  <li><a href="/contact">Contact</a></li>
  <li><a href="/account">My Account</a></li>
  <li><a href="/wp-login.php">Staff login</a></li>
</ul>
</body></html>"""

CONTACT = """<!doctype html>
<html><head><title>Contact - Corner Bakery</title></head><body>
<h1>Contact us</h1>
<form method="POST" action="/submit">
  <input type="text" name="name" placeholder="Your name">
  <input type="email" name="email" placeholder="Email">
  <textarea name="message"></textarea>
  <button type="submit">Send</button>
</form>
</body></html>"""

LOGIN = """<!doctype html>
<html><head><title>Staff login</title></head><body>
<h1>Staff login</h1>
<form method="POST" action="/wp-login.php">
  <input type="text" name="log">
  <input type="password" name="pwd">
  <button type="submit">Log In</button>
</form>
</body></html>"""

ACCOUNT = """<!doctype html>
<html><head><title>My Account</title></head><body>
<h1>My Account</h1>
<p>Welcome back. <a href="/logout">Log out</a></p>
<p>Billing address on file.</p>
<p>Warning: mysql_query(): Access denied for user 'bakery'@'localhost' in /var/www/html/inc/db.php on line 42</p>
</body></html>"""

ABOUT = """<!doctype html>
<html><head><title>About - Corner Bakery</title></head><body>
<h1>About us</h1><p>Family owned since 1998.</p>
<a href="/contact">Contact</a>
</body></html>"""

UPLOADS = """<!doctype html>
<html><head><title>Index of /uploads</title></head><body>
<h1>Index of /uploads</h1>
<pre>
<a href="../">../</a>
<a href="customer-list-2025.xlsx">customer-list-2025.xlsx</a>
<a href="staff-roster.pdf">staff-roster.pdf</a>
<a href="invoice-template.docx">invoice-template.docx</a>
</pre>
</body></html>"""

PHPINFO = """<!doctype html><html><head><title>phpinfo()</title></head><body>
<h1>PHP Version 7.2.11</h1>
<table><tr><td>System</td><td>Linux web01 5.4.0</td></tr>
<tr><td>Loaded Configuration File</td><td>/etc/php/7.2/apache2/php.ini</td></tr></table>
</body></html>"""

ENV_FILE = """APP_ENV=production
APP_DEBUG=true
DB_HOST=localhost
DB_DATABASE=bakery_prod
DB_USERNAME=bakery
DB_PASSWORD=SuperSecret123
STRIPE_SECRET=sk_live_51H8xExampleKeyNotReal
MAIL_PASSWORD=hunter2
"""

NOT_FOUND = """<!doctype html>
<html><head><title>Page not found - Corner Bakery</title></head>
<body><h1>Sorry, we could not find that page.</h1></body></html>"""

ROBOTS = """User-agent: *
Disallow: /admin/
Disallow: /internal-reports/
Disallow: /wp-admin/
Allow: /
"""

ROUTES: dict[str, tuple[str, str]] = {
    "/": (HOME, "text/html"),
    "/about": (ABOUT, "text/html"),
    "/contact": (CONTACT, "text/html"),
    "/account": (ACCOUNT, "text/html"),
    "/wp-login.php": (LOGIN, "text/html"),
    "/uploads/": (UPLOADS, "text/html"),
    "/phpinfo.php": (PHPINFO, "text/html"),
    "/.env": (ENV_FILE, "text/plain"),
    "/.git/HEAD": ("ref: refs/heads/main\n", "text/plain"),
    "/.git/config": ("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
                     "\turl = git@github.com:cornerbakery/site.git\n", "text/plain"),
    "/robots.txt": (ROBOTS, "text/plain"),
}


class VulnerableHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.29"
    sys_version = "(Ubuntu) PHP/7.2.11"

    def do_GET(self):  # noqa: N802 - required by BaseHTTPRequestHandler
        path = self.path.split("?", 1)[0]
        body, content_type = ROUTES.get(path, (NOT_FOUND, "text/html"))
        status = 200 if path in ROUTES else 404
        self._respond(status, body, content_type)

    def do_OPTIONS(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Allow", "GET, POST, HEAD, OPTIONS, TRACE, PUT, DELETE")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):  # noqa: N802
        self._respond(200, "<html><body>Thanks!</body></html>", "text/html")

    def _respond(self, status: int, body: str, content_type: str):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Powered-By", "PHP/7.2.11")
        # Deliberately permissive cross-origin policy.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        # Deliberately unprotected cookies.
        self.send_header("Set-Cookie", "PHPSESSID=abc123def456; Path=/")
        self.send_header("Set-Cookie", "user_pref=dark; Path=/")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt, *args):
        pass  # keep the test output readable


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    server = ThreadingHTTPServer(("127.0.0.1", port), VulnerableHandler)
    print(f"Deliberately insecure test site running at http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
