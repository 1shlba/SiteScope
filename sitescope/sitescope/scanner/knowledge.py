"""The vulnerability knowledge base.

Every check the scanner can raise has one entry here. The entry carries both
the technical classification (CVSS base score, OWASP Top 10 category) and the
plain-language explanation shown to a small-business owner who has no security
background.

Writing rules for entries in this file:
  * `what_it_means`  - describe the situation without jargon, one or two lines.
  * `why_it_matters` - describe the business consequence, not the technical one.
  * `how_to_fix`     - ordered, concrete steps someone can follow or hand to
                       their web developer. Avoid "configure X appropriately".
  * `difficulty`     - Easy (settings change), Moderate (needs a developer or
                       server access), Advanced (needs a specialist).

CVSS base scores follow the CVSS v3.1 qualitative bands. They are indicative
severities for the class of issue, not per-target calculated vectors.
OWASP references use the OWASP Top 10 (2021) category identifiers.
"""

from __future__ import annotations

from typing import Any

# OWASP Top 10 (2021) categories used across the knowledge base.
A01 = "A01:2021 Broken Access Control"
A02 = "A02:2021 Cryptographic Failures"
A03 = "A03:2021 Injection"
A04 = "A04:2021 Insecure Design"
A05 = "A05:2021 Security Misconfiguration"
A06 = "A06:2021 Vulnerable and Outdated Components"
A07 = "A07:2021 Identification and Authentication Failures"
A08 = "A08:2021 Software and Data Integrity Failures"
A09 = "A09:2021 Security Logging and Monitoring Failures"


KNOWLEDGE: dict[str, dict[str, Any]] = {

    # ----------------------------------------------------------------------
    # Encryption and certificates
    # ----------------------------------------------------------------------
    "tls-not-available": {
        "title": "Website does not use a secure (HTTPS) connection",
        "cvss": 7.5,
        "owasp": A02,
        "what_it_means": (
            "Your website is served over a plain, unencrypted connection. Anything typed "
            "into it travels across the internet as readable text."
        ),
        "why_it_matters": (
            "Anyone sharing a network with your customers - public Wi-Fi in a cafe, an "
            "airport, a hotel - can read what they send you, including contact forms, "
            "logins and payment details. Browsers also show a 'Not secure' warning next "
            "to your address, which drives customers away, and Google ranks insecure "
            "sites lower."
        ),
        "how_to_fix": [
            "Ask your hosting provider to enable a free Let's Encrypt SSL certificate - most hosts do this with one click in the control panel.",
            "Once it is active, set your site to redirect all visitors from http:// to https:// automatically.",
            "Update any hard-coded internal links, images and scripts in your site to use https://.",
            "Reload your site and confirm the padlock icon appears in the browser address bar.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    },

    "tls-cert-expired": {
        "title": "Security certificate has expired",
        "cvss": 7.4,
        "owasp": A02,
        "what_it_means": (
            "The certificate that proves your website is genuine has passed its expiry date."
        ),
        "why_it_matters": (
            "Visitors now see a full-page red browser warning telling them your site may be "
            "dangerous. Most people will leave immediately, and some browsers make it hard "
            "to continue at all. In practice your website is effectively offline for new "
            "customers until this is renewed."
        ),
        "how_to_fix": [
            "Renew the certificate through your hosting provider or certificate supplier - this is usually immediate.",
            "Turn on automatic renewal so it cannot lapse again (Let's Encrypt certificates renew every 90 days).",
            "Set a calendar reminder 30 days before the next expiry as a backup.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://letsencrypt.org/docs/",
    },

    "tls-cert-expiring": {
        "title": "Security certificate expires soon",
        "cvss": 3.7,
        "owasp": A02,
        "what_it_means": "Your website's security certificate is valid but will expire shortly.",
        "why_it_matters": (
            "If it lapses, every visitor will see a browser security warning and your site "
            "will appear broken. This is a routine renewal, but missing it causes a very "
            "visible outage."
        ),
        "how_to_fix": [
            "Check whether automatic renewal is enabled in your hosting control panel.",
            "If it is not, renew the certificate now and switch automatic renewal on.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://letsencrypt.org/docs/",
    },

    "tls-cert-hostname-mismatch": {
        "title": "Security certificate does not match this website address",
        "cvss": 7.4,
        "owasp": A02,
        "what_it_means": (
            "The certificate installed on your server was issued for a different web address "
            "than the one visitors are using."
        ),
        "why_it_matters": (
            "Browsers cannot confirm the site is really yours, so visitors get a security "
            "warning. This is also exactly what an impersonation attack looks like, so the "
            "warning cannot safely be ignored."
        ),
        "how_to_fix": [
            "Check which addresses the certificate covers - it should list your domain both with and without 'www.'.",
            "Ask your host to reissue the certificate covering every address your site answers on.",
            "If you use a subdomain such as shop.yourbusiness.com, make sure it is included too.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security",
    },

    "tls-cert-self-signed": {
        "title": "Security certificate is not from a recognised authority",
        "cvss": 6.5,
        "owasp": A02,
        "what_it_means": (
            "Your site uses a certificate it generated itself, rather than one issued by a "
            "trusted certificate authority that browsers recognise."
        ),
        "why_it_matters": (
            "The connection is encrypted, but no independent party has verified that the "
            "site belongs to you, so every visitor sees a security warning. Self-signed "
            "certificates are fine for internal testing and unsuitable for a public site."
        ),
        "how_to_fix": [
            "Replace it with a free Let's Encrypt certificate, or one from your hosting provider.",
            "Remove the self-signed certificate from the server configuration once the new one is live.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://letsencrypt.org/getting-started/",
    },

    "tls-weak-protocol": {
        "title": "Website accepts outdated encryption standards",
        "cvss": 5.9,
        "owasp": A02,
        "what_it_means": (
            "Your server still allows old encryption methods (TLS 1.0 or 1.1) that have "
            "known weaknesses and were retired by the industry in 2020."
        ),
        "why_it_matters": (
            "An attacker positioned on the network can push a visitor's browser onto the "
            "weaker method and then work on decrypting the traffic. It will also fail PCI "
            "DSS compliance checks if you take card payments."
        ),
        "how_to_fix": [
            "Ask your hosting provider to disable TLS 1.0 and TLS 1.1 and allow only TLS 1.2 and 1.3.",
            "Most hosts have a one-line setting or a control panel toggle for this.",
            "Re-run this scan afterwards to confirm the old versions are refused.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://www.ssllabs.com/projects/best-practices/",
    },

    "tls-no-redirect": {
        "title": "Insecure connections are not redirected to the secure site",
        "cvss": 5.3,
        "owasp": A02,
        "what_it_means": (
            "Your site works over HTTPS, but visitors who arrive at the plain http:// "
            "address stay on the unencrypted version instead of being moved across."
        ),
        "why_it_matters": (
            "Most people type your address without 'https', so they silently end up on the "
            "unprotected version. Everything they submit on that page is readable in transit, "
            "which defeats the certificate you already paid for."
        ),
        "how_to_fix": [
            "Turn on 'Force HTTPS' or 'Always use HTTPS' in your hosting control panel - most providers offer this as a switch.",
            "If your host does not offer it, ask them to add a permanent (301) redirect from http:// to https://.",
            "Test by typing your address without https:// and confirming the padlock appears.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },

    # ----------------------------------------------------------------------
    # Security headers
    # ----------------------------------------------------------------------
    "header-missing-hsts": {
        "title": "Browsers are not told to always use the secure connection",
        "cvss": 4.3,
        "owasp": A05,
        "what_it_means": (
            "Your site does not send the HSTS instruction, which tells a browser to only "
            "ever connect securely to your domain in future."
        ),
        "why_it_matters": (
            "Without it, a returning visitor's very first request each time can still be "
            "made insecurely, and that moment is enough for an attacker on the same network "
            "to intercept and redirect them to a fake copy of your site."
        ),
        "how_to_fix": [
            "Confirm your whole site works over HTTPS first - this setting is difficult to undo.",
            "Ask your developer or host to add the response header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            "Start with a shorter max-age (for example 86400) for a week if you want to test cautiously.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-secure-headers/",
    },

    "header-missing-csp": {
        "title": "No content security policy is set",
        "cvss": 5.4,
        "owasp": A05,
        "what_it_means": (
            "Your site does not tell browsers which sources of scripts and content are "
            "allowed, so a browser will run any script that appears on the page."
        ),
        "why_it_matters": (
            "If an attacker manages to slip code into your site - through a comment box, a "
            "compromised plugin or an advert - it will run with full access to your visitors' "
            "session. This is the main defence against that class of attack, and it is missing."
        ),
        "how_to_fix": [
            "Ask your developer to add a Content-Security-Policy header, starting in report-only mode so nothing breaks.",
            "Begin with a policy such as: default-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
            "Review the reported violations for a week, add the legitimate sources you use (payment providers, analytics, fonts), then switch it from report-only to enforcing.",
        ],
        "difficulty": "Advanced",
        "needs_professional": True,
        "reference": "https://owasp.org/www-project-secure-headers/#content-security-policy",
    },

    "header-missing-xfo": {
        "title": "Your site can be embedded inside another website",
        "cvss": 4.3,
        "owasp": A05,
        "what_it_means": (
            "Nothing stops another website from loading your pages inside an invisible frame "
            "on their own site."
        ),
        "why_it_matters": (
            "An attacker can put an invisible copy of your site over their own buttons, so a "
            "customer who thinks they are clicking something harmless is really clicking a "
            "button on your site - approving a change or a payment. This is called clickjacking."
        ),
        "how_to_fix": [
            "Ask your developer or host to add the response header: X-Frame-Options: DENY",
            "Also add frame-ancestors 'none' to your Content-Security-Policy, which is the modern equivalent.",
            "If a partner legitimately needs to embed your site, use frame-ancestors with their exact domain instead of removing the protection.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/www-community/attacks/Clickjacking",
    },

    "header-missing-xcto": {
        "title": "Browsers are allowed to guess file types",
        "cvss": 3.1,
        "owasp": A05,
        "what_it_means": (
            "Your server does not tell browsers to trust the file type it declares, so "
            "browsers will guess based on file contents."
        ),
        "why_it_matters": (
            "A file uploaded as an image can be re-interpreted by the browser as a script "
            "and executed. Where you accept uploads - profile pictures, document attachments "
            "- this turns a harmless upload into a way to run code on your visitors."
        ),
        "how_to_fix": [
            "Add the response header: X-Content-Type-Options: nosniff",
            "This is a single line in your server or CDN configuration and rarely breaks anything.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-secure-headers/",
    },

    "header-missing-referrer": {
        "title": "Your visitors' page addresses are shared with other sites",
        "cvss": 3.1,
        "owasp": A05,
        "what_it_means": (
            "When someone clicks a link away from your site, their browser tells the "
            "destination exactly which page they came from, including anything in the address."
        ),
        "why_it_matters": (
            "Addresses often contain private details - order numbers, password reset links, "
            "search terms, customer identifiers. Those get handed to every external site you "
            "link to, and to any advertising or analytics script on the page."
        ),
        "how_to_fix": [
            "Add the response header: Referrer-Policy: strict-origin-when-cross-origin",
            "This keeps analytics working while hiding the specific page address from third parties.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-secure-headers/",
    },

    "header-missing-permissions": {
        "title": "Camera, microphone and location access are not restricted",
        "cvss": 2.4,
        "owasp": A05,
        "what_it_means": (
            "Your site does not declare which device features it uses, so embedded content "
            "such as adverts or widgets may request access to a visitor's camera, microphone "
            "or location."
        ),
        "why_it_matters": (
            "A visitor sees the permission prompt attached to your brand. Even if they decline, "
            "an unexpected request for camera or location access damages trust in your business."
        ),
        "how_to_fix": [
            "Add the response header: Permissions-Policy: geolocation=(), microphone=(), camera=()",
            "If your site genuinely uses one of these - a store locator, for example - allow just that one with geolocation=(self).",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-secure-headers/",
    },

    "header-csp-weak": {
        "title": "Content security policy is too permissive to be effective",
        "cvss": 4.0,
        "owasp": A05,
        "what_it_means": (
            "You have a content security policy, but it allows unsafe inline scripts or "
            "content from any source, which cancels out most of its protection."
        ),
        "why_it_matters": (
            "The policy gives the appearance of protection without delivering it. An attacker "
            "who injects a script into your page would still have it executed by the browser."
        ),
        "how_to_fix": [
            "Ask your developer to remove 'unsafe-inline' and wildcard (*) sources from the policy.",
            "Move inline scripts into separate files, or use nonces so only your own scripts are allowed.",
            "Re-test in report-only mode before enforcing the tightened policy.",
        ],
        "difficulty": "Advanced",
        "needs_professional": True,
        "reference": "https://owasp.org/www-project-secure-headers/#content-security-policy",
    },

    # ----------------------------------------------------------------------
    # Cookies
    # ----------------------------------------------------------------------
    "cookie-missing-secure": {
        "title": "Login cookie can be sent over an insecure connection",
        "cvss": 5.3,
        "owasp": A02,
        "what_it_means": (
            "A cookie your site uses is not marked 'Secure', so the browser will send it "
            "over an unencrypted connection as well as a secure one."
        ),
        "why_it_matters": (
            "Cookies are what keep a customer or an administrator signed in. If one is sent "
            "unencrypted even once, somebody watching the network can copy it and take over "
            "that session without ever needing the password."
        ),
        "how_to_fix": [
            "Ask your developer to add the Secure flag to every cookie the site sets.",
            "In most content management systems this is a setting rather than code - in WordPress, define('FORCE_SSL_ADMIN', true); in wp-config.php.",
            "Confirm the whole site is on HTTPS first, or the cookies will stop working.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://owasp.org/www-community/controls/SecureCookieAttribute",
    },

    "cookie-missing-httponly": {
        "title": "Login cookie is readable by scripts on the page",
        "cvss": 5.3,
        "owasp": A05,
        "what_it_means": (
            "A cookie is not marked 'HttpOnly', which means any JavaScript running on your "
            "page can read its value."
        ),
        "why_it_matters": (
            "If a malicious script ever reaches your site - through a plugin, an advert or a "
            "compromised third-party widget - it can quietly copy signed-in sessions and send "
            "them to an attacker."
        ),
        "how_to_fix": [
            "Ask your developer to add the HttpOnly flag to session and authentication cookies.",
            "Leave it off only for cookies your own front-end scripts genuinely need to read, such as a cookie-banner preference.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://owasp.org/www-community/HttpOnly",
    },

    "cookie-missing-samesite": {
        "title": "Cookie is sent when other websites make requests to yours",
        "cvss": 3.5,
        "owasp": A01,
        "what_it_means": (
            "A cookie has no SameSite setting, so the browser attaches it even when the "
            "request comes from a different website."
        ),
        "why_it_matters": (
            "Someone can build a page that quietly submits a request to your site while a "
            "signed-in customer visits it, and your site will treat it as a genuine action - "
            "changing an email address or placing an order. This is called cross-site request "
            "forgery."
        ),
        "how_to_fix": [
            "Ask your developer to set SameSite=Lax on cookies (or SameSite=Strict for admin sessions).",
            "If a payment provider needs the cookie on a cross-site return, use SameSite=None together with the Secure flag for that specific cookie only.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://owasp.org/www-community/SameSite",
    },

    # ----------------------------------------------------------------------
    # Page content
    # ----------------------------------------------------------------------
    "mixed-content": {
        "title": "Secure page loads some content insecurely",
        "cvss": 4.3,
        "owasp": A02,
        "what_it_means": (
            "The page itself is encrypted, but it pulls in images, scripts or stylesheets "
            "over an unencrypted connection."
        ),
        "why_it_matters": (
            "The padlock is misleading - the insecure parts can be swapped out in transit. If "
            "a script is affected, an attacker can change anything on the page, including "
            "where your payment form submits to. Browsers also block this content, which often "
            "breaks the page's appearance."
        ),
        "how_to_fix": [
            "Find the insecure items listed in the evidence for this finding.",
            "Change their addresses from http:// to https:// in your page templates or content.",
            "For a content management system, a search-and-replace plugin can update old links across the whole database in one step.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://developer.mozilla.org/docs/Web/Security/Mixed_content",
    },

    "form-insecure-action": {
        "title": "A form on your site submits data insecurely",
        "cvss": 7.5,
        "owasp": A02,
        "what_it_means": (
            "A form on your website sends what visitors type to an unencrypted address."
        ),
        "why_it_matters": (
            "Everything entered into that form - names, phone numbers, messages, possibly "
            "passwords or card details - travels in readable text. Anyone on the same network "
            "can capture it. If it collects personal information, this is likely a notifiable "
            "data breach risk under Australian privacy law."
        ),
        "how_to_fix": [
            "Change the form's destination address from http:// to https:// in your page template.",
            "Reload the page and submit a harmless test entry to confirm it still works.",
            "If the form posts to an external service, contact that provider for their secure endpoint address.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
    },

    "password-over-http": {
        "title": "Password is entered on an unencrypted page",
        "cvss": 8.2,
        "owasp": A02,
        "what_it_means": (
            "A page that asks for a password is served over a plain, unencrypted connection."
        ),
        "why_it_matters": (
            "Passwords typed here are transmitted in readable text and can be captured by "
            "anyone on the same network. Because people reuse passwords, a single capture "
            "often opens their email and banking too. Browsers also display a prominent "
            "'Not secure' warning directly on the password box."
        ),
        "how_to_fix": [
            "Enable HTTPS on your site as an immediate priority - free certificates are available from your host.",
            "Redirect all traffic to the secure version of the site.",
            "Ask any staff or customers who signed in recently over the insecure page to change their password.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    },

    "form-no-csrf-token": {
        "title": "Form has no protection against forged submissions",
        "cvss": 4.3,
        "owasp": A01,
        "what_it_means": (
            "A form that changes something on your site does not include a hidden one-time "
            "token that proves the submission genuinely came from your own page."
        ),
        "why_it_matters": (
            "Another website can trigger that form on behalf of a signed-in visitor without "
            "their knowledge. Depending on what the form does, that could change account "
            "details, post content or place an order."
        ),
        "how_to_fix": [
            "If you use a content management system, this is usually handled for you - check the form is built with the platform's own form builder rather than hand-written HTML.",
            "For custom forms, ask your developer to add CSRF token protection (most web frameworks include it as a built-in feature).",
            "Set SameSite=Lax on your session cookies as an additional layer.",
        ],
        "difficulty": "Advanced",
        "needs_professional": True,
        "reference": "https://owasp.org/www-community/attacks/csrf",
    },

    # ----------------------------------------------------------------------
    # Exposed files and directories
    # ----------------------------------------------------------------------
    "exposed-git": {
        "title": "Your website's source code repository is publicly downloadable",
        "cvss": 9.8,
        "owasp": A05,
        "what_it_means": (
            "The hidden .git folder used by developers is accessible from the internet. It "
            "contains a complete copy of your website's source code and its full history."
        ),
        "why_it_matters": (
            "Anyone can download your entire codebase, including passwords, database "
            "credentials and API keys that were committed at any point - even if they were "
            "later removed from the current version. This is one of the most damaging "
            "misconfigurations there is, and automated bots scan for it constantly."
        ),
        "how_to_fix": [
            "Block access to the .git folder immediately - your host can add a rule denying all requests to paths containing '.git'.",
            "Treat every password, database credential and API key in that repository as compromised and change them all.",
            "Change how you deploy the site so the .git folder is never uploaded to the web server in the first place.",
            "This one warrants professional help if you are not sure what was exposed.",
        ],
        "difficulty": "Advanced",
        "needs_professional": True,
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },

    "exposed-env": {
        "title": "Configuration file containing passwords is publicly readable",
        "cvss": 9.8,
        "owasp": A05,
        "what_it_means": (
            "A configuration file (such as .env) is downloadable from your website. These "
            "files hold database passwords, email credentials and payment provider keys."
        ),
        "why_it_matters": (
            "Anyone who finds this file gets direct access to your database and any connected "
            "service. It is the equivalent of leaving your keys in the front door. Automated "
            "bots check for this file on every site they encounter."
        ),
        "how_to_fix": [
            "Move the file outside your website's public folder immediately, or block access to it at the server.",
            "Change every password and key stored in that file - assume all of them are known.",
            "Check your database and email accounts for unfamiliar activity.",
            "Engage a security professional to check whether anything was accessed.",
        ],
        "difficulty": "Advanced",
        "needs_professional": True,
        "reference": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },

    "exposed-backup": {
        "title": "Backup or archive file is publicly downloadable",
        "cvss": 7.5,
        "owasp": A05,
        "what_it_means": (
            "A backup file was left in your website's public folder and anyone can download it."
        ),
        "why_it_matters": (
            "Backups usually contain the whole site, and often a copy of the database with "
            "customer records. Downloading it gives an attacker everything at once, without "
            "needing to break into anything."
        ),
        "how_to_fix": [
            "Delete the file from the web server now.",
            "Store future backups outside the public web folder, or in your host's backup service.",
            "Check your server access logs to see whether the file was downloaded, and by whom.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },

    "exposed-database-dump": {
        "title": "Database export is publicly downloadable",
        "cvss": 9.1,
        "owasp": A05,
        "what_it_means": (
            "A database export file is sitting in a public folder on your website and can be "
            "downloaded by anyone."
        ),
        "why_it_matters": (
            "This file typically contains every customer record you hold - names, email "
            "addresses, order history and password hashes. If it has been downloaded, you are "
            "likely dealing with a reportable data breach under the Notifiable Data Breaches "
            "scheme."
        ),
        "how_to_fix": [
            "Remove the file from the web server immediately.",
            "Check server access logs to determine whether it was downloaded.",
            "Speak to a security professional and review your obligations with the Office of the Australian Information Commissioner if customer data was included.",
            "Force a password reset for all user accounts.",
        ],
        "difficulty": "Advanced",
        "needs_professional": True,
        "reference": "https://www.oaic.gov.au/privacy/notifiable-data-breaches",
    },

    "exposed-config-file": {
        "title": "Server configuration file is readable",
        "cvss": 6.5,
        "owasp": A05,
        "what_it_means": (
            "A configuration file that should be private is being served as a readable file "
            "instead of being processed by the server."
        ),
        "why_it_matters": (
            "These files describe how your site is put together and often contain internal "
            "paths, connection settings or credentials. They give an attacker a detailed map "
            "before they try anything."
        ),
        "how_to_fix": [
            "Ask your host to block direct web access to configuration file types.",
            "Move sensitive settings out of the public web folder.",
            "Review any credentials the file contained and rotate them.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },

    "directory-listing": {
        "title": "Folder contents are publicly browsable",
        "cvss": 5.3,
        "owasp": A05,
        "what_it_means": (
            "A folder on your website shows a list of every file it contains, instead of a "
            "web page."
        ),
        "why_it_matters": (
            "Visitors can browse files you never intended to publish - old drafts, documents, "
            "spreadsheets, uploaded customer files. It also hands an attacker a complete "
            "inventory of what to look at next."
        ),
        "how_to_fix": [
            "Ask your host to turn off directory browsing (in Apache this is 'Options -Indexes').",
            "Add an empty index.html file to affected folders as an immediate stop-gap.",
            "Review what was listed and move anything private out of the public folder.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },

    "exposed-admin-panel": {
        "title": "Administrator login page is publicly reachable",
        "cvss": 3.7,
        "owasp": A07,
        "what_it_means": (
            "Your site's administration login page is accessible from anywhere on the internet "
            "at a well-known address."
        ),
        "why_it_matters": (
            "This is normal for most small business sites, but it means automated bots will "
            "continuously try common passwords against it. Without a lockout or a second "
            "factor, it is only a matter of time before a weak password is found."
        ),
        "how_to_fix": [
            "Turn on two-factor authentication for every administrator account - this alone stops almost all automated attacks.",
            "Install a plugin or host feature that locks out an address after several failed attempts.",
            "Make sure no account still uses the default 'admin' username, and that passwords are long and unique.",
            "If your host supports it, restrict the admin page to your own office IP address.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    },

    "exposed-phpinfo": {
        "title": "Server diagnostic page is publicly visible",
        "cvss": 7.5,
        "owasp": A05,
        "what_it_means": (
            "A diagnostic page that prints your server's full configuration is reachable from "
            "the internet."
        ),
        "why_it_matters": (
            "It reveals exact software versions, file paths, loaded modules and sometimes "
            "credentials. An attacker uses it to pick a known exploit that matches your exact "
            "setup, turning guesswork into a targeted attack."
        ),
        "how_to_fix": [
            "Delete the diagnostic file from your web server now - it is only ever needed temporarily during setup.",
            "Search the site for other similar test files left behind (info.php, test.php, phpinfo.php).",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },

    # ----------------------------------------------------------------------
    # Information disclosure
    # ----------------------------------------------------------------------
    "info-server-version": {
        "title": "Server software version is publicly advertised",
        "cvss": 3.1,
        "owasp": A05,
        "what_it_means": (
            "Your website announces the exact name and version number of the software it runs on."
        ),
        "why_it_matters": (
            "Attackers search the internet for sites running versions with known "
            "vulnerabilities. Publishing your version puts your site on that list. Hiding it "
            "does not fix an out-of-date server, but it removes you from easy target lists."
        ),
        "how_to_fix": [
            "Ask your host to hide version details (in Apache, ServerTokens Prod; in Nginx, server_tokens off).",
            "More importantly, confirm the software is actually up to date - this finding often points at an old version.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },

    "info-powered-by": {
        "title": "Technology stack is disclosed in page responses",
        "cvss": 2.6,
        "owasp": A05,
        "what_it_means": (
            "Your site sends headers naming the programming language or framework it uses, "
            "often with the version number."
        ),
        "why_it_matters": (
            "It narrows down which attacks are worth trying against you. On its own this is "
            "minor, but it makes every other weakness easier to find and exploit."
        ),
        "how_to_fix": [
            "Ask your developer to remove the X-Powered-By header (in PHP, set expose_php = Off).",
            "Check your framework's documentation for its equivalent setting.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-secure-headers/",
    },

    "info-outdated-component": {
        "title": "Website software appears to be out of date",
        "cvss": 7.5,
        "owasp": A06,
        "what_it_means": (
            "Your site reports a version of its content management system or framework that "
            "is behind the current release."
        ),
        "why_it_matters": (
            "Security fixes are published alongside each release, which also tells attackers "
            "exactly what is wrong with older versions. Out-of-date website software is the "
            "single most common way small business sites get compromised."
        ),
        "how_to_fix": [
            "Back up your site, then update the core software, themes and plugins to their current versions.",
            "Turn on automatic updates for security releases.",
            "Remove any plugins or themes you no longer use - inactive ones are still exploitable.",
            "Set a monthly reminder to check for updates.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    },

    "info-email-disclosure": {
        "title": "Email addresses are published in the page source",
        "cvss": 2.6,
        "owasp": A05,
        "what_it_means": "Email addresses appear in plain text within your website's pages.",
        "why_it_matters": (
            "Automated harvesters collect these for spam and, more seriously, for targeted "
            "phishing aimed at your staff. A published finance or admin address is a common "
            "starting point for invoice fraud."
        ),
        "how_to_fix": [
            "Replace published addresses with a contact form where practical.",
            "If an address must be shown, have your developer obfuscate it or render it with script.",
            "Brief staff whose addresses are public about invoice and payment redirection scams.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },

    "info-error-disclosure": {
        "title": "Detailed technical error messages are shown to visitors",
        "cvss": 5.3,
        "owasp": A05,
        "what_it_means": (
            "When something goes wrong, your site displays technical detail such as file "
            "paths, database queries or code traces to the visitor."
        ),
        "why_it_matters": (
            "These messages hand an attacker a map of your server's internals and often reveal "
            "database structure, which is the groundwork for a database injection attack. They "
            "also look alarming and unprofessional to customers."
        ),
        "how_to_fix": [
            "Turn off debug mode in your site's configuration (in WordPress, set WP_DEBUG to false; in PHP, display_errors = Off).",
            "Set up a friendly custom error page instead.",
            "Keep errors going to a private log file so your developer can still diagnose problems.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },

    "info-html-comments": {
        "title": "Developer notes are left in the page source",
        "cvss": 2.6,
        "owasp": A05,
        "what_it_means": (
            "Hidden comments in your page code contain notes that were meant for developers."
        ),
        "why_it_matters": (
            "Anyone can read them by viewing the page source. They sometimes mention test "
            "accounts, internal addresses, unfinished features or known problems - all useful "
            "to somebody probing your site."
        ),
        "how_to_fix": [
            "Review the comments listed in the evidence and remove any that mention credentials, internal systems or known issues.",
            "Have your build process strip comments from published pages.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },

    # ----------------------------------------------------------------------
    # Server configuration
    # ----------------------------------------------------------------------
    "cors-wildcard": {
        "title": "Any website is allowed to read data from your site",
        "cvss": 5.3,
        "owasp": A05,
        "what_it_means": (
            "Your site tells browsers that any other website is permitted to request and read "
            "its content."
        ),
        "why_it_matters": (
            "If part of your site returns customer or account data, another website can pull "
            "it and read the response. This becomes serious when combined with the setting "
            "that also sends cookies."
        ),
        "how_to_fix": [
            "Ask your developer to replace the wildcard (*) with the specific web addresses that genuinely need access.",
            "If nothing external needs access, remove the header entirely.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },

    "cors-credentials-wildcard": {
        "title": "Other websites can read your visitors' private data",
        "cvss": 8.1,
        "owasp": A01,
        "what_it_means": (
            "Your site allows other websites to make requests that include your visitors' "
            "login cookies, and to read the responses."
        ),
        "why_it_matters": (
            "A malicious page can silently read a signed-in customer's account details from "
            "your own site while they browse elsewhere. To your server the requests look "
            "completely legitimate."
        ),
        "how_to_fix": [
            "Ask your developer to restrict Access-Control-Allow-Origin to a specific list of trusted addresses.",
            "Never combine a wildcard origin with Access-Control-Allow-Credentials: true.",
            "Have this reviewed by a professional if your site exposes any customer account information.",
        ],
        "difficulty": "Advanced",
        "needs_professional": True,
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },

    "http-dangerous-methods": {
        "title": "Server accepts request types that should be disabled",
        "cvss": 5.3,
        "owasp": A05,
        "what_it_means": (
            "Your web server responds to request types such as TRACE, PUT or DELETE that a "
            "normal website has no use for."
        ),
        "why_it_matters": (
            "Depending on the type, these can allow files to be uploaded or removed on your "
            "server, or be used to steal cookies. They are enabled by default on some servers "
            "and are simply left on by mistake."
        ),
        "how_to_fix": [
            "Ask your host to allow only GET, POST and HEAD requests.",
            "In Apache this is TraceEnable Off plus a LimitExcept rule; your host can apply it.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },

    "cache-sensitive-page": {
        "title": "Private pages may be stored in shared caches",
        "cvss": 3.7,
        "owasp": A05,
        "what_it_means": (
            "A page that shows personal or account information does not tell browsers and "
            "proxies to avoid storing a copy."
        ),
        "why_it_matters": (
            "On a shared computer - a library, a hotel, a reception desk - the next person can "
            "press the back button and see the previous user's account page."
        ),
        "how_to_fix": [
            "Ask your developer to add Cache-Control: no-store to pages showing account or personal data.",
            "Apply it to login, account, checkout and order history pages.",
        ],
        "difficulty": "Moderate",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },

    "missing-security-txt": {
        "title": "No published way to report a security problem",
        "cvss": 0.0,
        "owasp": A09,
        "what_it_means": (
            "Your site does not publish a security contact file, which is the standard way for "
            "a researcher to tell you about a problem they have found."
        ),
        "why_it_matters": (
            "This is not a vulnerability. It matters because when someone does find a genuine "
            "issue, they often cannot work out who to tell, so it goes unreported - or public."
        ),
        "how_to_fix": [
            "Create a text file at /.well-known/security.txt on your site.",
            "Include at minimum: Contact: mailto:security@yourbusiness.com and an Expires: date.",
            "Make sure that mailbox is actually monitored.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://securitytxt.org/",
    },

    "robots-sensitive-paths": {
        "title": "Your robots.txt file points to private areas",
        "cvss": 0.0,
        "owasp": A05,
        "what_it_means": (
            "The robots.txt file, which asks search engines not to index certain pages, names "
            "administrative or private folders."
        ),
        "why_it_matters": (
            "This is informational rather than a vulnerability. Attackers read robots.txt "
            "first precisely because it is a curated list of the pages you would rather people "
            "did not see. Hiding something here does not protect it."
        ),
        "how_to_fix": [
            "Make sure the listed areas are protected by a login, not just by robots.txt.",
            "Where possible use broad rules rather than naming each sensitive folder.",
        ],
        "difficulty": "Easy",
        "needs_professional": False,
        "reference": "https://owasp.org/www-project-web-security-testing-guide/",
    },
}


def build_finding(check_id: str, url: str, evidence: str = "", **overrides) -> "Any":
    """Create a Finding from its knowledge base entry.

    Keeping construction in one place guarantees every finding the scanner
    raises carries a CVSS score, an OWASP category and remediation guidance.
    """
    from ..models import Finding, severity_from_cvss

    entry = KNOWLEDGE.get(check_id)
    if entry is None:
        raise KeyError(f"No knowledge base entry for check '{check_id}'")

    cvss = float(overrides.pop("cvss", entry["cvss"]))
    return Finding(
        check_id=check_id,
        title=overrides.pop("title", entry["title"]),
        severity=overrides.pop("severity", severity_from_cvss(cvss)),
        cvss=cvss,
        owasp=entry["owasp"],
        url=url,
        evidence=evidence,
        what_it_means=entry["what_it_means"],
        why_it_matters=entry["why_it_matters"],
        how_to_fix=list(entry["how_to_fix"]),
        difficulty=entry["difficulty"],
        needs_professional=entry["needs_professional"],
        reference=entry["reference"],
        **overrides,
    )
