"""Transport security: certificates, protocol versions and HTTPS redirection."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from ...models import Finding
from ..base import BaseCheck, ScanContext
from ..knowledge import build_finding

CERT_EXPIRY_WARNING_DAYS = 21


class TransportSecurityCheck(BaseCheck):
    """Inspect the TLS certificate and the protocol versions the server accepts."""

    check_id = "transport"
    name = "Transport security"
    phase = "Transport Security (TLS)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        if ctx.parsed.scheme != "https":
            # The site was reached over plain HTTP. Check whether a secure
            # version exists at all before declaring HTTPS unavailable.
            https_url = ctx.target_url.replace("http://", "https://", 1)
            probe = ctx.fetch(https_url, allow_redirects=False)
            if probe.error or probe.status_code == 0:
                ctx.log("No working HTTPS service found on this site.", "ALERT")
                findings.append(build_finding(
                    "tls-not-available",
                    ctx.target_url,
                    evidence=(
                        f"Connecting to {https_url} failed: "
                        f"{probe.error or 'no response'}. The site is only available "
                        f"over an unencrypted connection."
                    ),
                ))
                return findings

            ctx.log("Site answered over HTTPS as well - continuing on the secure address.")

        cert_findings = self._inspect_certificate(ctx)
        findings.extend(cert_findings)
        findings.extend(self._check_protocols(ctx))
        return findings

    # ------------------------------------------------------------------
    # Certificate
    # ------------------------------------------------------------------

    def _inspect_certificate(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        host = ctx.host
        port = 443 if ctx.parsed.scheme == "https" else ctx.port

        context = ssl.create_default_context()
        cert = None
        verify_error = ""

        try:
            with socket.create_connection((host, port), timeout=ctx.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    ctx.tls_info["version"] = tls.version()
                    ctx.tls_info["cipher"] = tls.cipher()
        except ssl.SSLCertVerificationError as exc:
            verify_error = str(exc)
        except (socket.timeout, socket.gaierror, ConnectionError, OSError) as exc:
            ctx.log(f"Could not open a TLS connection to {host}: {exc}", "WARN")
            return findings

        if verify_error:
            # Reconnect without verification purely to read the certificate so
            # we can tell the user precisely what is wrong with it.
            cert = self._read_unverified_cert(ctx, host, port)
            findings.extend(self._classify_verify_error(ctx, verify_error, cert))
            ctx.allow_insecure_tls()

        if cert:
            ctx.tls_info["cert"] = cert
            findings.extend(self._check_expiry(ctx, cert, already_expired=bool(findings)))

        return findings

    def _read_unverified_cert(self, ctx: ScanContext, host: str, port: int):
        insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=ctx.timeout) as sock:
                with insecure.wrap_socket(sock, server_hostname=host) as tls:
                    ctx.tls_info["version"] = tls.version()
                    # getpeercert() returns {} without validation, so fall back
                    # to the binary form and decode the essential fields.
                    der = tls.getpeercert(binary_form=True)
                    return _decode_certificate(der)
        except (ssl.SSLError, socket.timeout, socket.gaierror, ConnectionError, OSError):
            return None

    def _classify_verify_error(self, ctx: ScanContext, error: str, cert) -> list[Finding]:
        lowered = error.lower()
        evidence = f"Certificate verification failed: {error.strip()}"

        if "expired" in lowered:
            ctx.log("Certificate has expired.", "ALERT")
            return [build_finding("tls-cert-expired", ctx.target_url, evidence=evidence)]

        if "hostname mismatch" in lowered or "doesn't match" in lowered or "match either of" in lowered:
            ctx.log("Certificate does not match this hostname.", "ALERT")
            return [build_finding("tls-cert-hostname-mismatch", ctx.target_url, evidence=evidence)]

        if "self signed" in lowered or "self-signed" in lowered:
            ctx.log("Certificate is self-signed.", "ALERT")
            return [build_finding("tls-cert-self-signed", ctx.target_url, evidence=evidence)]

        if "unable to get local issuer" in lowered or "unable to verify" in lowered:
            ctx.log("Certificate chain is incomplete or untrusted.", "ALERT")
            return [build_finding(
                "tls-cert-self-signed", ctx.target_url,
                title="Security certificate could not be verified as trustworthy",
                evidence=evidence + (
                    "\nThis usually means an intermediate certificate is missing from the "
                    "server configuration, so some browsers will reject the site."
                ),
            )]

        ctx.log(f"Certificate problem: {error.strip()[:120]}", "ALERT")
        return [build_finding("tls-cert-self-signed", ctx.target_url, evidence=evidence)]

    def _check_expiry(self, ctx: ScanContext, cert: dict, already_expired: bool) -> list[Finding]:
        not_after = cert.get("notAfter")
        if not not_after:
            return []

        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError:
            return []

        days_left = (expiry - datetime.now(timezone.utc)).days
        ctx.tls_info["days_until_expiry"] = days_left

        if days_left < 0:
            if already_expired:
                return []
            return [build_finding(
                "tls-cert-expired", ctx.target_url,
                evidence=f"The certificate expired on {expiry:%d %B %Y}, {abs(days_left)} days ago.",
            )]

        if days_left <= CERT_EXPIRY_WARNING_DAYS:
            ctx.log(f"Certificate expires in {days_left} days.", "WARN")
            return [build_finding(
                "tls-cert-expiring", ctx.target_url,
                evidence=f"The certificate expires on {expiry:%d %B %Y}, in {days_left} days.",
            )]

        ctx.log(f"Certificate valid, expires in {days_left} days.")
        return []

    # ------------------------------------------------------------------
    # Protocol versions
    # ------------------------------------------------------------------

    def _check_protocols(self, ctx: ScanContext) -> list[Finding]:
        if ctx.parsed.scheme != "https":
            return []

        weak_accepted: list[str] = []
        untestable = False

        for label, version in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
            outcome = self._try_protocol(ctx, version)
            if outcome is True:
                weak_accepted.append(label)
            elif outcome is None:
                untestable = True

        if weak_accepted:
            ctx.log(f"Server still accepts {', '.join(weak_accepted)}.", "ALERT")
            return [build_finding(
                "tls-weak-protocol", ctx.target_url,
                evidence=(
                    f"The server completed a connection using {' and '.join(weak_accepted)}. "
                    f"These versions were deprecated by all major browsers in 2020."
                ),
            )]

        if untestable:
            ctx.log("Old TLS versions could not be tested from this machine.", "WARN")
        else:
            ctx.log("Outdated TLS versions are correctly refused.")
        return []

    def _try_protocol(self, ctx: ScanContext, version) -> bool | None:
        """True if the server accepted the version, False if refused, None if untestable."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            try:
                # Modern OpenSSL builds refuse legacy ciphers at security level 1.
                context.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
        except (ValueError, ssl.SSLError):
            # The local OpenSSL build has removed this version entirely.
            return None

        try:
            with socket.create_connection((ctx.host, 443), timeout=min(8, ctx.timeout)) as sock:
                with context.wrap_socket(sock, server_hostname=ctx.host):
                    return True
        except ssl.SSLError:
            return False
        except (socket.timeout, ConnectionError, OSError):
            return None


class HttpsRedirectCheck(BaseCheck):
    """Confirm that plain HTTP visitors are moved to the secure site."""

    check_id = "https-redirect"
    name = "HTTPS redirection"
    phase = "Transport Security (TLS)"

    def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.parsed.scheme != "https":
            return []  # already reported as tls-not-available

        http_url = f"http://{ctx.parsed.netloc}{ctx.parsed.path or '/'}"
        page = ctx.fetch(http_url, allow_redirects=False)

        if page.error or page.status_code == 0:
            ctx.log("No service on the insecure port - nothing to redirect.")
            return []

        location = page.header("Location")
        if page.status_code in (301, 302, 307, 308) and location.startswith("https://"):
            ctx.log(f"Insecure requests redirect correctly (HTTP {page.status_code}).")
            return []

        if page.status_code in (301, 302, 307, 308):
            evidence = (
                f"http:// returned HTTP {page.status_code} redirecting to '{location}', "
                f"which is not a secure address."
            )
        else:
            evidence = (
                f"http://{ctx.parsed.netloc} returned HTTP {page.status_code} and served the "
                f"page directly instead of redirecting to the secure version."
            )

        ctx.log("Insecure connections are not redirected to HTTPS.", "ALERT")
        return [build_finding("tls-no-redirect", http_url, evidence=evidence)]


def _decode_certificate(der: bytes) -> dict | None:
    """Extract the fields we need from a DER certificate.

    Used when verification failed, because getpeercert() returns an empty dict
    on an unverified connection.
    """
    if not der:
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:  # pragma: no cover - cryptography ships with requests
        return None

    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        return {
            "notAfter": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
            "subject": ((("commonName", _common_name(cert)),),),
            "issuer": ((("commonName", _issuer_name(cert)),),),
        }
    except Exception:
        return None


def _common_name(cert) -> str:
    try:
        from cryptography.x509.oid import NameOID
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return "unknown"


def _issuer_name(cert) -> str:
    try:
        from cryptography.x509.oid import NameOID
        return cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return "unknown"
