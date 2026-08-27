"""Individual security checks, grouped by the phase they belong to."""

from .transport import TransportSecurityCheck, HttpsRedirectCheck
from .headers import SecurityHeadersCheck
from .cookies import CookieSecurityCheck
from .content import (
    MixedContentCheck,
    FormSecurityCheck,
    InformationLeakCheck,
)
from .exposure import ExposedFilesCheck, DirectoryListingCheck
from .disclosure import TechnologyDisclosureCheck
from .serverconfig import (
    CorsPolicyCheck,
    HttpMethodsCheck,
    CachePolicyCheck,
    SecurityContactCheck,
    RobotsCheck,
)

# Order matters: this is the sequence shown in the scan log and the phase
# progression displayed on the New Scan screen.
ALL_CHECKS = [
    TransportSecurityCheck,
    HttpsRedirectCheck,
    SecurityHeadersCheck,
    CookieSecurityCheck,
    MixedContentCheck,
    FormSecurityCheck,
    ExposedFilesCheck,
    DirectoryListingCheck,
    TechnologyDisclosureCheck,
    InformationLeakCheck,
    CorsPolicyCheck,
    HttpMethodsCheck,
    CachePolicyCheck,
    SecurityContactCheck,
    RobotsCheck,
]

__all__ = ["ALL_CHECKS"]
