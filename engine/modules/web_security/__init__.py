"""
web_security
------------
OWASP Top 10 (2021) analysis engine for the Hybrid AI Red Team Framework.
Analyses web services using service banners, technology fingerprints,
and Nmap HTTP script output — no active payload injection.
"""

from .owasp_engine                       import OWASPEngine
from .technology_detector                import TechnologyDetector
from .injection_checker                  import InjectionChecker
from .broken_access_control_checker      import BrokenAccessControlChecker
from .auth_failure_checker               import AuthFailureChecker
from .security_misconfiguration_checker  import SecurityMisconfigurationChecker
from .vulnerable_components_checker      import VulnerableComponentsChecker
from .cryptographic_failure_checker      import CryptographicFailureChecker
from .ssrf_checker                       import SSRFChecker
from .owasp_report_builder               import OWASPReportBuilder

__all__ = [
    "OWASPEngine",
    "TechnologyDetector",
    "InjectionChecker",
    "BrokenAccessControlChecker",
    "AuthFailureChecker",
    "SecurityMisconfigurationChecker",
    "VulnerableComponentsChecker",
    "CryptographicFailureChecker",
    "SSRFChecker",
    "OWASPReportBuilder",
]
