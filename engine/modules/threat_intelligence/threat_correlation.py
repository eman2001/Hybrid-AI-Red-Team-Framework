"""
threat_intelligence/threat_correlation.py
------------------------------------------
Correlates vulnerability findings with threat intelligence signals
(CVSS, EPSS, KEV, vendor intel) to produce an enriched finding.
"""

from engine.modules.threat_intelligence.cvss_engine        import CvssEngine
from engine.modules.threat_intelligence.epss_engine        import EpssEngine
from engine.modules.threat_intelligence.kev_engine         import KevEngine
from engine.modules.threat_intelligence.vendor_intelligence import VendorIntelligence
from engine.modules.threat_intelligence.product_intelligence import ProductIntelligence


class ThreatCorrelation:

    def __init__(self):
        self._cvss    = CvssEngine()
        self._epss    = EpssEngine()
        self._kev     = KevEngine()
        self._vendor  = VendorIntelligence()
        self._product = ProductIntelligence()

    def enrich(self, finding: dict) -> dict:
        cve     = finding.get("cve", "")
        product = finding.get("product", "")
        version = finding.get("version", "")

        # CWE identifiers (e.g. "CWE-89") are a weakness *category*, not a
        # specific tracked vulnerability -- CVE-based lookups (CVSS-by-CVE,
        # EPSS, KEV) don't apply to them and would silently return the same
        # generic default for every finding. Treat these findings' own
        # OWASP-derived CVSS estimate (Phase 3) as authoritative, and mark
        # EPSS/KEV as not applicable rather than showing a fabricated number.
        is_cwe_based = cve.upper().startswith("CWE-")

        if is_cwe_based:
            cvss   = finding.get("cvss", 5.0)
            # EPSS/KEV are CVE-specific by definition and don't apply to a CWE
            # category. Keep epss numeric (0.0, not a fabricated 0.1) so every
            # downstream sum/multiplication that already assumes a float stays
            # correct; `epss_applicable=False` is the flag report/print code
            # should check before displaying this as a real EPSS score.
            epss             = 0.0
            epss_applicable  = False
            is_kev = False
        else:
            cvss_found = self._cvss.score(cve)
            # No CVE-based score found (common for old backdoors with no CVE record) ->
            # keep the finding's own CVSS estimate from vulnerability mapping (Phase 3)
            # instead of silently overwriting it with a generic default.
            cvss   = cvss_found if cvss_found is not None else finding.get("cvss", 5.0)
            epss             = self._epss.score(cve)
            epss_applicable  = True
            is_kev = self._kev.is_kev(cve)

        finding["cvss_live"]      = cvss
        finding["is_cwe_based"]   = is_cwe_based
        finding["epss"]           = round(epss, 4)
        finding["epss_applicable"] = epss_applicable
        finding["epss_label"]     = self._epss.risk_label(epss) if epss_applicable else "N/A"
        finding["in_kev"]         = is_kev
        finding["eol_risk"]     = self._product.eol_risk(product, version)
        self._vendor.enrich_finding(finding)

        if is_kev:
            finding["severity"] = "critical"
        return finding

    def enrich_all(self, findings: list[dict]) -> list[dict]:
        return [self.enrich(f) for f in findings]
