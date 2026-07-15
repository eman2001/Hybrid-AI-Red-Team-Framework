"""
modules/threat_intelligence/__init__.py
-----------------------------------------
Preserves original RiskEngine interface; now backed by full TI pipeline.
"""

from engine.modules.threat_intelligence.cvss_engine        import CvssEngine
from engine.modules.threat_intelligence.epss_engine        import EpssEngine
from engine.modules.threat_intelligence.kev_engine         import KevEngine
from engine.modules.threat_intelligence.vendor_intelligence import VendorIntelligence
from engine.modules.threat_intelligence.product_intelligence import ProductIntelligence
from engine.modules.threat_intelligence.threat_correlation  import ThreatCorrelation
from engine.modules.threat_intelligence.threat_score        import ThreatScore

# Alias so main.py import still works
from engine.modules.risk_engine import RiskEngine  # noqa: F401  (kept for backward compat)

__all__ = [
    "CvssEngine", "EpssEngine", "KevEngine",
    "VendorIntelligence", "ProductIntelligence",
    "ThreatCorrelation", "ThreatScore", "RiskEngine",
]
