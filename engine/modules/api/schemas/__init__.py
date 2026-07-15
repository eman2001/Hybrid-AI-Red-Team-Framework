"""
modules/api/schemas/__init__.py
================================
Pydantic v2 schemas for all API request/response models.
"""

from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, Field


# ── Shared ────────────────────────────────────────────────────

class ServiceOut(BaseModel):
    port:    int
    proto:   str = "tcp"
    service: str
    product: str = ""
    version: str = ""

class PortInfo(BaseModel):
    port:    int
    service: str = ""
    product: str = ""
    version: str = ""

# ── Scan ──────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target:    str  = Field(..., example="192.168.1.100",
                            description="Target IP, hostname, or CIDR range")
    lhost:     str  = Field("127.0.0.1", example="192.168.1.50",
                            description="Attacker IP (LHOST for reverse shells)")
    dry_run:   bool = Field(True,  description="Simulation only — no real tools")
    threshold: int  = Field(30,    description="Minimum risk score (0–100)")

class ScanHostOut(BaseModel):
    ip:       str
    hostname: str = ""
    os:       str = "unknown"
    services: list[ServiceOut] = []

class ScanResponse(BaseModel):
    status:      str
    session_id:  str
    target:      str
    live_hosts:  list[str]
    host_detail: list[ScanHostOut] = []
    port_count:  int = 0
    timestamp:   str

# ── Vulnerabilities ───────────────────────────────────────────

class VulnOut(BaseModel):
    host:      str
    port:      int
    service:   str
    cve:       str
    severity:  str
    cvss:      float
    risk_score: float
    exploit:   str = ""
    title:     str = ""
    intel:     dict[str, Any] = {}

class VulnListResponse(BaseModel):
    total:           int
    critical_count:  int
    high_count:      int
    vulnerabilities: list[VulnOut]

# ── Threat Intelligence ───────────────────────────────────────

class ThreatIntelOut(BaseModel):
    cve:          str
    cvss:         float
    epss:         float
    kev:          bool
    kev_name:     str = ""
    kev_ransomware: bool = False
    vendor:       str = ""
    product:      str = ""
    severity:     str = ""
    score:        float          # composite 0–100
    risk_tier:    str = ""
    priority:     str = ""

class ThreatSummaryResponse(BaseModel):
    total:         int
    kev_count:     int
    ransomware:    int
    imminent_epss: int
    avg_cvss:      float
    avg_epss:      float
    findings:      list[ThreatIntelOut]

# ── MITRE ─────────────────────────────────────────────────────

class TechniqueOut(BaseModel):
    technique_id:   str
    technique_name: str
    tactic:         str
    confidence:     float
    source:         str
    host:           str = ""

class TacticDistOut(BaseModel):
    tactic:    str
    count:     int
    techniques: list[str]

class HeatmapTechniqueOut(BaseModel):
    techniqueID: str
    score:       int
    color:       str
    comment:     str = ""

class MitreResponse(BaseModel):
    total_techniques: int
    tactics_covered:  int
    techniques:       list[TechniqueOut]
    tactic_distribution: list[TacticDistOut]

class HeatmapResponse(BaseModel):
    name:       str
    domain:     str
    techniques: list[HeatmapTechniqueOut]
    legend:     list[dict] = []

# ── Attack Chain ──────────────────────────────────────────────

class ChainPhaseOut(BaseModel):
    phase_name: str
    tactic:     str
    techniques: list[dict]
    hosts:      list[str]
    confidence: float
    source:     str

class AttackChainResponse(BaseModel):
    generated:    str
    phase_count:  int
    tech_count:   int
    avg_confidence: float
    phases:       dict[str, ChainPhaseOut]

# ── Attack Graph ──────────────────────────────────────────────

class GraphNodeOut(BaseModel):
    id:      str
    type:    str           # attacker | target | host | service
    host:    str = ""
    port:    int = 0
    service: str = ""
    risk:    float = 0.0

class GraphEdgeOut(BaseModel):
    from_node:  str = Field(alias="from")
    to_node:    str = Field(alias="to")
    tactic:     str = ""
    technique:  str = ""

    class Config:
        populate_by_name = True

class AttackGraphResponse(BaseModel):
    node_count:  int
    edge_count:  int
    nodes:       list[GraphNodeOut]
    edges:       list[dict]
    critical_path: list[str] = []

# ── Analytics ─────────────────────────────────────────────────

class RiskDistOut(BaseModel):
    critical: int
    high:     int
    medium:   int
    low:      int

class DashboardResponse(BaseModel):
    session_id:    str
    target:        str
    host_count:    int
    vuln_count:    int
    exploit_count: int
    technique_count: int
    kev_count:     int
    risk_dist:     RiskDistOut
    top_techniques: list[dict]
    pipeline_status: dict[str, bool]
