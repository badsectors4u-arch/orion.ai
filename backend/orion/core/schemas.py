"""
Orion Security Platform — Canonical Data Contracts.

SINGLE SOURCE OF TRUTH for every payload that crosses boundaries between
Member 3's services, Member 2's API layer, and Member 1's React Flow UI.

⚠️  DO NOT rename fields or change types without coordinating with
    Member 1 (frontend) and Member 2 (backend + DB models).
    Any drift here whitescreens the React Flow graph or fails DB inserts.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ──────────────────────────────────────────────────────────────────────
# Severity scale — MUST match Member 1's UI color palette exactly
# ──────────────────────────────────────────────────────────────────────
Severity = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0,
}

SEVERITY_COLORS: dict[str, str] = {
    "critical": "#e84057", "high": "#f97316",
    "medium": "#f59e0b", "low": "#3b82f6", "info": "#6b7280",
}


# ──────────────────────────────────────────────────────────────────────
# Sanitized target — the safe, normalized output of input_sanitizer
# ──────────────────────────────────────────────────────────────────────
class SanitizedTarget(BaseModel):
    """
    Normalized representation of a scan target.
    """
    model_config = ConfigDict(frozen=True)

    original: str
    scheme: Literal["http", "https"]
    hostname: str
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    resolved_ip: str
    path: str = "/"
    url: str

    @property
    def effective_port(self) -> int:
        if self.port is not None:
            return self.port
        return 443 if self.scheme == "https" else 80


# ──────────────────────────────────────────────────────────────────────
# Vulnerability — the atomic unit Member 1 renders and Member 2 stores
# ──────────────────────────────────────────────────────────────────────
class VulnerabilityItem(BaseModel):
    """
    Structured finding. Matches the exact contract that Member 1 and
    Member 2 depend on. `extra="forbid"` means any typo in a producer
    fails immediately instead of silently disappearing from the UI.
    """
    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str = Field(min_length=1, max_length=300)
    severity: Severity
    service: str = Field(min_length=1, max_length=256)
    port: Optional[int] = Field(default=None, ge=0, le=65535)
    cve_id: Optional[str] = Field(default=None, max_length=32)
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    description: str = Field(min_length=1)
    remediation_steps: list[str] = Field(default_factory=list)

    @field_validator("cve_id")
    @classmethod
    def _normalize_cve(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        return v.strip().upper()


# ──────────────────────────────────────────────────────────────────────
# Attack graph — consumed by Member 1's React Flow component
# ──────────────────────────────────────────────────────────────────────
class GraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    type: Literal["target", "service", "vulnerability", "root"]
    label: str
    severity: Severity


class GraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    source: str
    target: str
    label: str
    animated: bool = False


class AttackGraphPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────
# Tool result — internal contract between tools and the orchestrator
# ──────────────────────────────────────────────────────────────────────
class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str
    success: bool
    vulnerabilities: list[VulnerabilityItem] = Field(default_factory=list)
    duration_seconds: float = 0.0
    error: Optional[str] = None
    raw_output_truncated: Optional[str] = None


# ──────────────────────────────────────────────────────────────────────
# AI adapter response — NEVER raises, always inspectable
# ──────────────────────────────────────────────────────────────────────
class AIResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ok: bool
    data: Any = None
    error: Optional[str] = None
    latency_ms: Optional[float] = None
    provider: Optional[str] = None
    model: Optional[str] = None


# ──────────────────────────────────────────────────────────────────────
# Progress message — Redis Pub/Sub contract with Member 1's WebSocket
# ──────────────────────────────────────────────────────────────────────
class ProgressMessage(BaseModel):
    """
    Published to `scan:{scan_id}`. Member 1 subscribes and drives the
    progress bar / "current tool" badge off these fields.
    """
    model_config = ConfigDict(extra="forbid")
    type: Literal["progress", "error", "complete"] = "progress"
    scan_id: str
    percentage: int = Field(ge=0, le=100)
    current_tool: Optional[str] = None
    message: str = ""
    phase: Optional[str] = None
    phase_number: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ──────────────────────────────────────────────────────────────────────
# Breach check — Member 2 stores this, Member 1 renders it
# ──────────────────────────────────────────────────────────────────────
class BreachAIAnalysis(BaseModel):
    model_config = ConfigDict(extra="ignore")
    threat_level: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW, CLEAN
    verdict: str = "Account identity is safe"
    summary: str = "No credential exposures detected on dark web monitoring channels."
    primary_threat_vector: Optional[str] = "None"
    remediation_checklist: list[str] = Field(default_factory=list)


class BreachEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str
    date: str = "Verified Leak"  # ISO YYYY-MM-DD or year
    data_classes: list[str] = Field(default_factory=list)
    account_count: Optional[int] = Field(default=None)
    details: Optional[str] = Field(default=None)
    domain: Optional[str] = Field(default=None)
    industry: Optional[str] = Field(default=None)
    logo: Optional[str] = Field(default=None)
    password_risk: Optional[str] = Field(default=None)
    verified: Optional[str] = Field(default="Yes")


class BreachResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    email: str
    breach_count: int = 0
    breaches: list[BreachEntry] = Field(default_factory=list)
    risk_score: float = 0.0
    risk_label: str = "Clean"
    passwords_exposed: int = 0
    plaintext_passwords: int = 0
    easy_to_crack_passwords: int = 0
    paste_count: int = 0
    year_distribution: dict[str, int] = Field(default_factory=dict)
    exposed_data_types: list[str] = Field(default_factory=list)
    ai_analysis: Optional[BreachAIAnalysis] = None
    error: Optional[str] = None


# ──────────────────────────────────────────────────────────────────────
# Phase 1 — Reconnaissance Data Contracts
# ──────────────────────────────────────────────────────────────────────
class TechFingerprint(BaseModel):
    """Output from httpx tech detection."""
    model_config = ConfigDict(extra="forbid")
    server: Optional[str] = None
    technologies: list[str] = Field(default_factory=list)
    cdn: Optional[str] = None
    status_code: int = 0
    title: Optional[str] = None
    ip: Optional[str] = None
    tls_version: Optional[str] = None
    headers: dict[str, str] = Field(default_factory=dict)


class CMSInfo(BaseModel):
    """Output from WhatWeb CMS detection."""
    model_config = ConfigDict(extra="forbid")
    cms_name: Optional[str] = None
    cms_version: Optional[str] = None
    plugins: list[str] = Field(default_factory=list)
    theme: Optional[str] = None


class SubdomainEntry(BaseModel):
    """A discovered subdomain with liveness status."""
    model_config = ConfigDict(extra="forbid")
    subdomain: str
    ip: Optional[str] = None
    status_code: Optional[int] = None
    is_alive: bool = False


class ReconResult(BaseModel):
    """Aggregated output of Phase 1 Reconnaissance."""
    model_config = ConfigDict(extra="forbid")
    tech_fingerprint: TechFingerprint = Field(default_factory=TechFingerprint)
    cms_info: CMSInfo = Field(default_factory=CMSInfo)
    subdomains: list[SubdomainEntry] = Field(default_factory=list)
    raw_subdomains: list[str] = Field(default_factory=list)
    live_subdomains: list[str] = Field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────
# Phase 2 — Discovery Data Contracts
# ──────────────────────────────────────────────────────────────────────
class FormEntry(BaseModel):
    """An HTML form discovered by katana crawler."""
    model_config = ConfigDict(extra="forbid")
    url: str
    method: str = "GET"
    action: Optional[str] = None
    params: list[str] = Field(default_factory=list)


class SecretLeak(BaseModel):
    """A leaked secret / sensitive token found in JS files."""
    model_config = ConfigDict(extra="forbid")
    type: str
    value: str
    file: str
    line: Optional[int] = None
    severity: Severity = "high"


class DiscoveryResult(BaseModel):
    """Aggregated output of Phase 2 Crawling & Discovery."""
    model_config = ConfigDict(extra="forbid")
    crawled_urls: list[str] = Field(default_factory=list)
    forms: list[FormEntry] = Field(default_factory=list)
    js_files: list[str] = Field(default_factory=list)
    js_endpoints: list[str] = Field(default_factory=list)
    archived_urls: list[str] = Field(default_factory=list)
    hidden_params: dict[str, list[str]] = Field(default_factory=dict)
    leaked_secrets: list[SecretLeak] = Field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────
# AI Attack Plan — Bridge between Phase 2 and Phase 4
# ──────────────────────────────────────────────────────────────────────
class AttackPlan(BaseModel):
    """AI-generated targeting plan for Phase 4 tools."""
    model_config = ConfigDict(extra="forbid")
    sqlmap_targets: list[str] = Field(default_factory=list)
    xss_targets: list[str] = Field(default_factory=list)
    ffuf_targets: list[str] = Field(default_factory=list)
    nuclei_targets: list[str] = Field(default_factory=list)
    nuclei_tags: list[str] = Field(default_factory=list)
    corsy_targets: list[str] = Field(default_factory=list)
    jwt_enabled: bool = False
    jwt_token: Optional[str] = None
    idor_targets: list[str] = Field(default_factory=list)
    skip_tools: list[str] = Field(default_factory=list)
    immediate_vulns: list[VulnerabilityItem] = Field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────
# Attack Chain — Correlated Multi-Vulnerability Findings
# ──────────────────────────────────────────────────────────────────────
class AttackChain(BaseModel):
    """A chain of vulnerabilities that escalate impact when combined."""
    model_config = ConfigDict(extra="forbid")
    chain_name: str
    steps: list[str] = Field(default_factory=list)
    combined_severity: Severity = "high"
    narrative: str = ""


# ──────────────────────────────────────────────────────────────────────
# Top-level scan result — what ScanOrchestrator.run_full_scan returns
# ──────────────────────────────────────────────────────────────────────
class AIAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    top_recommendations: list[str] = Field(default_factory=list)
    priority_matrix: dict[str, Any] = Field(default_factory=dict)
    fallback: bool = False  # True if rule-based analysis was used


class ScanResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vulnerabilities: list[VulnerabilityItem] = Field(default_factory=list)
    attack_graph: AttackGraphPayload = Field(default_factory=AttackGraphPayload)
    ai_analysis: AIAnalysis = Field(default_factory=AIAnalysis)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    tools_used: list[str] = Field(default_factory=list)
    scan_duration_seconds: float = 0.0
    recon: Optional[ReconResult] = None
    discovery: Optional[DiscoveryResult] = None
    attack_chains: list[AttackChain] = Field(default_factory=list)
