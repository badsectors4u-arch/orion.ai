"""
Orion Security Platform — Pydantic Validation Schemas (Pydantic v2).

Enforces strict input validation and serialization contracts for all REST and WebSocket endpoints.
Contracts match frontend TypeScript interfaces and Member 3's core data models exactly.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]
ScanStatusType = Literal["pending", "running", "completed", "failed"]
PlanType = Literal["free", "pro", "enterprise", "advanced"]


# ──────────────────────────────────────────────────────────────
# 1. User & Authentication Schemas
# ──────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6, max_length=128)
    username: Optional[str] = Field(None, max_length=64)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    username: Optional[str] = None
    plan: str
    scans_today: int
    is_active: bool
    created_at: datetime
    ai_provider: Optional[str] = None
    ai_model: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class UserSettingsUpdate(BaseModel):
    username: Optional[str] = None
    ai_provider: Optional[str] = Field(None, description="'custom', 'cloud', or 'local_ollama'")
    ai_api_key: Optional[str] = None
    ai_base_url: Optional[str] = None
    ai_model: Optional[str] = None


# ──────────────────────────────────────────────────────────────
# 2. Target Schemas
# ──────────────────────────────────────────────────────────────

class TargetCreate(BaseModel):
    url: str = Field(..., min_length=4, max_length=500, description="Target domain, IP, or URL")


class TargetResponse(BaseModel):
    id: str
    url: str
    domain: Optional[str] = None
    ip: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ──────────────────────────────────────────────────────────────
# 3. Vulnerability Schemas
# ──────────────────────────────────────────────────────────────

class VulnerabilityItem(BaseModel):
    id: str
    title: str
    severity: SeverityLevel
    service: str = "http"
    port: Optional[int] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    description: str
    remediation_steps: List[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class VulnerabilityResponse(VulnerabilityItem):
    pass


# ──────────────────────────────────────────────────────────────
# 4. Scan Schemas
# ──────────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    target_url: str = Field(..., description="Target URL to scan")
    scan_type: Literal["quick", "standard", "full", "web_only"] = "full"
    plan: Optional[str] = "advanced"
    ai_hunter_duration: Optional[int] = Field(300, ge=60, le=900, description="AI Deep Hunter budget in seconds")


class ScanResponse(BaseModel):
    id: str
    target_url: str
    status: ScanStatusType
    scan_type: str
    plan: str
    progress: int
    current_tool: Optional[str] = None
    risk_score: Optional[float] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ScanDetailResponse(ScanResponse):
    vulnerabilities: List[VulnerabilityResponse] = Field(default_factory=list)
    attack_graph: Dict[str, Any] = Field(default_factory=dict)
    attack_chains: List[Dict[str, Any]] = Field(default_factory=list)
    ai_analysis: Dict[str, Any] = Field(default_factory=dict)


# ──────────────────────────────────────────────────────────────
# 5. Scan Comparison (Diff) Schemas
# ──────────────────────────────────────────────────────────────

class ScanDiffResult(BaseModel):
    scan_a_id: str
    scan_b_id: str
    target_url: str
    resolved_vulnerabilities: List[VulnerabilityItem] = Field(
        default_factory=list, description="Present in Scan A but fixed in Scan B"
    )
    new_vulnerabilities: List[VulnerabilityItem] = Field(
        default_factory=list, description="New vulnerabilities detected in Scan B"
    )
    persistent_vulnerabilities: List[VulnerabilityItem] = Field(
        default_factory=list, description="Unresolved vulnerabilities open in both scans"
    )
    security_score_improvement: float = Field(
        ..., description="Percentage improvement in security posture (+ positive is better)"
    )


# ──────────────────────────────────────────────────────────────
# 6. Breach Checker Schemas
# ──────────────────────────────────────────────────────────────

class BreachCheckRequest(BaseModel):
    email: EmailStr


class BreachAIAnalysis(BaseModel):
    model_config = ConfigDict(extra="ignore")
    threat_level: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW, CLEAN
    verdict: str = "Account identity is safe"
    summary: str = "No credential exposures detected on dark web monitoring channels."
    primary_threat_vector: Optional[str] = "None"
    remediation_checklist: List[str] = Field(default_factory=list)


class BreachEntry(BaseModel):
    name: str
    date: str = "Verified Leak"
    data_classes: List[str] = Field(default_factory=list)
    account_count: Optional[int] = None
    details: Optional[str] = None
    domain: Optional[str] = None
    industry: Optional[str] = None
    logo: Optional[str] = None
    password_risk: Optional[str] = None
    verified: Optional[str] = "Yes"


class BreachResult(BaseModel):
    email: str
    breach_count: int = 0
    breaches: List[BreachEntry] = Field(default_factory=list)
    risk_score: float = 0.0
    risk_label: str = "Clean"
    passwords_exposed: int = 0
    plaintext_passwords: int = 0
    easy_to_crack_passwords: int = 0
    paste_count: int = 0
    year_distribution: Dict[str, int] = Field(default_factory=dict)
    exposed_data_types: List[str] = Field(default_factory=list)
    ai_analysis: Optional[BreachAIAnalysis] = None
    error: Optional[str] = None


# ──────────────────────────────────────────────────────────────
# 7. Knowledgebase Schemas
# ──────────────────────────────────────────────────────────────

class KBArticleResponse(BaseModel):
    id: str
    title: str
    cwe_id: str
    severity: str
    description: str
    references: List[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class KBArticleDetailResponse(KBArticleResponse):
    vulnerable_code: Optional[str] = None
    remediation_code: Optional[str] = None


# ──────────────────────────────────────────────────────────────
# 8. Subscription Quota & Plans Schemas
# ──────────────────────────────────────────────────────────────

class QuotaResponse(BaseModel):
    plan: str
    scans_today: int
    daily_limit: int  # 3 for free, -1 for unlimited
    scans_remaining: int  # >=0 or -1 for unlimited


class PlanUpgradeRequest(BaseModel):
    plan: Literal["pro", "enterprise"]


class PlanUpgradeResponse(BaseModel):
    success: bool = True
    new_plan: str
    message: str


# ──────────────────────────────────────────────────────────────
# 9. AI Security Copilot / Chatbot Schemas
# ──────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    scan_id: Optional[str] = None
    history: List[Dict[str, str]] = Field(default_factory=list)


class ChatResponse(BaseModel):
    answer: str
    key_points: List[str] = Field(default_factory=list)
    severity: Optional[str] = None
    suggestions: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)

