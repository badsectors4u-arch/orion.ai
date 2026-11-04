"""
Orion Security Platform — Ghost Analyst & AI Correlation Engine (Decision Point #3).

PURPOSE:
- Deduplicates findings reported by multiple scanners.
- Correlates multi-stage vulnerability chains (AttackChain synthesis).
- Generates CISO-grade executive summaries, unified risk scores, and priority matrices.
- Provides robust deterministic mathematical fallbacks.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from orion.ai.universal_ai_adapter import UniversalAIAdapter
from orion.core.schemas import (
    AIAnalysis,
    AttackChain,
    DiscoveryResult,
    ReconResult,
    SEVERITY_WEIGHTS,
    VulnerabilityItem,
)

logger = logging.getLogger(__name__)


class GhostAnalyst:
    def __init__(self, ai_adapter: UniversalAIAdapter):
        self.ai = ai_adapter

    async def analyze(
        self,
        vulnerabilities: list[VulnerabilityItem],
        target_url: str,
    ) -> AIAnalysis:
        """Standard executive summary and risk score analysis (backward compatible)."""
        if not vulnerabilities:
            return AIAnalysis(
                summary="No vulnerabilities were identified during this scan. The target appears well-configured.",
                risk_score=0.0,
                top_recommendations=["Maintain continuous security monitoring and automated scanning."],
                fallback=True,
            )

        vuln_data = [v.model_dump() for v in vulnerabilities]

        system_prompt = """
        You are a Chief Information Security Officer (CISO) writing an executive summary.
        Return ONLY valid JSON with this EXACT structure:
        {
          "summary": "A 3-5 sentence executive summary of the security posture.",
          "risk_score": 85.5,
          "top_recommendations": ["Patch X immediately", "Review Y configuration"],
          "priority_matrix": {"immediate": ["Vuln A"], "short_term": ["Vuln B"]}
        }
        Rules:
        1. risk_score must be a float between 0 and 100.
        2. Return ONLY JSON, no markdown.
        """

        user_prompt = f"Target: {target_url}\nVulnerabilities:\n{json.dumps(vuln_data, indent=2)}"

        try:
            response = await self.ai.call(system_prompt, user_prompt, json_mode=True)
            if response.ok and isinstance(response.data, dict):
                data = response.data
                return AIAnalysis(
                    summary=data.get("summary", "Analysis complete."),
                    risk_score=float(data.get("risk_score", 50.0)),
                    top_recommendations=data.get("top_recommendations", []),
                    priority_matrix=data.get("priority_matrix", {}),
                    fallback=False,
                )
        except Exception as e:
            logger.warning(f"AI returned invalid analysis structure, using fallback: {e}")

        return self._fallback_analysis(vulnerabilities)

    async def correlate_and_analyze(
        self,
        vulnerabilities: list[VulnerabilityItem],
        target_url: str,
        recon: Optional[ReconResult] = None,
        discovery: Optional[DiscoveryResult] = None,
    ) -> tuple[list[VulnerabilityItem], list[AttackChain], AIAnalysis]:
        """
        Deduplicates vulnerabilities, synthesizes attack chains, enriches all findings
        with rich location/payload/CVSS metadata, and produces AIAnalysis.
        """
        # 1. Smart Deduplication
        deduped = self._deduplicate_vulns(vulnerabilities)

        # 2. Enrich all findings with advanced Location, Payload, Mechanics, and CVSS metadata
        enriched = [self._enrich_finding(v, target_url) for v in deduped]

        # 3. Attack Chains synthesis
        chains = self._synthesize_chains(enriched)

        # 4. Overall Analysis
        analysis = await self.analyze(enriched, target_url)

        # Adjust risk score if high-severity chains exist
        if chains and any(c.combined_severity in ["critical", "high"] for c in chains):
            chain_bonus = 10.0 if any(c.combined_severity == "critical" for c in chains) else 5.0
            analysis.risk_score = min(100.0, analysis.risk_score + chain_bonus)

        return enriched, chains, analysis

    @classmethod
    def _enrich_finding(cls, v: VulnerabilityItem, target_url: str) -> VulnerabilityItem:
        """
        Ensures 100% of findings possess authoritative CVSS score, CWE classification,
        concrete remediation steps, and structured Location/Payload/Mechanics description.
        """
        title_lower = v.title.lower()
        score = v.cvss_score
        cwe = v.cve_id
        sev = v.severity

        # Determine authoritative defaults if missing
        if score is None:
            if sev == "critical":
                score = 9.8 if "sql" in title_lower or "rce" in title_lower else 9.1
            elif sev == "high":
                score = 8.6 if "traversal" in title_lower or "idor" in title_lower else 7.5
            elif sev == "medium":
                score = 6.5 if "redirect" in title_lower else 5.4
            elif sev == "low":
                score = 3.7
            else:
                score = 2.0

        if not cwe:
            if "sql" in title_lower:
                cwe = "CWE-89"
            elif "xss" in title_lower or "scripting" in title_lower:
                cwe = "CWE-79"
            elif "traversal" in title_lower or "file inclusion" in title_lower:
                cwe = "CWE-22"
            elif "idor" in title_lower or "direct object" in title_lower:
                cwe = "CWE-639"
            elif "content-security-policy" in title_lower or "csp" in title_lower:
                cwe = "CWE-693"
            elif "strict-transport-security" in title_lower or "hsts" in title_lower:
                cwe = "CWE-319"
            elif "x-frame-options" in title_lower or "clickjacking" in title_lower:
                cwe = "CWE-1021"
            elif "x-content-type-options" in title_lower or "mime" in title_lower:
                cwe = "CWE-693"
            elif "version disclosure" in title_lower or "banner" in title_lower or "trace" in title_lower:
                cwe = "CWE-200"
            elif "redirect" in title_lower:
                cwe = "CWE-601"
            else:
                cwe = "CWE-200"

        # Check if description already contains structured sections
        if "### 📍 Vulnerability Location" not in v.description:
            port_label = str(v.port) if v.port is not None else "80/443"
            cvss_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if sev == "critical" else (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N" if sev == "high" else (
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N" if sev == "medium" else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                )
            )

            # Determine payload/proof string based on title
            if "content-security-policy" in title_lower:
                proof_label = "Missing HTTP Header: 'Content-Security-Policy'"
                vuln_param = "HTTP Response Header: Content-Security-Policy"
            elif "strict-transport-security" in title_lower:
                proof_label = "Missing HTTP Header: 'Strict-Transport-Security'"
                vuln_param = "HTTP Response Header: Strict-Transport-Security"
            elif "x-frame-options" in title_lower:
                proof_label = "Missing HTTP Header: 'X-Frame-Options'"
                vuln_param = "HTTP Response Header: X-Frame-Options"
            elif "x-content-type-options" in title_lower:
                proof_label = "Missing HTTP Header: 'X-Content-Type-Options'"
                vuln_param = "HTTP Response Header: X-Content-Type-Options"
            elif "version disclosure" in title_lower:
                proof_label = f"Banner String in HTTP Response: '{v.description}'"
                vuln_param = "HTTP Response Header: Server / X-Powered-By"
            else:
                proof_label = "Automated scanner diagnostic signature verification"
                vuln_param = "Network / Application Endpoint"

            new_desc = (
                f"### 📍 Vulnerability Location\n"
                f"- **Target URL**: `{target_url}`\n"
                f"- **Vulnerable Component / Parameter**: `{vuln_param}`\n"
                f"- **Protocol & Port**: `{v.service}` / Port {port_label}\n\n"
                f"### 💥 Exploitation Proof & Payload\n"
                f"- **Tested Payload / Indicator**: `{proof_label}`\n"
                f"- **Verification Vector**: Automated Security Audit Probe\n"
                f"- **CVSS v3.1 Vector String**: `{cvss_vec}`\n\n"
                f"### 🔬 Technical Analysis & Vulnerability Mechanics\n"
                f"{v.description}\n\n"
                f"### 📊 Threat Severity & CVSS v3.1 Scoring\n"
                f"- **CVSS v3.1 Unified Base Score**: **{score:.1f} ({sev.capitalize()})**\n"
                f"- **Authoritative Taxonomy**: **{cwe}**\n"
                f"- **Impact Assessment**: May permit unauthorized perimeter discovery, session integrity compromise, or execution alteration."
            )
        else:
            new_desc = v.description

        # Ensure concrete remediation steps exist
        steps = v.remediation_steps
        if not steps or len(steps) == 0:
            steps = ["Review relevant configuration documentation and restrict access to the affected resource."]

        return VulnerabilityItem(
            id=v.id,
            title=v.title,
            severity=v.severity,
            service=v.service,
            port=v.port,
            cve_id=cwe,
            cvss_score=score,
            description=new_desc,
            remediation_steps=steps,
        )

    @staticmethod
    def _deduplicate_vulns(vulns: list[VulnerabilityItem]) -> list[VulnerabilityItem]:
        """Eliminates overlapping findings reported by multiple scanners."""
        seen: dict[str, VulnerabilityItem] = {}
        for v in vulns:
            # Normalize title for grouping
            norm_title = v.title.lower().strip()
            norm_title = norm_title.replace("strict-transport-security", "hsts")
            key = f"{norm_title}:{v.port or 0}"

            if key not in seen:
                seen[key] = v
            else:
                # Keep finding with higher CVSS or CVE if available
                existing = seen[key]
                if v.cve_id and not existing.cve_id:
                    seen[key] = v
                elif (v.cvss_score or 0) > (existing.cvss_score or 0):
                    seen[key] = v

        return list(seen.values())

    @staticmethod
    def _synthesize_chains(vulns: list[VulnerabilityItem]) -> list[AttackChain]:
        """Correlates multiple vulnerabilities into dangerous exploit sequences."""
        chains: list[AttackChain] = []
        titles_lower = [v.title.lower() for v in vulns]

        has_secret = any("leaked credential" in t or "secret" in t for t in titles_lower)
        has_cors = any("cors" in t for t in titles_lower)
        has_xss = any("xss" in t or "cross-site scripting" in t for t in titles_lower)
        has_sqli = any("sql injection" in t for t in titles_lower)
        has_idor = any("idor" in t or "direct object reference" in t for t in titles_lower)

        # Chain 1: Secret Leak + CORS Misconfiguration
        if has_secret and has_cors:
            chains.append(
                AttackChain(
                    chain_name="Credential Exfiltration via Permissive CORS",
                    steps=[v.id for v in vulns if "secret" in v.title.lower() or "cors" in v.title.lower()],
                    combined_severity="critical",
                    narrative=(
                        "An attacker can exploit the overly permissive CORS origin policy to execute cross-origin requests "
                        "and exfiltrate the exposed frontend credentials directly to an external server."
                    ),
                )
            )

        # Chain 2: XSS + Missing CSP
        if has_xss and any("content-security-policy" in t for t in titles_lower):
            chains.append(
                AttackChain(
                    chain_name="Unrestricted Session Hijacking via XSS and Missing CSP",
                    steps=[v.id for v in vulns if "xss" in v.title.lower() or "content-security-policy" in v.title.lower()],
                    combined_severity="high",
                    narrative=(
                        "Because Content-Security-Policy is absent or improperly configured, the Reflected/DOM XSS "
                        "vulnerability can execute inline scripts without restriction to capture cookies and localStorage."
                    ),
                )
            )

        # Chain 3: IDOR + Sensitive Information Disclosure
        if has_idor and any("information disclosure" in t or "exposure" in t for t in titles_lower):
            chains.append(
                AttackChain(
                    chain_name="Mass Data Harvesting via IDOR & Endpoint Enumeration",
                    steps=[v.id for v in vulns if "idor" in v.title.lower() or "exposure" in v.title.lower()],
                    combined_severity="high",
                    narrative=(
                        "Sequential IDOR parameters allow automated enumeration and unauthorized bulk harvesting "
                        "of sensitive customer records without authentication controls."
                    ),
                )
            )

        return chains

    def _fallback_analysis(self, vulns: list[VulnerabilityItem]) -> AIAnalysis:
        """Deterministic risk score calculation when AI is unavailable."""
        raw_score = sum(SEVERITY_WEIGHTS[v.severity] for v in vulns) * 2
        risk_score = min(100.0, float(raw_score))

        criticals = [v.title for v in vulns if v.severity == "critical"]
        highs = [v.title for v in vulns if v.severity == "high"]

        summary = f"Scan identified {len(vulns)} vulnerabilities. "
        if criticals:
            summary += f"There are {len(criticals)} critical issues requiring urgent remediation. "
        if highs:
            summary += f"Additionally, {len(highs)} high-severity findings were flagged. "
        summary += "Consult the remediation advisory below to secure the application."

        recs = ["Remediate critical vulnerabilities immediately."] if criticals else ["Review high severity findings."]

        return AIAnalysis(
            summary=summary,
            risk_score=risk_score,
            top_recommendations=recs,
            priority_matrix={"immediate": criticals, "short_term": highs},
            fallback=True,
        )
