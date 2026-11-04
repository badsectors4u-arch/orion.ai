"""
Orion Security Platform — Master Scan Orchestrator (Multi-Phase AI Pipeline).

PURPOSE: Coordinates the 5-phase intelligent security scanning pipeline:
  Phase 1: Reconnaissance (httpx + WhatWeb + subfinder) [Parallel]
  🧠 AI Decision Point #1: Tech & Subdomain Intelligence Analysis
  Phase 2: Discovery & Crawling (katana + gau + LinkFinder + SecretFinder + Arjun)
  🧠 AI Decision Point #2: Attack Surface Planning & Prioritization
  Phase 3: Core Scanning (Headers + SSL + Nmap)
  Phase 4: Vulnerability Hunting (nuclei + dalfox + SQLMap + ffuf + Corsy + jwt_tool + IDOR)
  🧠 AI Decision Point #3: Smart Deduplication, Attack Chains, & Risk Scoring
  Phase 5: Attack Graph & Final Reporting

This is the MAIN ENTRY POINT called by Member 2 inside Celery worker tasks.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Optional

from orion.ai.attack_graph_generator import AttackGraphGenerator
from orion.ai.attack_planner import AttackPlanner
from orion.ai.data_masker import DataMasker
from orion.ai.deep_hunter import AIDeepHunter
from orion.ai.ghost_analyst import GhostAnalyst
from orion.ai.recon_analyzer import ReconAnalyzer
from orion.ai.universal_ai_adapter import UniversalAIAdapter
from orion.core.input_sanitizer import sanitize_target
from orion.core.schemas import (
    AttackChain,
    AttackPlan,
    DiscoveryResult,
    ProgressMessage,
    ReconResult,
    SanitizedTarget,
    ScanResult,
    ToolResult,
    VulnerabilityItem,
)
from orion.core.tools.discovery.arjun_scanner import ArjunScanner
from orion.core.tools.discovery.gau_fetcher import GauFetcher
from orion.core.tools.discovery.katana_crawler import KatanaCrawler
from orion.core.tools.discovery.linkfinder_scanner import LinkFinderScanner
from orion.core.tools.discovery.secretfinder_scanner import SecretFinderScanner
from orion.core.tools.nmap_scanner import NmapScanner
from orion.core.tools.recon.httpx_scanner import HttpxScanner
from orion.core.tools.recon.subfinder_scanner import SubfinderScanner
from orion.core.tools.recon.whatweb_scanner import WhatWebScanner
from orion.core.tools.sqlmap_scanner import SqlmapScanner
from orion.core.tools.vuln_scanners.corsy_scanner import CorsyScanner
from orion.core.tools.vuln_scanners.dalfox_scanner import DalfoxScanner
from orion.core.tools.vuln_scanners.ffuf_scanner import FfufScanner
from orion.core.tools.vuln_scanners.idor_checker import IdorChecker
from orion.core.tools.vuln_scanners.jwt_scanner import JwtScanner
from orion.core.tools.vuln_scanners.nuclei_scanner import NucleiScanner
from orion.core.tools.web_scanners import HeadersAnalyzer, SSLChecker, XSSScanner

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    def __init__(self, ai_config: dict[str, Any] | None = None):
        # 1. Initialize Universal AI Brain
        if ai_config:
            self.ai_adapter = UniversalAIAdapter(ai_config)
        else:
            default_p = os.getenv("AI_PROVIDER") or ("custom" if os.getenv("AI_API_KEY") else "cloud")
            self.ai_adapter = UniversalAIAdapter({"provider": default_p})

        # 2. AI Decision Modules
        self.recon_analyzer = ReconAnalyzer(self.ai_adapter)
        self.attack_planner = AttackPlanner(self.ai_adapter)
        self.graph_gen = AttackGraphGenerator(self.ai_adapter)
        self.analyst = GhostAnalyst(self.ai_adapter)
        self.deep_hunter = AIDeepHunter(self.ai_adapter)

    async def _publish_progress(
        self,
        redis_client: Any,
        scan_id: str,
        percentage: int,
        tool: str | None,
        message: str,
        phase: Optional[str] = None,
        phase_number: Optional[int] = None,
    ) -> None:
        """Publishes real-time progress to Redis Pub/Sub for WebSocket transmission."""
        if not redis_client or not scan_id:
            return

        msg = ProgressMessage(
            scan_id=scan_id,
            percentage=percentage,
            current_tool=tool,
            message=message,
            phase=phase,
            phase_number=phase_number,
        )
        try:
            await redis_client.publish(f"scan:{scan_id}", msg.model_dump_json())
        except Exception as e:
            logger.warning(f"Failed to publish progress to Redis: {e}")

    async def _run_tool_safe(
        self,
        tool: Any,
        target: SanitizedTarget,
        options: Optional[dict[str, Any]] = None,
    ) -> list[VulnerabilityItem]:
        """Runs a tool safely; catches exceptions to maintain pipeline resilience."""
        try:
            result: ToolResult = await tool.run(target, options or {})
            if not result.success:
                logger.warning(f"Tool {tool.name} failed: {result.error}")
                return []
            return result.vulnerabilities
        except Exception as e:
            logger.error(f"Tool {tool.name} crashed: {e}")
            return []

    async def run_full_scan(
        self,
        target_url: str,
        scan_type: str = "full",
        scan_id: str | None = None,
        redis_client: Any = None,
        allow_private: bool = False,
        plan: str = "advanced",
        ai_hunter_duration: int = 300,
    ) -> ScanResult:
        """
        Master Pipeline Runner. Coordinates Phases 1 through 5.
        """
        start_time = time.monotonic()
        all_vulns: list[VulnerabilityItem] = []
        tools_used: list[str] = []

        recon_result = ReconResult()
        discovery_result = DiscoveryResult()
        attack_chains: list[AttackChain] = []

        # ──────────────────────────────────────────────────────────
        # Phase 0: Validation & Sanitization (0% - 5%)
        # ──────────────────────────────────────────────────────────
        await self._publish_progress(redis_client, scan_id, 3, None, "Validating target and DNS resolution...")
        try:
            target = await sanitize_target(target_url, allow_private=allow_private)
        except ValueError as e:
            logger.error(f"Target validation failed: {e}")
            raise e

        # Mask sensitive data
        masker = DataMasker.create_fresh()
        masker.add_known(target.hostname, "HOST")
        masker.add_known(target.url, "URL")

        # ──────────────────────────────────────────────────────────
        # Phase 1: Reconnaissance (5% - 15%) [Quick skips this]
        # ──────────────────────────────────────────────────────────
        if scan_type in ["standard", "full"]:
            await self._publish_progress(
                redis_client, scan_id, 6, "recon",
                "Phase 1: Gathering passive tech stack and subdomain intelligence...",
                phase="reconnaissance", phase_number=1
            )

            httpx_scanner = HttpxScanner()
            whatweb_scanner = WhatWebScanner()
            subfinder_scanner = SubfinderScanner()

            # Execute reconnaissance tools in parallel
            t_httpx = httpx_scanner.fingerprint(target)
            t_whatweb = whatweb_scanner.detect_cms(target)
            t_subfinder = subfinder_scanner.enumerate_subdomains(target)

            res_httpx, res_whatweb, res_subfinder = await asyncio.gather(
                t_httpx, t_whatweb, t_subfinder, return_exceptions=True
            )

            # Process httpx
            if isinstance(res_httpx, tuple):
                recon_result.tech_fingerprint = res_httpx[0]
                all_vulns.extend(res_httpx[1])
                tools_used.append("httpx")

            # Process WhatWeb
            if isinstance(res_whatweb, tuple):
                recon_result.cms_info = res_whatweb[0]
                all_vulns.extend(res_whatweb[1])
                tools_used.append("whatweb")

            # Process Subfinder
            if isinstance(res_subfinder, tuple):
                recon_result.subdomains = res_subfinder[0]
                recon_result.live_subdomains = [s.subdomain for s in res_subfinder[0] if s.is_alive]
                all_vulns.extend(res_subfinder[1])
                tools_used.append("subfinder")

            # 🧠 AI Decision Point #1 (15% - 17%)
            await self._publish_progress(
                redis_client, scan_id, 15, "ai_recon",
                "AI Decision Point #1: Analyzing tech stack and optimizing crawl profiles...",
                phase="reconnaissance", phase_number=1
            )
            ai_recon_decisions = await self.recon_analyzer.analyze(recon_result, target.url)

        # ──────────────────────────────────────────────────────────
        # Phase 2: Discovery & Crawling (17% - 40%) [Full only]
        # ──────────────────────────────────────────────────────────
        if scan_type == "full":
            await self._publish_progress(
                redis_client, scan_id, 18, "crawler",
                "Phase 2: Spidering target and harvesting web archives...",
                phase="discovery", phase_number=2
            )

            crawler = KatanaCrawler()
            gau = GauFetcher()

            crawl_options = {
                "priority_paths": ai_recon_decisions.get("priority_paths", []) if "ai_recon_decisions" in locals() else [],
                "subdomains": recon_result.live_subdomains,
            }

            # Parallel: Katana web crawl + GAU archive mining
            c_res, g_res = await asyncio.gather(
                crawler.crawl(target, crawl_options),
                gau.fetch_urls(target),
                return_exceptions=True
            )

            if isinstance(c_res, tuple):
                discovery_result.crawled_urls, discovery_result.forms, discovery_result.js_files = c_res
                tools_used.append("katana")

            if isinstance(g_res, list):
                discovery_result.archived_urls = g_res
                tools_used.append("gau")

            # Parallel JS & Parameter Analysis
            await self._publish_progress(
                redis_client, scan_id, 28, "js_analysis",
                "Phase 2: Analyzing JavaScript endpoints, secrets, and hidden parameters...",
                phase="discovery", phase_number=2
            )

            linkfinder = LinkFinderScanner()
            secretfinder = SecretFinderScanner()
            arjun = ArjunScanner()

            all_discovered_urls = discovery_result.crawled_urls + discovery_result.archived_urls

            lf_task = linkfinder.extract_endpoints(discovery_result.js_files)
            sf_task = secretfinder.find_secrets(discovery_result.js_files, target)
            arjun_task = arjun.discover_params(all_discovered_urls[:5], target)

            lf_res, sf_res, arj_res = await asyncio.gather(
                lf_task, sf_task, arjun_task, return_exceptions=True
            )

            if isinstance(lf_res, list):
                discovery_result.js_endpoints = lf_res
                tools_used.append("linkfinder")

            if isinstance(sf_res, tuple):
                discovery_result.leaked_secrets = sf_res[0]
                all_vulns.extend(sf_res[1])  # Leaked secrets added directly as critical vulns
                tools_used.append("secretfinder")

            if isinstance(arj_res, dict):
                discovery_result.hidden_params = arj_res
                tools_used.append("arjun")

        # 🧠 AI Decision Point #2 (40% - 42%)
        attack_plan = AttackPlan()
        if scan_type in ["standard", "full"]:
            await self._publish_progress(
                redis_client, scan_id, 41, "ai_planner",
                "AI Decision Point #2: Prioritizing attack surface & synthesizing exploit paths...",
                phase="discovery", phase_number=2
            )
            attack_plan = await self.attack_planner.build_plan(
                recon_result, discovery_result, target.url, immediate_vulns=[]
            )

        # ──────────────────────────────────────────────────────────
        # Phase 3: Core Scanners (42% - 55%) [Headers, SSL, Nmap]
        # ──────────────────────────────────────────────────────────
        await self._publish_progress(
            redis_client, scan_id, 43, "headers",
            "Phase 3: Auditing HTTP headers, SSL/TLS certificates, and service ports...",
            phase="core_scanning", phase_number=3
        )

        headers_tool = HeadersAnalyzer()
        ssl_tool = SSLChecker()
        nmap_tool = NmapScanner()

        # Execute Core Scanners
        h_vulns = await self._run_tool_safe(headers_tool, target)
        tools_used.append("headers")
        all_vulns.extend(h_vulns)

        await self._publish_progress(redis_client, scan_id, 47, "ssl", "Auditing TLS cryptographic configuration...")
        ssl_vulns = await self._run_tool_safe(ssl_tool, target)
        tools_used.append("ssl")
        all_vulns.extend(ssl_vulns)

        await self._publish_progress(redis_client, scan_id, 51, "nmap", "Executing Nmap service port scan...")
        nmap_vulns = await self._run_tool_safe(nmap_tool, target)
        tools_used.append("nmap")
        all_vulns.extend(nmap_vulns)

        # ──────────────────────────────────────────────────────────
        # Phase 4: Specialized Vulnerability Hunting (55% - 88%)
        # ──────────────────────────────────────────────────────────
        if scan_type in ["standard", "full"]:
            await self._publish_progress(
                redis_client, scan_id, 56, "nuclei",
                "Phase 4: Launching specialized vulnerability hunting engines...",
                phase="vulnerability_hunting", phase_number=4
            )

            # Layer A: High-speed Go engines
            nuclei = NucleiScanner()
            dalfox = DalfoxScanner()
            ffuf = FfufScanner()
            corsy = CorsyScanner()

            nuclei_task = nuclei.run(target, {"tags": attack_plan.nuclei_tags, "urls": attack_plan.nuclei_targets})
            candidate_xss_urls = list(dict.fromkeys(
                attack_plan.xss_targets +
                [u for u in discovery_result.crawled_urls if "?" in u] +
                discovery_result.crawled_urls[:5] +
                [target.url]
            ))
            dalfox_task = dalfox.run(target, {"urls": candidate_xss_urls, "forms": discovery_result.forms})
            ffuf_task = ffuf.run(target, {"urls": attack_plan.ffuf_targets})
            corsy_task = corsy.run(target, {"urls": attack_plan.corsy_targets})

            await self._publish_progress(redis_client, scan_id, 62, "nuclei", "Executing Nuclei CVE templates & fuzzers...")
            res_a = await asyncio.gather(nuclei_task, dalfox_task, ffuf_task, corsy_task, return_exceptions=True)

            for tool_inst, res in zip([nuclei, dalfox, ffuf, corsy], res_a):
                if isinstance(res, ToolResult) and res.success:
                    all_vulns.extend(res.vulnerabilities)
                    tools_used.append(tool_inst.name)

            # Layer B: SQLMap + JWT Tool + IDOR Checker
            if scan_type == "full":
                await self._publish_progress(redis_client, scan_id, 72, "sqlmap", "Testing endpoints for SQL Injection...")
                sqlmap = SqlmapScanner()
                candidate_sqli_urls = list(dict.fromkeys(
                    attack_plan.sqlmap_targets +
                    [u for u in discovery_result.crawled_urls if "?" in u] +
                    [target.url]
                ))
                sqli_vulns = await self._run_tool_safe(
                    sqlmap, target, {"urls": candidate_sqli_urls, "forms": discovery_result.forms}
                )
                tools_used.append("sqlmap")
                all_vulns.extend(sqli_vulns)

                # JWT Scanner
                if attack_plan.jwt_enabled:
                    await self._publish_progress(redis_client, scan_id, 80, "jwt_tool", "Auditing JSON Web Tokens cryptographic security...")
                    jwt_tool = JwtScanner()
                    jwt_vulns = await self._run_tool_safe(
                        jwt_tool, target, {"token": attack_plan.jwt_token, "headers": recon_result.tech_fingerprint.headers}
                    )
                    tools_used.append("jwt_tool")
                    all_vulns.extend(jwt_vulns)

                # IDOR Checker
                if attack_plan.idor_targets:
                    await self._publish_progress(redis_client, scan_id, 84, "idor", "Checking for Broken Object Level Authorization (IDOR)...")
                    idor = IdorChecker()
                    idor_vulns = await self._run_tool_safe(idor, target, {"urls": attack_plan.idor_targets})
                    tools_used.append("idor")
                    all_vulns.extend(idor_vulns)

            # ──────────────────────────────────────────────────────────
            # Phase 4.5: Autonomous AI Deep Hunter (Advanced Plan Exclusive)
            # ──────────────────────────────────────────────────────────
            is_advanced_plan = plan.lower() in ["advanced", "pro", "enterprise", "unlimited"]
            if is_advanced_plan and scan_type == "full":
                duration_sec = float(ai_hunter_duration or 300)
                duration_min = max(1, int(duration_sec // 60))
                await self._publish_progress(
                    redis_client, scan_id, 86, "ai_deep_hunter",
                    f"Phase 4.5: Launching Autonomous AI Deep Hunter ({duration_min}m budget, {plan.capitalize()} Plan)...",
                    phase="vulnerability_hunting", phase_number=4
                )
                h_start = time.monotonic()
                hunter_vulns = await self.deep_hunter.hunt(
                    target=target,
                    recon=recon_result,
                    discovery=discovery_result,
                    existing_vulns=all_vulns,
                    max_duration_seconds=duration_sec,
                )
                h_elapsed = time.monotonic() - h_start
                if hunter_vulns:
                    all_vulns.extend(hunter_vulns)
                    tools_used.append("ai_deep_hunter")

                # Send completion notification
                await self._publish_progress(
                    redis_client, scan_id, 89, "ai_deep_hunter",
                    f"Notification: AI Deep Hunter completed in {h_elapsed:.1f}s. Confirmed {len(hunter_vulns)} findings.",
                    phase="vulnerability_hunting", phase_number=4
                )
            else:
                logger.info(
                    f"Skipping AI Deep Hunter (plan: '{plan}', scan_type: '{scan_type}'). "
                    "Feature exclusive to Advanced/Pro subscription plans."
                )

        # ──────────────────────────────────────────────────────────
        # Phase 5: AI Analysis, Attack Graph & Final Assembly (88% - 100%)
        # ──────────────────────────────────────────────────────────
        await self._publish_progress(
            redis_client, scan_id, 90, "ai_analyst",
            "Phase 5: Correlating findings, generating Attack Graph, and calculating unified risk score...",
            phase="reporting", phase_number=5
        )

        # 🧠 AI Decision Point #3: Smart Deduplication & Attack Chains
        deduped_vulns, attack_chains, ai_analysis = await self.analyst.correlate_and_analyze(
            all_vulns, target.url, recon_result, discovery_result
        )

        # Generate Visual Attack Graph
        await self._publish_progress(redis_client, scan_id, 96, "ai_graph", "Constructing interactive React Flow attack topology...")
        graph = await self.graph_gen.generate(deduped_vulns, target.url)

        duration = time.monotonic() - start_time
        await self._publish_progress(
            redis_client, scan_id, 100, None,
            f"Scan completed successfully in {duration:.1f}s.",
            phase="complete", phase_number=5
        )

        return ScanResult(
            vulnerabilities=deduped_vulns,
            attack_graph=graph,
            ai_analysis=ai_analysis,
            risk_score=ai_analysis.risk_score,
            tools_used=list(set(tools_used)),
            scan_duration_seconds=round(duration, 2),
            recon=recon_result if scan_type in ["standard", "full"] else None,
            discovery=discovery_result if scan_type == "full" else None,
            attack_chains=attack_chains,
        )
