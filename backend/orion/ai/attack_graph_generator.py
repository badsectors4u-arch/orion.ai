"""
Orion Security Platform — Attack Graph Generator.

PURPOSE: Uses the AI to generate a visual attack chain (React Flow nodes/edges)
from the discovered vulnerabilities. Includes a deterministic rule-based fallback.
"""
from __future__ import annotations

import json
import logging

from orion.ai.universal_ai_adapter import UniversalAIAdapter
from orion.core.schemas import AttackGraphPayload, GraphEdge, GraphNode, VulnerabilityItem

logger = logging.getLogger(__name__)


class AttackGraphGenerator:
    def __init__(self, ai_adapter: UniversalAIAdapter):
        self.ai = ai_adapter

    async def generate(self, vulnerabilities: list[VulnerabilityItem], target_url: str) -> AttackGraphPayload:
        if not vulnerabilities:
            return self._fallback_graph(vulnerabilities, target_url)

        # Prepare data for the AI (no IPs here, just the vuln data)
        vuln_data = [v.model_dump() for v in vulnerabilities]

        system_prompt = """
        You are a SOC Analyst. Given discovered vulnerabilities, generate an attack chain graph.
        Return ONLY valid JSON with this EXACT structure:
        {
          "nodes": [
            {"id": "node-1", "type": "target", "label": "example.com", "severity": "info"},
            {"id": "node-2", "type": "service", "label": "HTTP :80", "severity": "low"},
            {"id": "node-3", "type": "vulnerability", "label": "SQL Injection", "severity": "critical"},
            {"id": "node-4", "type": "root", "label": "Full System Compromise", "severity": "critical"}
          ],
          "edges": [
            {"id": "edge-1-2", "source": "node-1", "target": "node-2", "label": "Exposes", "animated": true},
            {"id": "edge-2-3", "source": "node-2", "target": "node-3", "label": "Exploits via", "animated": true}
          ]
        }
        Rules: 
        1. types MUST be target/service/vulnerability/root. 
        2. severity MUST be critical/high/medium/low/info.
        3. Return ONLY JSON, no markdown, no explanation.
        """

        user_prompt = f"Target: {target_url}\nVulnerabilities:\n{json.dumps(vuln_data, indent=2)}"

        response = await self.ai.call(system_prompt, user_prompt, json_mode=True)

        if response.ok and isinstance(response.data, dict):
            try:
                raw_nodes = response.data.get("nodes", [])
                raw_edges = response.data.get("edges", [])

                clean_nodes: list[GraphNode] = []
                for idx, n in enumerate(raw_nodes):
                    if isinstance(n, dict):
                        node_type = n.get("type", "vulnerability")
                        if node_type not in ["target", "service", "vulnerability", "root"]:
                            node_type = "vulnerability"

                        sev = str(n.get("severity", "info")).lower()
                        if sev not in ["critical", "high", "medium", "low", "info"]:
                            sev = "info"

                        clean_nodes.append(
                            GraphNode(
                                id=str(n.get("id", f"node-{idx}")),
                                type=node_type,
                                label=str(n.get("label", "Vulnerability")),
                                severity=sev,  # type: ignore[arg-type]
                            )
                        )

                clean_edges: list[GraphEdge] = []
                for idx, e in enumerate(raw_edges):
                    if isinstance(e, dict) and "source" in e and "target" in e:
                        clean_edges.append(
                            GraphEdge(
                                id=str(e.get("id", f"edge-{idx}")),
                                source=str(e.get("source")),
                                target=str(e.get("target")),
                                label=str(e.get("label", "relates to")),
                                animated=bool(e.get("animated", False)),
                            )
                        )

                if clean_nodes:
                    return AttackGraphPayload(nodes=clean_nodes, edges=clean_edges)
            except Exception as e:
                logger.warning(f"AI returned invalid graph structure, using fallback. Error: {e}")

        return self._fallback_graph(vulnerabilities, target_url)

    def _fallback_graph(self, vulns: list[VulnerabilityItem], target_url: str) -> AttackGraphPayload:
        """A simple star-graph generated without AI if the API fails."""
        nodes = [GraphNode(id="root-target", type="target", label=target_url, severity="info")]
        edges = []

        # Sort by severity so criticals are at the top
        sorted_vulns = sorted(vulns, key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.severity))

        for i, v in enumerate(sorted_vulns):
            nid = f"vuln-{i}"
            nodes.append(GraphNode(id=nid, type="vulnerability", label=v.title, severity=v.severity))
            edges.append(
                GraphEdge(
                    id=f"edge-{i}",
                    source="root-target",
                    target=nid,
                    label="has vulnerability",
                    animated=(v.severity == "critical"),
                )
            )

        return AttackGraphPayload(nodes=nodes, edges=edges)
