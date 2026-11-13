"""
Orion Security Platform — Nmap Scanner Wrapper & Native Socket Scanner.

PURPOSE: Executes Nmap safely via subprocess and parses the resulting XML.
Maps known dangerous services to vulnerabilities.
Provides an asynchronous pure-Python TCP socket port scanner fallback
when Nmap binary is absent on the host.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import xml.etree.ElementTree as ET
from typing import Any

from orion.core.schemas import SanitizedTarget, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)

# Static mapping of dangerous services/ports.
DANGEROUS_SERVICES = {
    21: ("FTP", "medium", "FTP transmits data in cleartext and is frequently targeted by attackers.", 
         ["Disable FTP. Use SFTP or SCP instead."]),
    23: ("Telnet", "critical", "Telnet transmits data (including passwords) in cleartext.", 
         ["Disable Telnet. Use SSH instead."]),
    445: ("SMB", "high", "SMB is a common ransomware vector. Ensure it is fully patched and not exposed to the internet.", 
          ["Apply MS17-010 patch. Block port 445 at the perimeter firewall."]),
    3389: ("RDP", "medium", "Remote Desktop is exposed. Ensure strong passwords and MFA are enabled.", 
           ["Restrict RDP access via VPN or firewall."]),
}


class NmapScanner(ToolInterface):
    name = "nmap"

    async def _run_impl(self, target: SanitizedTarget, options: dict[str, Any]) -> list[VulnerabilityItem]:
        nmap_bin = shutil.which("nmap")

        if nmap_bin:
            cmd = [
                nmap_bin,
                "-sV", "--version-light",
                "--script", "default,smb-vuln-ms17-010",
                "-T4", "--max-retries", "2",
                "-Pn",
                "-oX", "-"
            ]
            if ":" in target.resolved_ip:
                cmd.append("-6")
            cmd.append(target.resolved_ip)

            try:
                returncode, stdout, stderr = await self.run_subprocess(cmd, timeout=300)
                if returncode == 0 and stdout.strip():
                    return await self.parse_output(stdout, target)
            except Exception as e:
                logger.warning(f"Nmap CLI execution failed, switching to native socket scanner: {e}")

        # Native Python TCP socket port scanner fallback
        return await self._python_socket_scan(target)

    async def _python_socket_scan(self, target: SanitizedTarget) -> list[VulnerabilityItem]:
        """Asynchronous pure-Python TCP port scanner."""
        vulns: list[VulnerabilityItem] = []
        host = target.hostname
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443]

        async def _probe(p: int) -> int | None:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, p),
                    timeout=1.5
                )
                writer.close()
                await writer.wait_closed()
                return p
            except Exception:
                return None

        tasks = [_probe(p) for p in ports]
        open_ports = await asyncio.gather(*tasks, return_exceptions=False)

        for p in open_ports:
            if not p:
                continue
            if p in DANGEROUS_SERVICES:
                svc, sev, desc, rec = DANGEROUS_SERVICES[p]
                vulns.append(
                    self.make_vuln(
                        title=f"Insecure Service Port Exposed: {svc} (Port {p})",
                        severity=sev,
                        service=svc.lower(),
                        port=p,
                        description=desc,
                        remediation_steps=rec,
                    )
                )
            elif p in [1433, 1521, 3306, 5432, 6379]:
                vulns.append(
                    self.make_vuln(
                        title=f"Exposed Database Service: Port {p}",
                        severity="high",
                        service="database",
                        port=p,
                        description=f"Database port {p} is directly accessible over the public network.",
                        remediation_steps=["Bind database listener only to localhost (127.0.0.1) or restrict access via firewall."]
                    )
                )
            elif p in [8080, 8443]:
                vulns.append(
                    self.make_vuln(
                        title=f"Alternative HTTP Service Detected on Port {p}",
                        severity="info",
                        service="http",
                        port=p,
                        description=f"Port {p} is running an alternative web service or administration interface.",
                        remediation_steps=["Audit services running on alternative web ports."]
                    )
                )
        return vulns

    async def parse_output(self, raw_output: str, target: SanitizedTarget) -> list[VulnerabilityItem]:
        vulns = []
        if not raw_output.strip():
            return vulns

        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError as e:
            logger.warning("Failed to parse Nmap XML output: %s", e)
            return vulns

        for host in root.findall("host"):
            ports = host.find("ports")
            if ports is None:
                continue

            for port in ports.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_id = int(port.get("portid", 0))
                service = port.find("service")
                service_name = service.get("name", "unknown") if service is not None else "unknown"
                product = service.get("product", "") if service is not None else ""
                version = service.get("version", "") if service is not None else ""

                full_service = f"{product} {version}".strip() or service_name

                # Check static mapping of dangerous services
                if port_id in DANGEROUS_SERVICES:
                    svc_name, severity, desc, recs = DANGEROUS_SERVICES[port_id]
                    vulns.append(self.make_vuln(
                        title=f"Exposed Insecure Service: {svc_name} (Port {port_id})",
                        severity=severity,
                        service=full_service,
                        port=port_id,
                        description=f"Nmap detected an open port running {svc_name}.\n{desc}",
                        remediation_steps=recs
                    ))

                # Check NSE script results for vulnerabilities
                for script in port.findall("script"):
                    script_id = script.get("id", "")
                    script_output = script.get("output", "")

                    if "VULNERABLE" in script_output.upper():
                        cve = None
                        cvss = None
                        for elem in script.iter():
                            if elem.tag == "table" and elem.get("key") == "cve":
                                for val in elem.findall("elem"):
                                    cve = val.text
                                    break
                            if elem.tag == "elem" and elem.get("key") == "cvss":
                                try:
                                    cvss = float(elem.text or 0)
                                except ValueError:
                                    pass

                        vulns.append(self.make_vuln(
                            title=f"Vulnerability Detected by NSE Script: {script_id}",
                            severity="critical",
                            service=full_service,
                            port=port_id,
                            cve_id=cve,
                            cvss_score=cvss,
                            description=f"Nmap NSE script '{script_id}' flagged this port as VULNERABLE.\nOutput:\n{script_output}",
                            remediation_steps=["Patch the affected service immediately or disable the port."]
                        ))

        return vulns
