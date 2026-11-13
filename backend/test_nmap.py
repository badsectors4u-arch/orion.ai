import os
import asyncio

# This line permanently fixes the Nmap path issue for this script
os.environ["PATH"] += r";C:\Program Files (x86)\Nmap"

from orion.core.input_sanitizer import sanitize_target
from orion.core.tools.nmap_scanner import NmapScanner

async def test():
    print("=== Testing Nmap Scanner ===")
    target = await sanitize_target("scanme.nmap.org")
    tool = NmapScanner()
    
    print(f"Scanning {target.hostname} (this takes about 30 seconds)...")
    result = await tool.run(target)
    
    if not result.success:
        print(f"\n[FAILED] {result.error}")
        return
        
    print(f"\n[SUCCESS] Scan complete in {result.duration_seconds:.1f}s")
    print(f"Found {len(result.vulnerabilities)} findings:\n")
    
    for v in result.vulnerabilities:
        cve_str = f" [CVE: {v.cve_id}]" if v.cve_id else " [No CVE claimed]"
        print(f"[{v.severity.upper()}] Port {v.port}: {v.title}{cve_str}")
        print(f"         Service: {v.service}")

if __name__ == "__main__":
    asyncio.run(test())