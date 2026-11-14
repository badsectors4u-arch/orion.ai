"""
Orion Security Platform — Tool Interface (Base Class).

Every scanner (Nmap, SQLMap, Headers, XSS, SSL) subclasses ToolInterface.
The contract:

    result: ToolResult = await tool.run(target, options)
    # result.success == False on ANY failure — never raises.
    # result.vulnerabilities is always a list (empty on failure).

This ensures the Orchestrator can treat every tool uniformly: wrap in 
try/except, log, and continue with remaining tools.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

from orion.core.schemas import (
    SEVERITY_WEIGHTS,
    SanitizedTarget,
    ToolResult,
    VulnerabilityItem,
)

logger = logging.getLogger(__name__)

MAX_OUTPUT_BYTES = 1024 * 1024  # 1 MB cap on captured stdout
DEFAULT_TIMEOUT = 120.0
SIGTERM_GRACE_SECONDS = 5.0


class ToolInterface(ABC):
    """
    Abstract base for all Orion scanners.
    Subclasses must set `name` and implement `_run_impl()` + `parse_output()`.
    """

    name: str = "base"

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout

    # ──────────────────────────────────────────────────────────────────
    # Public API — called by the orchestrator
    # ──────────────────────────────────────────────────────────────────
    async def run(
        self,
        target: SanitizedTarget,
        options: Optional[dict[str, Any]] = None,
    ) -> ToolResult:
        """
        Execute the tool and return a ToolResult. Never raises — errors
        are captured in `result.error` with `result.success=False`.
        """
        options = options or {}
        started = time.monotonic()
        try:
            vulns = await self._run_impl(target, options)
            return ToolResult(
                tool_name=self.name,
                success=True,
                vulnerabilities=vulns,
                duration_seconds=time.monotonic() - started,
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "tool=%s target=%s failed: %s",
                self.name, target.url, e, exc_info=True,
            )
            return ToolResult(
                tool_name=self.name,
                success=False,
                vulnerabilities=[],
                duration_seconds=time.monotonic() - started,
                error=f"{type(e).__name__}: {e}",
            )

    # ──────────────────────────────────────────────────────────────────
    # Subclass implementation points
    # ──────────────────────────────────────────────────────────────────
    @abstractmethod
    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        """Actual tool logic. May raise; `run()` converts to ToolResult."""

    @abstractmethod
    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        """Parse tool output into validated VulnerabilityItem objects."""

    # ──────────────────────────────────────────────────────────────────
    # Shared helpers
    # ──────────────────────────────────────────────────────────────────
    def make_vuln(
        self,
        *,
        title: str,
        severity: str,
        service: str,
        description: str,
        remediation_steps: list[str],
        port: Optional[int] = None,
        cve_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
    ) -> VulnerabilityItem:
        """Standard constructor for a finding."""
        return VulnerabilityItem(
            title=title,
            severity=severity,       # type: ignore[arg-type]
            service=service,
            port=port,
            cve_id=cve_id,
            cvss_score=cvss_score,
            description=description,
            remediation_steps=remediation_steps,
        )

    @staticmethod
    def severity_to_cvss(severity: str) -> float:
        """Default CVSS when a tool doesn't know the real score."""
        return {"critical": 9.5, "high": 8.0, "medium": 5.5,
                "low": 2.5, "info": 0.0}.get(severity.lower(), 5.0)

    @staticmethod
    def compute_risk_score(vulns: list[VulnerabilityItem]) -> float:
        """Deterministic risk score — the fallback used when AI fails."""
        if not vulns:
            return 0.0
        raw = sum(SEVERITY_WEIGHTS[v.severity] for v in vulns) * 2
        return min(100.0, float(raw))

    # ──────────────────────────────────────────────────────────────────
    # Safe subprocess runner — used by Nmap and SQLMap
    # ──────────────────────────────────────────────────────────────────
    async def run_subprocess(
        self,
        cmd: list[str],
        *,
        timeout: Optional[float] = None,
        cwd: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
    ) -> tuple[int, str, str]:
        """
        Run an external command SAFELY.
        - Never uses `shell=True` — argument list only.
        - Creates a new process group so timeout kills ALL children.
        - Caps captured stdout/stderr at MAX_OUTPUT_BYTES.
        - Strips sensitive API keys from the environment.
        """
        if not cmd or not isinstance(cmd[0], str):
            raise ValueError("cmd must be a non-empty list of strings.")
        
        # NOTE: We removed the shell metacharacter check because `shell=False` 
        # makes `&` and `;` safe (they are passed as literal strings to the tool).

        timeout = timeout if timeout is not None else self.timeout
        start = time.monotonic()
        logger.debug("tool=%s exec %s (timeout=%.1fs)", self.name, cmd[0], timeout)

        # Fix: Only pass safe environment variables (prevent API key leaks)
        safe_env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),  # Windows requirement
            "TEMP": os.environ.get("TEMP", ""),
        }
        if env:
            safe_env.update(env)

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=safe_env,
            start_new_session=(os.name != 'nt'),
        )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            await _kill_group(proc)
            raise TimeoutError(
                f"{self.name}: command timed out after {timeout:.0f}s "
                f"({time.monotonic() - start:.1f}s elapsed)"
            )

        return (
            proc.returncode or 0,
            _truncate(stdout_b),
            _truncate(stderr_b),
        )


# ──────────────────────────────────────────────────────────────────────
# Module-level helpers
# ──────────────────────────────────────────────────────────────────────
async def _kill_group(proc: asyncio.subprocess.Process) -> None:
    """Kills the process and all its children (Cross-platform safe)."""
    try:
        if os.name == 'nt':  # Windows: use taskkill to kill the tree
            import subprocess
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        else:                # Linux/macOS: kill the process group
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return

    try:
        await asyncio.wait_for(proc.wait(), timeout=SIGTERM_GRACE_SECONDS)
        return
    except asyncio.TimeoutError:
        pass

    # Force kill
    try:
        if os.name == 'nt':
            proc.kill()
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    await proc.wait()


def _truncate(raw: bytes, limit: int = MAX_OUTPUT_BYTES) -> str:
    if len(raw) <= limit:
        return raw.decode(errors="replace")
    return (
        raw[:limit].decode(errors="replace")
        + f"\n[... truncated {len(raw) - limit} bytes ...]"
    )