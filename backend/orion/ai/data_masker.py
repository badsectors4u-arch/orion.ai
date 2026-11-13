"""
Orion Security Platform — Data Masker.

PURPOSE: Redacts sensitive data (IPv4, IPv6, emails, and the target hostname/URL)
before sending it to an external Cloud AI provider, preserving privacy.

IMPORTANT FOR MEMBER 2 (BACKEND):
Do NOT share a DataMasker instance across Celery tasks. 
Instantiate a new one per scan using `DataMasker.create_fresh()`.
"""
from __future__ import annotations

import re


class DataMasker:
    def __init__(self) -> None:
        # Maps placeholder -> original (for unmasking)
        self.placeholder_to_original: dict[str, str] = {}
        # Maps original -> placeholder (for consistent masking)
        self.original_to_placeholder: dict[str, str] = {}

        # Compiled regexes for performance and safety
        self.ipv4_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        self.ipv6_pattern = re.compile(
            r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|"
            r"\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b|"
            r"\b::(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}\b"
        )
        self.email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

    @classmethod
    def create_fresh(cls) -> "DataMasker":
        """Factory method to ensure a clean instance per scan."""
        return cls()

    def add_known(self, value: str, label: str = "TARGET") -> None:
        """
        Pre-registers a known sensitive value (like hostname or URL) 
        so it gets masked consistently across all fields.
        """
        if not value or value in self.original_to_placeholder:
            return
            
        placeholder = f"[REDACTED-{label}-{len(self.original_to_placeholder) + 1}]"
        self.original_to_placeholder[value] = placeholder
        self.placeholder_to_original[placeholder] = value

    def _mask_match(self, match: re.Match, label: str) -> str:
        original = match.group(0)
        
        # If it's already in our map, use the existing placeholder (Fixes the duplicate IP bug)
        if original in self.original_to_placeholder:
            return self.original_to_placeholder[original]
            
        # Otherwise, create a new placeholder
        placeholder = f"[REDACTED-{label}-{len(self.original_to_placeholder) + 1}]"
        self.original_to_placeholder[original] = placeholder
        self.placeholder_to_original[placeholder] = original
        return placeholder

    def mask_text(self, text: str) -> str:
        """Replaces IPv4, IPv6, emails, and known values with placeholders."""
        if not text:
            return text

        masked = text

        # 1. Mask known targets (URLs, hostnames)
        # Sort by length descending to catch full URLs before hostnames
        for original in sorted(self.original_to_placeholder.keys(), key=len, reverse=True):
            if not original.startswith("[REDACTED"):
                masked = masked.replace(original, self.original_to_placeholder[original])

        # 2. Mask Regex Patterns
        masked = self.ipv4_pattern.sub(lambda m: self._mask_match(m, "IP"), masked)
        masked = self.ipv6_pattern.sub(lambda m: self._mask_match(m, "IP"), masked)
        masked = self.email_pattern.sub(lambda m: self._mask_match(m, "EMAIL"), masked)

        return masked

    def unmask_text(self, text: str) -> str:
        """Restores placeholders back to original data."""
        if not text:
            return text
        
        restored = text
        for placeholder, original in self.placeholder_to_original.items():
            restored = restored.replace(placeholder, original)
        return restored