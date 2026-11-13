"""
Orion Security Platform — Core Database Layer (SQLAlchemy ORM).

Defines the relational tables:
  users, targets, scans, vulnerabilities, knowledgebase_articles
Supports PostgreSQL (Production) and SQLite (Development/Test) seamlessly.
"""
from __future__ import annotations

import os
import uuid
from datetime import date, datetime
from typing import Any, Dict, Generator, List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session

# ──────────────────────────────────────────────────────────────
# Database Engine & Session Configuration
# ──────────────────────────────────────────────────────────────

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./orion.db")

# In SQLite, thread-check needs to be disabled for multi-threaded / async FastAPI access
engine_kwargs: dict[str, Any] = {}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Dependency that yields a database session and closes it cleanly."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Creates all database tables defined in the metadata."""
    Base.metadata.create_all(bind=engine)


# ──────────────────────────────────────────────────────────────
# ORM Models
# ──────────────────────────────────────────────────────────────

class User(Base):
    """Platform user account with subscription plan and daily scan quota."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(64), unique=True, nullable=True, index=True)
    hashed_password = Column(String(255), nullable=False)
    plan = Column(String(20), default="free", nullable=False)  # "free" | "pro" | "enterprise"
    scans_today = Column(Integer, default=0, nullable=False)
    last_scan_reset = Column(Date, default=date.today, nullable=False)
    
    # Custom AI Settings (BYOK or Local Ollama)
    ai_provider = Column(String(50), nullable=True)  # "custom" | "cloud" | "local_ollama"
    ai_api_key = Column(String(255), nullable=True)
    ai_base_url = Column(String(255), nullable=True)
    ai_model = Column(String(100), nullable=True)
    
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    targets = relationship("Target", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")


class Target(Base):
    """Scan target (Domain, Hostname, or URL)."""
    __tablename__ = "targets"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    url = Column(String(500), nullable=False)
    domain = Column(String(255), nullable=True)
    ip = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    user = relationship("User", back_populates="targets")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    """Vulnerability scan session storing execution status, metrics, and graph topology."""
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String(36), ForeignKey("targets.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    target_url = Column(String(500), nullable=False)
    status = Column(String(20), default="pending", nullable=False)  # "pending" | "running" | "completed" | "failed"
    scan_type = Column(String(20), default="full", nullable=False)  # "quick" | "standard" | "full" | "web_only"
    plan = Column(String(20), default="advanced", nullable=False)
    ai_hunter_duration = Column(Integer, default=300, nullable=False)
    risk_score = Column(Float, nullable=True)
    progress = Column(Integer, default=0, nullable=False)
    current_tool = Column(String(50), nullable=True)
    
    # Serialized Payloads (React Flow topology, Attack chains, Executive AI analysis)
    raw_results = Column(JSON, default=dict)
    ai_analysis = Column(JSON, default=dict)
    attack_graph = Column(JSON, default=dict)
    attack_chains = Column(JSON, default=list)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class Vulnerability(Base):
    """Structured security vulnerability finding adhering to the 4-section format."""
    __tablename__ = "vulnerabilities"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    severity = Column(String(20), nullable=False)  # "critical" | "high" | "medium" | "low" | "info"
    service = Column(String(100), default="http", nullable=False)
    port = Column(Integer, nullable=True)
    cve_id = Column(String(64), nullable=True)
    cvss_score = Column(Float, nullable=True)
    description = Column(Text, nullable=False)
    remediation_steps = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationship
    scan = relationship("Scan", back_populates="vulnerabilities")


class KnowledgebaseArticle(Base):
    """OWASP Top 10 security reference article with remediation code."""
    __tablename__ = "knowledgebase_articles"

    id = Column(String(100), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False)
    cwe_id = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text, nullable=False)
    vulnerable_code = Column(Text, nullable=True)
    remediation_code = Column(Text, nullable=True)
    references = Column(JSON, default=list)
