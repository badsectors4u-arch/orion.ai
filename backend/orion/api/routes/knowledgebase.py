"""
Orion Security Platform — Knowledgebase Routes.

Endpoints:
  GET /api/knowledgebase              — List OWASP Top 10 articles (Public)
  GET /api/knowledgebase/{article_id} — Retrieve detailed remediation guidance (Plan-gated)
"""
from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from orion.api.deps import get_current_user_optional, get_db
from orion.models.database import KnowledgebaseArticle, User
from orion.models.schemas import KBArticleDetailResponse, KBArticleResponse
from orion.services.kb_service import get_article_by_id, get_knowledgebase_articles

router = APIRouter(prefix="/api/knowledgebase", tags=["Knowledgebase"])


@router.get("", response_model=List[KBArticleResponse])
def list_articles(
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low"),
    search: Optional[str] = Query(None, description="Search term in title or CWE ID"),
    db: Session = Depends(get_db),
):
    """
    Public endpoint: Lists all security vulnerability reference articles.
    Supports filtering by severity and full-text keyword search.
    """
    query = db.query(KnowledgebaseArticle)

    if severity:
        query = query.filter(KnowledgebaseArticle.severity == severity.lower())
    if search:
        search_filter = f"%{search.lower()}%"
        query = query.filter(
            (KnowledgebaseArticle.title.ilike(search_filter))
            | (KnowledgebaseArticle.cwe_id.ilike(search_filter))
        )

    db_articles = query.all()

    # If DB is empty, fallback dynamically to in-memory OWASP articles
    if not db_articles:
        raw_list = get_knowledgebase_articles()
        results = []
        for a in raw_list:
            if severity and a["severity"].lower() != severity.lower():
                continue
            if search and (search.lower() not in a["title"].lower() and search.lower() not in a["cwe_id"].lower()):
                continue
            results.append(
                KBArticleResponse(
                    id=a["id"],
                    title=a["title"],
                    cwe_id=a["cwe_id"],
                    severity=a["severity"],
                    description=a["description"],
                    references=a.get("references", []),
                )
            )
        return results

    return [
        KBArticleResponse(
            id=str(a.id),
            title=a.title,
            cwe_id=a.cwe_id,
            severity=a.severity,
            description=a.description,
            references=a.references or [],
        )
        for a in db_articles
    ]


@router.get("/{article_id}", response_model=KBArticleDetailResponse)
def get_article_detail(
    article_id: str,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """
    Retrieves full article details including vulnerable code samples.
    Remediation code is plan-gated:
    - Free tier / Unauthenticated: Remediation code is masked (Upgrade required).
    - Pro / Enterprise: Full copy-paste ready remediation source code provided.
    """
    article = (
        db.query(KnowledgebaseArticle)
        .filter(
            (KnowledgebaseArticle.id == article_id)
            | (KnowledgebaseArticle.cwe_id.ilike(article_id))
        )
        .first()
    )

    # Fallback to in-memory lookup if not found in DB
    raw_article = None
    if not article:
        raw_article = get_article_by_id(article_id)
        if not raw_article:
            for item in get_knowledgebase_articles():
                if item["cwe_id"].lower() == article_id.lower():
                    raw_article = item
                    break

    if not article and not raw_article:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Knowledgebase article '{article_id}' not found.",
        )

    # Extract fields
    art_id = str(article.id) if article else raw_article["id"]
    title = article.title if article else raw_article["title"]
    cwe_id = article.cwe_id if article else raw_article["cwe_id"]
    severity = article.severity if article else raw_article["severity"]
    description = article.description if article else raw_article["description"]
    vulnerable_code = article.vulnerable_code if article else raw_article.get("vulnerable_code")
    remediation_code = article.remediation_code if article else raw_article.get("remediation_code")
    references = (article.references or []) if article else raw_article.get("references", [])

    # Plan gate: Pro and Enterprise get remediation code; Free tier gets None
    is_pro_or_enterprise = (
        current_user is not None
        and current_user.plan.lower() in ("pro", "enterprise", "advanced")
    )

    remediation_output = remediation_code if is_pro_or_enterprise else None

    return KBArticleDetailResponse(
        id=art_id,
        title=title,
        cwe_id=cwe_id,
        severity=severity,
        description=description,
        vulnerable_code=vulnerable_code,
        remediation_code=remediation_output,
        references=references,
    )

