"""
Orion Security Platform — Core Services.
Exposes public APIs consumed by Member 2 (Backend) and Member 1 (Frontend).
"""
from orion.services.breach_service import check_email_breach
from orion.services.kb_service import (
    get_article_by_id,
    get_knowledgebase_articles,
    seed_knowledgebase,
)
from orion.services.pdf_generator import generate_pdf_report

__all__ = [
    "check_email_breach",
    "get_knowledgebase_articles",
    "get_article_by_id",
    "seed_knowledgebase",
    "generate_pdf_report",
]

