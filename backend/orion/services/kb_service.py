"""
Orion Security Platform — OWASP Knowledgebase Service.

PURPOSE: Provides comprehensive educational articles, vulnerable code samples,
and secure remediation code for the OWASP Top 10 vulnerabilities.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

OWASP_ARTICLES: list[dict[str, Any]] = [
    {
        "id": "kb-001-cwe-89-sqli",
        "title": "SQL Injection (SQLi)",
        "cwe_id": "CWE-89",
        "severity": "critical",
        "description": (
            "SQL Injection (SQLi) occurs when untrusted user input is directly concatenated or "
            "interpolated into a dynamic database query without proper validation or parameterization. "
            "Attackers can inject arbitrary SQL commands into the backend database interpreter. "
            "This enables malicious actors to bypass authentication controls, extract confidential "
            "data (including user credentials and financial records), modify or delete database contents, "
            "and in severe cases, execute operating system commands or achieve remote code execution (RCE)."
        ),
        "vulnerable_code": (
            "# Vulnerable Python/FastAPI backend query\n"
            "@app.post('/api/user')\n"
            "async def get_user(username: str, db: Session = Depends(get_db)):\n"
            "    # DANGEROUS: Direct string concatenation allows 'admin' -- or ' OR 1=1 --\n"
            "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
            "    result = db.execute(text(query)).fetchall()\n"
            "    return result\n"
        ),
        "remediation_code": (
            "# Secure remediation using parameterized prepared statements\n"
            "@app.post('/api/user')\n"
            "async def get_user(username: str, db: Session = Depends(get_db)):\n"
            "    # SECURE: Bind parameters ensure input is treated strictly as data, not code\n"
            "    query = text(\"SELECT * FROM users WHERE username = :uname\")\n"
            "    result = db.execute(query, {'uname': username}).fetchall()\n"
            "    return result\n"
        ),
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-34362"
        ]
    },
    {
        "id": "kb-002-cwe-79-xss",
        "title": "Cross-Site Scripting (Reflected & Stored XSS)",
        "cwe_id": "CWE-79",
        "severity": "high",
        "description": (
            "Cross-Site Scripting (XSS) vulnerabilities emerge when web applications include untrusted "
            "data in a web page without adequate validation, sanitization, or context-aware output encoding. "
            "When an unsuspecting victim loads the rendered page, the malicious script executes in the "
            "victim's browser session. An attacker can hijack session tokens, steal sensitive cookies, "
            "deface websites, capture keystrokes, or redirect users to malicious phishing pages."
        ),
        "vulnerable_code": (
            "// Vulnerable React component rendering raw user input\n"
            "function UserGreeting({ queryName }: { queryName: string }) {\n"
            "  // DANGEROUS: dangerouslySetInnerHTML executes arbitrary injected HTML/JS\n"
            "  return (\n"
            "    <div dangerouslySetInnerHTML={{ __html: `<h1>Welcome, ${queryName}!</h1>` }} />\n"
            "  );\n"
            "}\n"
        ),
        "remediation_code": (
            "// Secure React component utilizing built-in automatic escaping\n"
            "function UserGreeting({ queryName }: { queryName: string }) {\n"
            "  // SECURE: React escapes JSX expressions by default; prevents script execution\n"
            "  return (\n"
            "    <div>\n"
            "      <h1>Welcome, {queryName}!</h1>\n"
            "    </div>\n"
            "  );\n"
            "}\n"
        ),
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ]
    },
    {
        "id": "kb-003-cwe-284-broken-access-control",
        "title": "Broken Access Control",
        "cwe_id": "CWE-284",
        "severity": "critical",
        "description": (
            "Access control policies enforce restrictions on which authenticated users can view, modify, "
            "or act upon specific resources. Failures typically lead to unauthorized information disclosure, "
            "modification, or destruction of data, or performing a business function outside the user's "
            "privileges. Examples include bypassing access control checks by modifying the URL, internal "
            "application state, or the HTML page, and elevating privileges without authorization."
        ),
        "vulnerable_code": (
            "@app.delete('/api/scans/{scan_id}')\n"
            "async def delete_scan(scan_id: str, db: Session = Depends(get_db)):\n"
            "    # DANGEROUS: Any user can delete any scan by guessing or iterating scan_id\n"
            "    scan = db.query(Scan).filter(Scan.id == scan_id).first()\n"
            "    db.delete(scan)\n"
            "    db.commit()\n"
            "    return {'status': 'deleted'}\n"
        ),
        "remediation_code": (
            "@app.delete('/api/scans/{scan_id}')\n"
            "async def delete_scan(\n"
            "    scan_id: str, \n"
            "    current_user: User = Depends(get_current_user),\n"
            "    db: Session = Depends(get_db)\n"
            "):\n"
            "    # SECURE: Strictly scope query by current authenticated user's ID\n"
            "    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()\n"
            "    if not scan:\n"
            "        raise HTTPException(status_code=404, detail='Scan not found or unauthorized')\n"
            "    db.delete(scan)\n"
            "    db.commit()\n"
            "    return {'status': 'deleted'}\n"
        ),
        "references": [
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://cwe.mitre.org/data/definitions/284.html"
        ]
    },
    {
        "id": "kb-004-cwe-16-security-misconfiguration",
        "title": "Security Misconfiguration",
        "cwe_id": "CWE-16",
        "severity": "medium",
        "description": (
            "Security misconfiguration happens when security settings in cloud providers, web servers, "
            "application frameworks, or databases are poorly managed, left at insecure defaults, or improperly "
            "hardened. This includes unpatched systems, active default passwords, unneeded services enabled, "
            "missing security headers (such as CSP, HSTS, and X-Frame-Options), and verbose error stack traces "
            "leaking sensitive database or infrastructure details to clients."
        ),
        "vulnerable_code": (
            "# Insecure Nginx configuration\n"
            "server {\n"
            "    listen 80;\n"
            "    server_name example.com;\n"
            "    # DANGEROUS: Missing HSTS, X-Frame-Options, server tokens exposed\n"
            "    server_tokens on;\n"
            "}\n"
        ),
        "remediation_code": (
            "# Hardened Nginx configuration\n"
            "server {\n"
            "    listen 443 ssl http2;\n"
            "    server_name example.com;\n"
            "    server_tokens off;\n"
            "    # SECURE: Enforce HTTPS and essential defense-in-depth headers\n"
            "    add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
            "    add_header X-Frame-Options \"DENY\" always;\n"
            "    add_header X-Content-Type-Options \"nosniff\" always;\n"
            "    add_header Content-Security-Policy \"default-src 'self';\" always;\n"
            "}\n"
        ),
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cwe.mitre.org/data/definitions/16.html"
        ]
    },
    {
        "id": "kb-005-cwe-918-ssrf",
        "title": "Server-Side Request Forgery (SSRF)",
        "cwe_id": "CWE-918",
        "severity": "high",
        "description": (
            "Server-Side Request Forgery flaws occur whenever a web application fetches a remote resource "
            "without properly validating the user-supplied destination URL. An attacker can coerce the "
            "application into sending crafted requests to unexpected destinations, such as loopback interfaces, "
            "internal microservices, private cloud subnets, or metadata services (e.g. 169.254.169.254). "
            "This often results in unauthorized access to sensitive internal APIs and cloud IAM credentials."
        ),
        "vulnerable_code": (
            "# Vulnerable endpoint fetching arbitrary target URLs\n"
            "@app.post('/api/fetch-preview')\n"
            "async def fetch_preview(target_url: str):\n"
            "    # DANGEROUS: Attacker can supply 'http://169.254.169.254/latest/meta-data/'\n"
            "    async with httpx.AsyncClient() as client:\n"
            "        resp = await client.get(target_url)\n"
            "        return resp.text\n"
        ),
        "remediation_code": (
            "# Protected endpoint validating target against blocklists\n"
            "@app.post('/api/fetch-preview')\n"
            "async def fetch_preview(target_url: str):\n"
            "    # SECURE: Validate protocol and reject private/loopback/cloud metadata IPs\n"
            "    target = await sanitize_target(target_url, allow_private=False)\n"
            "    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:\n"
            "        resp = await client.get(target.url)\n"
            "        return resp.text\n"
        ),
        "references": [
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            "https://cwe.mitre.org/data/definitions/918.html"
        ]
    },
    {
        "id": "kb-006-cwe-639-idor",
        "title": "Insecure Direct Object Reference (IDOR)",
        "cwe_id": "CWE-639",
        "severity": "high",
        "description": (
            "Insecure Direct Object Reference (IDOR) is a sub-type of broken access control that occurs when "
            "an application exposes a direct reference to an internal implementation object (such as a database "
            "key, filename, or account number) in an HTTP parameter, and fails to verify whether the requesting "
            "user has authorization to perform the operation on that specific object."
        ),
        "vulnerable_code": (
            "@app.get('/api/invoices/{invoice_id}')\n"
            "async def get_invoice(invoice_id: int, db: Session = Depends(get_db)):\n"
            "    # DANGEROUS: Directly returns invoice without checking ownership\n"
            "    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()\n"
            "    return invoice\n"
        ),
        "remediation_code": (
            "@app.get('/api/invoices/{invoice_id}')\n"
            "async def get_invoice(\n"
            "    invoice_id: int, \n"
            "    current_user: User = Depends(get_current_user),\n"
            "    db: Session = Depends(get_db)\n"
            "):\n"
            "    # SECURE: Verify that current user owns the requested invoice\n"
            "    invoice = db.query(Invoice).filter(\n"
            "        Invoice.id == invoice_id, \n"
            "        Invoice.user_id == current_user.id\n"
            "    ).first()\n"
            "    if not invoice:\n"
            "        raise HTTPException(status_code=404, detail='Invoice not found')\n"
            "    return invoice\n"
        ),
        "references": [
            "https://cwe.mitre.org/data/definitions/639.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
        ]
    },
    {
        "id": "kb-007-cwe-352-csrf",
        "title": "Cross-Site Request Forgery (CSRF)",
        "cwe_id": "CWE-352",
        "severity": "medium",
        "description": (
            "Cross-Site Request Forgery (CSRF) is an attack that forces an authenticated end user to execute "
            "unwanted actions on a web application in which they are currently authenticated. With a little "
            "help of social engineering (like sending a link via chat or email), an attacker may trick the "
            "users of a web application into executing actions of the attacker's choosing (such as password "
            "change or funds transfer)."
        ),
        "vulnerable_code": (
            "# Insecure cookie configuration in session-based authentication\n"
            "response.set_cookie(\n"
            "    key='session_token',\n"
            "    value=token,\n"
            "    httponly=True\n"
            "    # DANGEROUS: Missing SameSite=Strict and Secure flags\n"
            ")\n"
        ),
        "remediation_code": (
            "# Secure cookie configuration resisting CSRF\n"
            "response.set_cookie(\n"
            "    key='session_token',\n"
            "    value=token,\n"
            "    httponly=True,\n"
            "    secure=True,\n"
            "    samesite='Strict'  # SECURE: Browser omits cookie on cross-site requests\n"
            ")\n"
        ),
        "references": [
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://cwe.mitre.org/data/definitions/352.html"
        ]
    },
    {
        "id": "kb-008-cwe-502-insecure-deserialization",
        "title": "Insecure Deserialization",
        "cwe_id": "CWE-502",
        "severity": "critical",
        "description": (
            "Insecure deserialization occurs when untrusted or maliciously crafted data is used to inflict "
            "denial-of-service, execute arbitrary code, or abuse application logic as the payload is unpacked "
            "back into live memory objects. Using native serialization formats like Python's `pickle` on "
            "untrusted network input allows attackers to instantiate dangerous system commands."
        ),
        "vulnerable_code": (
            "import pickle\n"
            "@app.post('/api/load-session')\n"
            "async def load_session(payload: bytes):\n"
            "    # DANGEROUS: pickle.loads executes arbitrary bytecode embedded in payload\n"
            "    session_data = pickle.loads(payload)\n"
            "    return session_data\n"
        ),
        "remediation_code": (
            "import json\n"
            "@app.post('/api/load-session')\n"
            "async def load_session(payload: str):\n"
            "    # SECURE: JSON is a data-only interchange format; no code execution possible\n"
            "    session_data = json.loads(payload)\n"
            "    return session_data\n"
        ),
        "references": [
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
            "https://cwe.mitre.org/data/definitions/502.html"
        ]
    },
    {
        "id": "kb-009-cwe-1104-vulnerable-components",
        "title": "Vulnerable and Outdated Components",
        "cwe_id": "CWE-1104",
        "severity": "high",
        "description": (
            "Applications that depend on libraries, frameworks, and other software modules with known "
            "vulnerabilities (published CVEs) expand the attack surface. Attackers use automated tools to "
            "identify unpatched versions and exploit established attack vectors. Regular software composition "
            "analysis (SCA) and continuous dependency scanning are mandatory."
        ),
        "vulnerable_code": (
            "# Insecure requirements.txt specifying outdated, vulnerable libraries\n"
            "cryptography==3.3.1  # Vulnerable to buffer overflows\n"
            "urllib3==1.26.4       # Vulnerable to ReDoS and header injection\n"
        ),
        "remediation_code": (
            "# Hardened requirements.txt with pinned patched versions\n"
            "cryptography>=42.0.0\n"
            "urllib3>=2.0.7\n"
            "# Automated check: pip-audit or dependabot in CI/CD pipeline\n"
        ),
        "references": [
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            "https://cwe.mitre.org/data/definitions/1104.html"
        ]
    },
    {
        "id": "kb-010-cwe-778-insufficient-logging",
        "title": "Security Logging and Monitoring Failures",
        "cwe_id": "CWE-778",
        "severity": "medium",
        "description": (
            "Insufficient logging, detection, monitoring, and active incident response leaves organizations "
            "blind to ongoing attacks. Without comprehensive audit trails, security breaches cannot be detected "
            "in real time, forensics investigations are crippled, and attackers can maintain long-term persistence "
            "within the infrastructure unnoticed."
        ),
        "vulnerable_code": (
            "@app.post('/api/auth/login')\n"
            "async def login(credentials: LoginRequest):\n"
            "    user = authenticate(credentials)\n"
            "    if not user:\n"
            "        # DANGEROUS: Silent failure, brute-force attempts are unrecorded\n"
            "        raise HTTPException(status_code=401)\n"
            "    return {'token': create_token(user)}\n"
        ),
        "remediation_code": (
            "@app.post('/api/auth/login')\n"
            "async def login(credentials: LoginRequest, request: Request):\n"
            "    user = authenticate(credentials)\n"
            "    if not user:\n"
            "        # SECURE: Structured audit logging with client IP, timestamp and counter\n"
            "        logger.warning(\n"
            "            'Failed login attempt for user=%s from ip=%s',\n"
            "            credentials.username, request.client.host\n"
            "        )\n"
            "        track_failed_login(credentials.username)\n"
            "        raise HTTPException(status_code=401, detail='Invalid credentials')\n"
            "    logger.info('Successful login for user=%s', user.id)\n"
            "    return {'token': create_token(user)}\n"
        ),
        "references": [
            "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
            "https://cwe.mitre.org/data/definitions/778.html"
        ]
    }
]


def get_knowledgebase_articles() -> list[dict[str, Any]]:
    """
    Returns the comprehensive list of 10 OWASP Top 10 knowledgebase articles.
    """
    return OWASP_ARTICLES


def get_article_by_id(article_id: str) -> dict[str, Any] | None:
    """
    Retrieves a single article by its unique ID.
    """
    for article in OWASP_ARTICLES:
        if article["id"] == article_id:
            return article
    return None


async def seed_knowledgebase(db_session: Any = None) -> int:
    """
    Seeds the KnowledgebaseArticle database table if a SQLAlchemy session is provided.
    Returns the number of articles available/seeded.
    """
    if db_session is None:
        logger.info("No db_session provided. Returning in-memory articles count: %d", len(OWASP_ARTICLES))
        return len(OWASP_ARTICLES)

    try:
        # Dynamic import to avoid hard dependency on Member 2's models during standalone tests
        from orion.models.database import KnowledgebaseArticle
        
        seeded_count = 0
        for item in OWASP_ARTICLES:
            existing = db_session.query(KnowledgebaseArticle).filter(
                KnowledgebaseArticle.cwe_id == item["cwe_id"]
            ).first()
            if not existing:
                article = KnowledgebaseArticle(
                    id=item.get("id"),
                    title=item["title"],
                    cwe_id=item["cwe_id"],
                    severity=item["severity"],
                    description=item["description"],
                    vulnerable_code=item["vulnerable_code"],
                    remediation_code=item["remediation_code"],
                    references=item["references"]
                )
                db_session.add(article)
                seeded_count += 1
        
        db_session.commit()
        logger.info("Successfully seeded %d new knowledgebase articles to database.", seeded_count)
        return seeded_count
    except Exception as e:
        logger.warning("Could not seed database via SQLAlchemy model: %s", e)
        return len(OWASP_ARTICLES)

