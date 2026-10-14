"""
Source Code SQL Injection Scanner (SAST Engine).

Analyzes source code files (Python, PHP, JavaScript, TypeScript, Java, C#, SQL)
for SQL injection vulnerabilities, dynamic query construction, and insecure API usage.
Also recognizes and verifies safe parameterized queries.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from .pipeline import inspect as inspect_sql_payload


@dataclass
class CodeFinding:
    line_number: int
    line_content: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str
    description: str
    recommendation: str
    risk_score: int        # 0-100
    matched_pattern: Optional[str] = None


@dataclass
class SafePractice:
    line_number: int
    line_content: str
    description: str


@dataclass
class ScanReport:
    filename: str
    language: str
    total_lines: int
    overall_risk: str      # CRITICAL | HIGH | MEDIUM | LOW | SAFE
    overall_score: int     # 0-100
    findings: List[CodeFinding] = field(default_factory=list)
    safe_practices: List[SafePractice] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "language": self.language,
            "total_lines": self.total_lines,
            "overall_risk": self.overall_risk,
            "overall_score": self.overall_score,
            "summary": self.summary,
            "findings_count": len(self.findings),
            "safe_practices_count": len(self.safe_practices),
            "findings": [
                {
                    "line_number": f.line_number,
                    "line_content": f.line_content,
                    "severity": f.severity,
                    "category": f.category,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "risk_score": f.risk_score,
                    "matched_pattern": f.matched_pattern,
                }
                for f in self.findings
            ],
            "safe_practices": [
                {
                    "line_number": s.line_number,
                    "line_content": s.line_content,
                    "description": s.description,
                }
                for s in self.safe_practices
            ],
        }


# ---------------------------------------------------------------------------
# Detection Rules & Patterns
# ---------------------------------------------------------------------------

# SQL statement start keywords
_SQL_VERBS = r"(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE|UNION(?:\s+ALL)?\s+SELECT)"

# 1. Python Patterns
_PY_FSTRING_SQL = re.compile(
    rf'''f["'].*?{_SQL_VERBS}.*?\{{.+?\}}.*?["']''',
    re.IGNORECASE | re.DOTALL,
)
_PY_PERCENT_SQL = re.compile(
    rf'''["'].*?{_SQL_VERBS}.*?%s.*?["']\s*%\s*(?!\s*\()''',
    re.IGNORECASE,
)
_PY_FORMAT_SQL = re.compile(
    rf'''["'].*?{_SQL_VERBS}.*?["']\.format\(.+?\)''',
    re.IGNORECASE,
)
_PY_CONCAT_SQL = re.compile(
    rf'''(?:["'].*?{_SQL_VERBS}.*?["']\s*\+\s*[a-zA-Z_]\w*|[a-zA-Z_]\w*\s*\+\s*["'].*?(?:WHERE|FROM|AND|OR)\s+.*?["'])''',
    re.IGNORECASE,
)
_PY_RAW_EXEC_VAR = re.compile(
    r'''\b(?:cursor|db|connection|conn)\.execute\(\s*([a-zA-Z_]\w*)\s*\)''',
    re.IGNORECASE,
)
_PY_SAFE_PARAMETRIZED = re.compile(
    r'''\b(?:cursor|cur|db|conn|connection)\.execute\(\s*["'].*?(?:\?|%s|:[a-zA-Z_]\w*).*?["']\s*,\s*[\(\{\[]''',
    re.IGNORECASE,
)

# 2. PHP Patterns
_PHP_CONCAT_SQL = re.compile(
    rf'''["'].*?{_SQL_VERBS}.*?["']\s*\.\s*\$[a-zA-Z_]\w*''',
    re.IGNORECASE,
)
_PHP_INTERPOLATED_SQL = re.compile(
    rf'''"{_SQL_VERBS}.*?\$[a-zA-Z_]\w*.*?"''',
    re.IGNORECASE,
)
_PHP_RAW_QUERY = re.compile(
    r'''\b(?:mysqli?_query|mysql_query)\s*\(\s*(?:\$[a-zA-Z_]\w*,\s*)?["'].*?\$[a-zA-Z_]\w*.*?["']''',
    re.IGNORECASE,
)
_PHP_SAFE_PREPARE = re.compile(
    r'''->prepare\(\s*["'].*?(?:\?|:[a-zA-Z_]\w*).*?["']\s*\)''',
    re.IGNORECASE,
)

# 3. JavaScript / TypeScript Patterns
_JS_TEMPLATE_LITERAL_SQL = re.compile(
    rf'''`.*?{_SQL_VERBS}.*?\${{.+?\}}.*?`''',
    re.IGNORECASE | re.DOTALL,
)
_JS_CONCAT_SQL = re.compile(
    rf'''(?:["'].*?{_SQL_VERBS}.*?["']\s*\+\s*[a-zA-Z_]\w*|[a-zA-Z_]\w*\s*\+\s*["'].*?(?:WHERE|FROM)\b.*?["'])''',
    re.IGNORECASE,
)
_JS_SAFE_PARAMETRIZED = re.compile(
    r'''\b(?:db|client|pool|conn)\.query\(\s*["'].*?(?:\?|\$[0-9]+).*?["']\s*,\s*\[.*?\]''',
    re.IGNORECASE,
)

# 4. Java / C# Patterns
_JAVA_CONCAT_SQL = re.compile(
    rf'''(?:["'].*?{_SQL_VERBS}.*?["']\s*\+\s*[a-zA-Z_]\w*|[a-zA-Z_]\w*\s*\+\s*["'].*?(?:WHERE|FROM)\b.*?["'])''',
    re.IGNORECASE,
)
_JAVA_EXEC_QUERY_CONCAT = re.compile(
    r'''\b(?:executeQuery|executeUpdate)\s*\(\s*.*?["'].*?\+.*?\)''',
    re.IGNORECASE,
)
_JAVA_SAFE_PREPARED = re.compile(
    r'''\b(?:prepareStatement|PreparedStatement)\s*\(\s*["'].*?\?.*?["']\s*\)''',
    re.IGNORECASE,
)


def detect_language(filename: str, sample_code: str) -> str:
    """Infer source code language from filename extension or content clues."""
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    if ext in ("py", "pyw"):
        return "python"
    elif ext in ("php", "phtml"):
        return "php"
    elif ext in ("js", "mjs", "cjs", "jsx"):
        return "javascript"
    elif ext in ("ts", "tsx"):
        return "typescript"
    elif ext in ("java",):
        return "java"
    elif ext in ("cs",):
        return "csharp"
    elif ext in ("sql",):
        return "sql"

    # Fallback to inspecting content
    lower_sample = sample_code.lower()
    if "def " in lower_sample or "import " in lower_sample or "cursor.execute" in lower_sample:
        return "python"
    if "<?php" in lower_sample or "$_" in lower_sample:
        return "php"
    if "const " in lower_sample or "function " in lower_sample or "require(" in lower_sample:
        return "javascript"
    if "public class " in lower_sample or "preparedstatement" in lower_sample:
        return "java"

    return "generic"


def scan_source_code(code_text: str, filename: str = "source_code.py") -> ScanReport:
    """
    Scan the provided source code for SQL injection vulnerabilities and safe patterns.
    Returns a comprehensive ScanReport.
    """
    language = detect_language(filename, code_text)
    lines = code_text.splitlines()
    findings: List[CodeFinding] = []
    safe_practices: List[SafePractice] = []

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith(("#", "//", "/*", "*", "--")):
            # Skip full comment lines
            continue

        # -------------------------------------------------------------------
        # Check for Safe Practices first
        # -------------------------------------------------------------------
        if _PY_SAFE_PARAMETRIZED.search(line) or _JS_SAFE_PARAMETRIZED.search(line):
            safe_practices.append(SafePractice(
                line_number=idx,
                line_content=raw_line,
                description="Secure parameterized query using parameter binding placeholders."
            ))
            continue
        elif _PHP_SAFE_PREPARE.search(line) or _JAVA_SAFE_PREPARED.search(line):
            safe_practices.append(SafePractice(
                line_number=idx,
                line_content=raw_line,
                description="Secure prepared statement using parameter binding."
            ))
            continue

        # -------------------------------------------------------------------
        # Check Language-Specific Injections
        # -------------------------------------------------------------------

        # --- Python Vulnerabilities ---
        if language in ("python", "generic"):
            if _PY_FSTRING_SQL.search(line):
                findings.append(CodeFinding(
                    line_number=idx,
                    line_content=raw_line,
                    severity="CRITICAL",
                    category="f-string SQL Interpolation",
                    description="SQL statement is dynamically constructed using Python f-string interpolation with user/variable inputs. Attackers can inject arbitrary SQL commands.",
                    recommendation="Use parameterized placeholders: cursor.execute('SELECT ... WHERE col = ?', (val,)) instead of f-strings.",
                    risk_score=95,
                    matched_pattern="f-string with SQL verb",
                ))
                continue

            if _PY_PERCENT_SQL.search(line):
                findings.append(CodeFinding(
                    line_number=idx,
                    line_content=raw_line,
                    severity="CRITICAL",
                    category="String Formatting SQL Injection (% operator)",
                    description="SQL string is constructed using Python % operator formatting. Values are concatenated into SQL syntax prior to execution.",
                    recommendation="Pass parameters as a tuple argument to execute(): cursor.execute('SELECT ... WHERE col = %s', (val,))",
                    risk_score=92,
                    matched_pattern="SQL string % variable",
                ))
                continue

            if _PY_FORMAT_SQL.search(line):
                findings.append(CodeFinding(
                    line_number=idx,
                    line_content=raw_line,
                    severity="CRITICAL",
                    category=".format() Dynamic SQL Injection",
                    description="SQL string is formatted using .format(). Untrusted parameters change query structure directly.",
                    recommendation="Refactor to parameterized queries: cursor.execute('SELECT ... WHERE col = ?', (val,))",
                    risk_score=90,
                    matched_pattern="SQL string .format()",
                ))
                continue

            if _PY_CONCAT_SQL.search(line):
                findings.append(CodeFinding(
                    line_number=idx,
                    line_content=raw_line,
                    severity="CRITICAL",
                    category="String Concatenation in SQL Query",
                    description="SQL query fragment is directly concatenated using the '+' operator with an external variable.",
                    recommendation="Remove string concatenation and supply input via DB-API query parameter binding.",
                    risk_score=92,
                    matched_pattern="SQL string + variable",
                ))
                continue

        # --- PHP Vulnerabilities ---
        if language in ("php", "generic"):
            if _PHP_INTERPOLATED_SQL.search(line) or _PHP_CONCAT_SQL.search(line):
                findings.append(CodeFinding(
                    line_number=idx,
                    line_content=raw_line,
                    severity="CRITICAL",
                    category="PHP Dynamic SQL Injection",
                    description="SQL query contains variable interpolation or '.' concatenation in raw SQL statement.",
                    recommendation="Use PDO or MySQLi prepared statements: $stmt = $pdo->prepare('SELECT ... WHERE id = ?'); $stmt->execute([$id]);",
                    risk_score=95,
                    matched_pattern="PHP SQL string concatenation/interpolation",
                ))
                continue

            if _PHP_RAW_QUERY.search(line):
                findings.append(CodeFinding(
                    line_number=idx,
                    line_content=raw_line,
                    severity="HIGH",
                    category="Direct mysqli_query Execution",
                    description="Direct query execution with unescaped variable string passed into mysqli_query().",
                    recommendation="Bind parameters with mysqli_prepare() and mysqli_stmt_bind_param().",
                    risk_score=85,
                    matched_pattern="mysqli_query with variable",
                ))
                continue

        # --- JavaScript / TypeScript Vulnerabilities ---
        if language in ("javascript", "typescript", "generic"):
            if _JS_TEMPLATE_LITERAL_SQL.search(line):
                findings.append(CodeFinding(
                    line_number=idx,
                    line_content=raw_line,
                    severity="CRITICAL",
                    category="Template Literal SQL Injection",
                    description="SQL statement is constructed via ES6 template literal `${...}` without query parameterization.",
                    recommendation="Use parameterized queries: db.query('SELECT ... WHERE id = $1', [id]) or a query builder.",
                    risk_score=95,
                    matched_pattern="`SQL ${var}`",
                ))
                continue

            if _JS_CONCAT_SQL.search(line):
                findings.append(CodeFinding(
                    line_number=idx,
                    line_content=raw_line,
                    severity="CRITICAL",
                    category="JavaScript SQL Concatenation",
                    description="SQL query string is concatenated with '+' and runtime variables.",
                    recommendation="Pass parameters in query arguments array instead of concatenating strings.",
                    risk_score=90,
                    matched_pattern="JS SQL string + variable",
                ))
                continue

        # --- Java / C# Vulnerabilities ---
        if language in ("java", "csharp", "generic"):
            if _JAVA_EXEC_QUERY_CONCAT.search(line) or _JAVA_CONCAT_SQL.search(line):
                findings.append(CodeFinding(
                    line_number=idx,
                    line_content=raw_line,
                    severity="CRITICAL",
                    category="Java / C# SQL String Concatenation",
                    description="Statement.executeQuery() or dynamic SQL string built using string concatenation (+).",
                    recommendation="Use PreparedStatement with parameter placeholders: conn.prepareStatement('SELECT ... WHERE col = ?')",
                    risk_score=94,
                    matched_pattern="Java executeQuery + var",
                ))
                continue

        # --- Raw SQL / Payload Script Analysis ---
        # For SQL files or raw strings in files, test against our multi-layer detection pipeline
        sql_match = inspect_sql_payload(line)
        if sql_match.get("decision") in ("LIKELY_ATTACK", "DEFINITE_ATTACK"):
            sig_name = sql_match.get("signature_hit") or "Malicious SQL Payload Pattern"
            findings.append(CodeFinding(
                line_number=idx,
                line_content=raw_line,
                severity="HIGH" if sql_match.get("decision") == "LIKELY_ATTACK" else "CRITICAL",
                category="Embedded SQL Injection Payload",
                description=f"Line contains malicious SQL injection signature: {sig_name}. Risk score: {sql_match.get('risk_score')}.",
                recommendation="Audit query logic. Remove raw tautologies, UNION payloads, or unparameterized fragments.",
                risk_score=sql_match.get("risk_score", 85),
                matched_pattern=str(sig_name),
            ))
            continue
        elif sql_match.get("decision") == "SUSPICIOUS":
            findings.append(CodeFinding(
                line_number=idx,
                line_content=raw_line,
                severity="MEDIUM",
                category="Suspicious SQL Pattern",
                description=f"Suspicious SQL syntax structure detected (anomaly score: {sql_match.get('anomaly_score')}, ML prob: {int(sql_match.get('ml_score', 0)*100)}%).",
                recommendation="Review query formatting to ensure inputs are strictly separated from SQL commands.",
                risk_score=sql_match.get("risk_score", 45),
                matched_pattern="Anomaly/ML threshold match",
            ))

    # -----------------------------------------------------------------------
    # Compute Overall File Risk
    # -----------------------------------------------------------------------
    if any(f.severity == "CRITICAL" for f in findings):
        overall_risk = "CRITICAL"
        overall_score = max(f.risk_score for f in findings)
        summary = f"CRITICAL: Found {len(findings)} potential SQL injection vulnerability(ies). Immediate remediation required!"
    elif any(f.severity == "HIGH" for f in findings):
        overall_risk = "HIGH"
        overall_score = max(f.risk_score for f in findings)
        summary = f"HIGH RISK: Found {len(findings)} suspicious query construction(s) that may permit SQL injection."
    elif any(f.severity == "MEDIUM" for f in findings):
        overall_risk = "MEDIUM"
        overall_score = max(f.risk_score for f in findings)
        summary = f"MEDIUM RISK: Found {len(findings)} pattern(s) requiring security review."
    elif safe_practices and not findings:
        overall_risk = "SAFE"
        overall_score = 0
        summary = f"SAFE: Verified {len(safe_practices)} safe parameterized SQL pattern(s). No injection vulnerabilities found."
    else:
        overall_risk = "SAFE"
        overall_score = 0
        summary = "SAFE: No SQL injection vulnerabilities or unparameterized queries detected."

    return ScanReport(
        filename=filename,
        language=language.upper(),
        total_lines=len(lines),
        overall_risk=overall_risk,
        overall_score=overall_score,
        findings=findings,
        safe_practices=safe_practices,
        summary=summary,
    )
