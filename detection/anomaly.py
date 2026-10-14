"""
Rule-based anomaly checks.

These catch suspicious *structure* without needing an exact pattern match.
Each check returns a score 0-100. The final anomaly score is the maximum
of all individual check scores (not the sum — we do not want an input that
fails every mild check to score higher than one that fails one severe check).
"""

import re

# SQL keywords we count when measuring token density.
_SQL_KEYWORDS = frozenset([
    "select", "insert", "update", "delete", "drop", "create", "alter",
    "union", "where", "having", "from", "join", "on", "set",
    "and", "or", "not", "null", "like", "between", "in", "exists",
    "order", "group", "by", "limit", "offset", "exec", "execute",
    "cast", "convert", "table", "column", "database", "schema",
])

_COMMENT_RE = re.compile(r"(--|#|/\*|\*/)")
_FORBIDDEN_FN_RE = re.compile(
    r"\b(sleep|benchmark|load_file|into\s+outfile|waitfor|pg_sleep|"
    r"extractvalue|updatexml|char|ascii|hex|unhex|substring|mid|"
    r"group_concat)\s*\(",
    re.IGNORECASE,
)


def check_anomalies(normalized_input: str) -> int:
    """
    Run all anomaly checks and return the highest individual score (0-100).
    """
    scores = [
        _keyword_density(normalized_input),
        _quote_imbalance(normalized_input),
        _comment_presence(normalized_input),
        _excessive_length(normalized_input),
        _forbidden_functions(normalized_input),
        _multiple_statements(normalized_input),
    ]
    return max(scores)


# ---------------------------------------------------------------------------
# Individual checks (each returns 0-100)
# ---------------------------------------------------------------------------

def _keyword_density(text: str) -> int:
    """High ratio of SQL keywords to total tokens is suspicious.

    Short phrases (< 5 tokens) are treated leniently because common English
    words like 'in', 'and', 'not', 'or' are in the SQL keyword set. A 3-word
    phrase such as 'in and out' legitimately scores 67% keyword density but is
    not an injection. Longer inputs (≥ 5 tokens) require proportionally more
    SQL keywords before high scores are returned.
    """
    tokens = re.findall(r"\b\w+\b", text.lower())
    if len(tokens) < 3:
        return 0
    kw_count = sum(1 for t in tokens if t in _SQL_KEYWORDS)
    ratio = kw_count / len(tokens)
    if len(tokens) < 5:
        # Short phrases — cap at a low score to avoid flagging "in and out" etc.
        return 30 if ratio >= 0.50 else 0
    if ratio >= 0.5:
        return 85
    if ratio >= 0.35:
        return 60
    if ratio >= 0.20:
        return 30
    return 0


def _quote_imbalance(text: str) -> int:
    """An odd number of single-quotes means an unclosed string — classic injection sign."""
    count = text.count("'")
    if count == 0:
        return 0
    return 70 if count % 2 != 0 else 0


def _comment_presence(text: str) -> int:
    """SQL comment sequences inside user input are almost always malicious."""
    if _COMMENT_RE.search(text):
        return 75
    return 0


def _excessive_length(text: str, normal_max: int = 120) -> int:
    """Input significantly longer than a typical field value is suspicious."""
    length = len(text)
    if length > normal_max * 10:
        return 60
    if length > normal_max * 5:
        return 35
    return 0


def _forbidden_functions(text: str) -> int:
    """Known dangerous SQL/database functions should never appear in user input."""
    if _FORBIDDEN_FN_RE.search(text):
        return 90
    return 0


def _multiple_statements(text: str) -> int:
    """A semicolon followed by a SQL keyword indicates stacked queries."""
    if re.search(r";\s*(select|insert|update|delete|drop|create|exec)\b",
                 text, re.IGNORECASE):
        return 95
    return 0
