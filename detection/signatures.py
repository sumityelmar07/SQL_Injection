"""
Regex-based SQL injection signature engine.

Each entry in SIGNATURES is a dict:
  name     : human-readable label shown in the attack log
  pattern  : compiled regex run against the *normalized* input
  severity : 'low' | 'medium' | 'high' | 'critical'
  score    : contribution to the signature component of the risk score (0-100)

Patterns are written against lowercased, whitespace-collapsed input
(after normalizer.normalize() has run), so we do not need case-insensitive
flags on every pattern — re.IGNORECASE is added anyway as a safety net.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class SignatureMatch:
    name: str
    severity: str
    score: int          # 0-100 contribution
    matched_text: str   # the portion of the input that triggered the rule


# ---------------------------------------------------------------------------
# Signature definitions
# ---------------------------------------------------------------------------

_RAW_SIGNATURES = [
    # --- Tautologies (always-true conditions) ---
    {
        "name": "tautology_or",
        "pattern": r"'\s*or\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
        "severity": "critical",
        "score": 90,
    },
    {
        "name": "tautology_numeric",
        "pattern": r"\bor\s+\d+\s*=\s*\d+",
        "severity": "critical",
        "score": 90,
    },
    # --- Comment injection (--  #  /**/) ---
    {
        "name": "sql_comment_dashdash",
        "pattern": r"--",
        "severity": "high",
        "score": 70,
    },
    {
        "name": "sql_comment_hash",
        "pattern": r"(?<![a-zA-Z0-9_])#",   # bare # not inside a word
        "severity": "medium",
        "score": 50,
    },
    # --- UNION-based injection ---
    {
        "name": "union_select",
        "pattern": r"\bunion\b.{0,40}\bselect\b",
        "severity": "critical",
        "score": 95,
    },
    # --- Stacked queries ---
    {
        "name": "stacked_query",
        "pattern": r";\s*(drop|insert|update|delete|create|alter|exec|execute)\b",
        "severity": "critical",
        "score": 95,
    },
    # --- Boolean blind ---
    {
        "name": "blind_boolean_and",
        "pattern": r"\band\s+\d+\s*=\s*\d+",
        "severity": "high",
        "score": 75,
    },
    # --- Time-based blind ---
    {
        "name": "time_based_sleep",
        "pattern": r"\bsleep\s*\(\s*\d+",
        "severity": "critical",
        "score": 90,
    },
    {
        "name": "time_based_waitfor",
        "pattern": r"\bwaitfor\s+delay\b",
        "severity": "critical",
        "score": 90,
    },
    {
        "name": "time_based_benchmark",
        "pattern": r"\bbenchmark\s*\(",
        "severity": "critical",
        "score": 90,
    },
    # --- Error-based ---
    {
        "name": "error_based_extractvalue",
        "pattern": r"\bextractvalue\s*\(",
        "severity": "critical",
        "score": 90,
    },
    {
        "name": "error_based_updatexml",
        "pattern": r"\bupdatexml\s*\(",
        "severity": "critical",
        "score": 90,
    },
    # --- File read / write ---
    {
        "name": "file_read",
        "pattern": r"\bload_file\s*\(",
        "severity": "critical",
        "score": 95,
    },
    {
        "name": "file_write",
        "pattern": r"\binto\s+outfile\b",
        "severity": "critical",
        "score": 95,
    },
    # --- Dangerous keywords in input context ---
    {
        "name": "drop_table",
        "pattern": r"\bdrop\s+table\b",
        "severity": "critical",
        "score": 95,
    },
    {
        "name": "exec_xp",
        "pattern": r"\bexec(ute)?\s+xp_",
        "severity": "critical",
        "score": 95,
    },
    # --- Quote followed by keyword (common injection opener) ---
    {
        "name": "quote_keyword",
        "pattern": r"'\s*(and|or|union|select|insert|update|delete|where|having)\b",
        "severity": "high",
        "score": 80,
    },
    # --- Subquery injection ---
    {
        "name": "subquery_select",
        "pattern": r"\(\s*select\s+",
        "severity": "high",
        "score": 75,
    },
    # --- Information schema probing ---
    {
        "name": "information_schema",
        "pattern": r"\binformation_schema\b",
        "severity": "critical",
        "score": 90,
    },
    {
        "name": "table_columns_probe",
        "pattern": r"\bsysobjects\b|\bsyscolumns\b|\bsql_variant\b",
        "severity": "high",
        "score": 80,
    },
]

# Pre-compile all patterns once at import time for performance.
SIGNATURES = []
for _entry in _RAW_SIGNATURES:
    SIGNATURES.append({
        **_entry,
        "compiled": re.compile(_entry["pattern"], re.IGNORECASE),
    })


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_signatures(normalized_input: str) -> tuple[list[SignatureMatch], int]:
    """
    Run all signatures against *normalized_input*.

    Returns (all_matches, best_score) where all_matches is a list of every
    SignatureMatch that fired (empty list if none), and best_score is the
    highest individual score across all matches (0 if none).

    Returning every match (not just the best) gives the attack log full
    forensic detail — e.g. a payload that triggers both union_select AND
    information_schema shows both in the dashboard.
    """
    matches = []
    for sig in SIGNATURES:
        m = sig["compiled"].search(normalized_input)
        if m:
            matches.append(SignatureMatch(
                name=sig["name"],
                severity=sig["severity"],
                score=sig["score"],
                matched_text=m.group(0),
            ))

    if not matches:
        return [], 0

    best_score = max(m.score for m in matches)
    return matches, best_score
