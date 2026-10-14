"""Tests for detection/signatures.py"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection.normalizer import normalize
from detection.signatures import check_signatures


def _run(raw):
    return check_signatures(normalize(raw))


def _names(matches):
    return [m.name for m in matches]


def test_tautology_or():
    matches, score = _run("' OR '1'='1")
    assert len(matches) > 0
    assert score >= 70


def test_union_select():
    matches, score = _run("' UNION SELECT null,null --")
    assert len(matches) > 0
    assert "union_select" in _names(matches)
    assert score >= 90


def test_union_select_multiple_hits():
    """Phase C: a UNION SELECT payload must fire at least two signatures."""
    matches, score = _run("' UNION SELECT null,null --")
    names = _names(matches)
    assert "union_select" in names
    assert "sql_comment_dashdash" in names   # -- also fires
    assert len(matches) >= 2


def test_drop_table():
    matches, score = _run("'; DROP TABLE users; --")
    assert len(matches) > 0
    assert score >= 90


def test_sleep():
    matches, score = _run("' AND SLEEP(5) --")
    assert len(matches) > 0
    assert any("time_based" in name for name in _names(matches))


def test_comment_dashdash():
    matches, score = _run("admin'--")
    assert len(matches) > 0


def test_information_schema():
    matches, score = _run("' UNION SELECT table_name FROM information_schema.tables --")
    assert len(matches) > 0
    names = _names(matches)
    assert "information_schema" in names


def test_information_schema_multiple_hits():
    """Phase C: a schema-probing UNION payload fires 3+ signatures."""
    matches, score = _run("' UNION SELECT table_name FROM information_schema.tables --")
    assert len(matches) >= 3   # union_select, information_schema, sql_comment_dashdash


def test_normal_input_no_match():
    matches, score = _run("alice_smith")
    assert len(matches) == 0
    assert score == 0


def test_normal_email_no_match():
    matches, score = _run("user@example.com")
    assert len(matches) == 0
    assert score == 0
