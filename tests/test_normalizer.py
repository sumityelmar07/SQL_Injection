"""Tests for detection/normalizer.py"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection.normalizer import normalize


def test_url_decode():
    assert normalize("%27%20OR%20%271%27%3D%271") == "' or '1'='1"


def test_double_url_decode():
    # %2527 → %27 → '
    result = normalize("%2527")
    assert "'" in result


def test_html_entity():
    assert normalize("&lt;script&gt;") == "<script>"


def test_hex_literal():
    result = normalize("0x27")
    assert "'" in result


def test_lowercase():
    assert normalize("SELECT * FROM USERS") == "select * from users"


def test_whitespace_collapse():
    assert normalize("a   b\t\tc") == "a b c"


def test_inline_comment_removal():
    result = normalize("SELECT/*!32302 1*/FROM users")
    assert "/*" not in result


def test_unicode_fullwidth():
    # Full-width letters should normalize to ASCII
    result = normalize("ＯＲ")
    assert "or" in result


def test_empty_string():
    assert normalize("") == ""


def test_normal_username():
    assert normalize("alice_smith") == "alice_smith"
