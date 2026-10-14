"""
Unit tests for detection/code_scanner.py.
Verifies detection of dynamic query construction, f-strings, concatenation,
template literals, safe parameterized queries, and language identification.
"""

import pytest
from detection.code_scanner import scan_source_code, detect_language


def test_detect_language():
    assert detect_language("app.py", "") == "python"
    assert detect_language("db.php", "") == "php"
    assert detect_language("server.js", "") == "javascript"
    assert detect_language("index.ts", "") == "typescript"
    assert detect_language("UserDao.java", "") == "java"
    assert detect_language("query.sql", "") == "sql"


def test_python_fstring_vulnerability():
    code = """
import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
"""
    report = scan_source_code(code, "test_fstring.py")
    assert report.overall_risk == "CRITICAL"
    assert len(report.findings) >= 1
    f = report.findings[0]
    assert f.category == "f-string SQL Interpolation"
    assert f.severity == "CRITICAL"
    assert "WHERE username =" in f.line_content


def test_python_concat_vulnerability():
    code = """
def search(query):
    sql = "SELECT id, name FROM products WHERE name = '" + query + "'"
    cursor.execute(sql)
"""
    report = scan_source_code(code, "test_concat.py")
    assert report.overall_risk == "CRITICAL"
    assert any("Concatenation" in f.category for f in report.findings)


def test_python_format_vulnerability():
    code = """
def lookup(user_id):
    sql = "SELECT * FROM users WHERE id = {}".format(user_id)
    cursor.execute(sql)
"""
    report = scan_source_code(code, "test_format.py")
    assert report.overall_risk == "CRITICAL"
    assert any(".format()" in f.category for f in report.findings)


def test_safe_python_parameterized():
    code = """
import sqlite3

def get_user_safe(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()
"""
    report = scan_source_code(code, "test_safe.py")
    assert report.overall_risk == "SAFE"
    assert len(report.findings) == 0
    assert len(report.safe_practices) >= 1


def test_php_concatenation_vulnerability():
    code = """<?php
$user_id = $_GET['id'];
$query = "SELECT * FROM accounts WHERE id = '" . $user_id . "'";
$result = mysqli_query($conn, $query);
?>"""
    report = scan_source_code(code, "index.php")
    assert report.overall_risk in ("CRITICAL", "HIGH")
    assert len(report.findings) >= 1


def test_javascript_template_literal_vulnerability():
    code = """
app.get('/user', async (req, res) => {
    const id = req.query.id;
    const result = await db.query(`SELECT * FROM users WHERE id = ${id}`);
    res.json(result);
});
"""
    report = scan_source_code(code, "app.js")
    assert report.overall_risk == "CRITICAL"
    assert any("Template Literal" in f.category for f in report.findings)


def test_raw_sql_script_with_payload():
    code = """
-- Test migration script
SELECT * FROM users WHERE id = 1;
SELECT * FROM users WHERE username = '' OR '1'='1' --;
"""
    report = scan_source_code(code, "script.sql")
    assert report.overall_risk in ("HIGH", "CRITICAL")
    assert len(report.findings) >= 1


def test_clean_non_sql_code():
    code = """
def add(a, b):
    return a + b

def multiply(x, y):
    total = 0
    for _ in range(y):
        total += x
    return total
"""
    report = scan_source_code(code, "math_utils.py")
    assert report.overall_risk == "SAFE"
    assert len(report.findings) == 0
