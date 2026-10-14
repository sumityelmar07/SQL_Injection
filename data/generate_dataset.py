"""
Generates a synthetic CSV dataset of normal inputs and SQL injection payloads.

Run:  python data/generate_dataset.py

Output: data/dataset.csv  with columns  [text, label]
  label=0  normal input
  label=1  injection attempt

All data is synthetically generated — no real user data, no copies of
live payloads from production systems.
"""

import csv
import os
import random
import string

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

OUT_PATH = os.path.join(os.path.dirname(__file__), "dataset.csv")


# ---------------------------------------------------------------------------
# Normal inputs
# ---------------------------------------------------------------------------

_FIRST = ["alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi",
          "ivan", "judy", "mallory", "niaj", "olivia", "peggy", "rupert",
          "sybil", "trent", "victor", "wendy", "xavier"]

_LAST  = ["smith", "jones", "brown", "taylor", "wilson", "davis", "miller",
          "moore", "jackson", "white", "harris", "martin", "garcia", "lee"]

_DOMAINS = ["example.com", "mail.org", "test.net", "sample.io", "demo.co"]

_SEARCH_WORDS = ["laptop", "phone", "shoes", "jacket", "book", "headphones",
                 "monitor", "keyboard", "mouse", "camera", "tablet", "watch",
                 "backpack", "charger", "cable", "speaker"]

# Natural-language phrases that happen to contain SQL keywords.
# These teach the ML model that "in", "and", "or", "not", "select", etc.
# appear in innocent contexts — preventing false positives like "in and out".
_NATURAL_PHRASES = [
    "in and out", "out of stock", "in stock now", "and so on", "back and forth",
    "not available", "not in stock", "not found", "by the way", "on and off",
    "order online", "order tracking", "order placed", "order confirmed",
    "select your size", "select all files", "select a date",
    "create account", "create new folder", "create a list",
    "update profile", "update address", "update settings",
    "drop down menu", "drop ship", "drop off location",
    "where is my order", "where to find", "where do i go",
    "group discount", "group booking", "group by category",
    "having a sale", "having trouble logging in",
    "like new condition", "like this item",
    "between sizes", "between 9am and 5pm",
    "delete old files", "delete my account", "delete notification",
    "table of contents", "table for two", "table lamp",
    "set reminder", "set up account", "set as default",
    "from the menu", "from our store", "from the catalog",
    "join our team", "join the club", "join waitlist",
    "cast iron skillet", "column header", "limit per order",
    "null and void", "offset printing", "schema design guide",
    "exists in catalog", "in order to", "insert coin",
    "on the go", "in case of", "not sure yet",
    "or best offer", "and more", "in progress",
]


def _normal_natural_phrase() -> str:
    return random.choice(_NATURAL_PHRASES)


def _rand_str(length: int) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=length))


def _normal_username() -> str:
    first = random.choice(_FIRST)
    last  = random.choice(_LAST)
    sep   = random.choice(["", "_", ".", ""])
    num   = str(random.randint(1, 999)) if random.random() < 0.4 else ""
    return f"{first}{sep}{last}{num}"


def _normal_email() -> str:
    user   = _normal_username()
    domain = random.choice(_DOMAINS)
    return f"{user}@{domain}"


def _normal_search() -> str:
    n = random.randint(1, 4)
    return " ".join(random.choices(_SEARCH_WORDS, k=n))


def _normal_number() -> str:
    return str(random.randint(1, 99999))


_NORMAL_GENERATORS = [
    _normal_username,
    _normal_email,
    _normal_search,
    _normal_number,
    _normal_natural_phrase,
    lambda: _rand_str(random.randint(3, 12)),
]


def generate_normal(n: int) -> list[str]:
    samples = []
    for _ in range(n):
        fn = random.choice(_NORMAL_GENERATORS)
        samples.append(fn())
    return samples


# ---------------------------------------------------------------------------
# Injection payloads (synthetic variants of well-known patterns)
# ---------------------------------------------------------------------------

_TAUTOLOGY_OPS = ["or", "OR", "Or", "||"]
_COMMENT_STYLES = ["--", "--+", "#", "/**/", "/*!*/"]
_UNION_COLS = [2, 3, 4, 5, 6]


def _tautology() -> str:
    op    = random.choice(_TAUTOLOGY_OPS)
    quote = random.choice(["'", '"'])
    cmt   = random.choice(_COMMENT_STYLES)
    n     = random.randint(1, 9)
    variants = [
        f"{quote} {op} {quote}1{quote}={quote}1",
        f"{quote} {op} {n}={n} {cmt}",
        f"1 {op} 1=1",
        f"{quote} {op} 1=1 {cmt}",
        f"admin{quote} {cmt}",
        f"{quote} {op} {quote}x{quote}={quote}x",
    ]
    return random.choice(variants)


def _union_select() -> str:
    cols = random.randint(2, 6)
    nulls = ",".join(["null"] * cols)
    cmt  = random.choice(_COMMENT_STYLES)
    variants = [
        f"' UNION SELECT {nulls} {cmt}",
        f"' UNION ALL SELECT {nulls} {cmt}",
        f"-1 UNION SELECT {nulls}",
        f"1' UNION SELECT username,password FROM users {cmt}",
    ]
    return random.choice(variants)


def _stacked() -> str:
    stmts = [
        "'; DROP TABLE users; --",
        "'; INSERT INTO users VALUES('hacker','hacker@x.com','pw','admin'); --",
        "'; UPDATE users SET role='admin' WHERE '1'='1",
        "'; DELETE FROM users WHERE 1=1 --",
        "1; EXEC xp_cmdshell('dir')",
    ]
    return random.choice(stmts)


def _blind_boolean() -> str:
    cmt = random.choice(_COMMENT_STYLES)
    n   = random.randint(1, 9)
    return random.choice([
        f"1 AND {n}={n}",
        f"1 AND {n}={n+1}",
        f"' AND '1'='1",
        f"' AND '1'='2",
        f"1' AND 1=1 {cmt}",
    ])


def _time_based() -> str:
    secs = random.randint(1, 10)
    return random.choice([
        f"' AND SLEEP({secs}) --",
        f"1; WAITFOR DELAY '0:0:{secs}'",
        f"' AND BENCHMARK({secs*100000},MD5(1)) --",
        f"1 AND pg_sleep({secs})",
    ])


def _error_based() -> str:
    return random.choice([
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,version())) --",
        "' AND UPDATEXML(1,CONCAT(0x7e,version()),1) --",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
    ])


def _file_op() -> str:
    return random.choice([
        "' UNION SELECT LOAD_FILE('/etc/passwd') --",
        "' INTO OUTFILE '/tmp/shell.php'",
        "1' AND 1=2 UNION SELECT null,LOAD_FILE('/etc/shadow') --",
    ])


def _comment_obfuscated() -> str:
    return random.choice([
        "'/**/OR/**/1=1/**/--",
        "' /*!OR*/ '1'='1",
        "UN/**/ION SE/**/LECT null,null --",
        "' OR/**/ 1/**/=/**/1 --",
    ])


def _info_schema() -> str:
    return random.choice([
        "' UNION SELECT table_name FROM information_schema.tables --",
        "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' --",
        "1 AND 1=(SELECT 1 FROM information_schema.tables LIMIT 1)",
    ])


_INJECTION_GENERATORS = [
    _tautology,
    _union_select,
    _stacked,
    _blind_boolean,
    _time_based,
    _error_based,
    _file_op,
    _comment_obfuscated,
    _info_schema,
]


def generate_injections(n: int) -> list[str]:
    samples = []
    for _ in range(n):
        fn = random.choice(_INJECTION_GENERATORS)
        samples.append(fn())
    return samples


# ---------------------------------------------------------------------------
# Phase F targeted additions
# ---------------------------------------------------------------------------

# Normal: admin in legitimate context (fixes admin false-positive gap)
_ADMIN_URL_BASES = [
    "/admin", "/admin/", "/admin/dashboard", "/admin/users",
    "/admin/settings", "/admin/logs", "/admin/reports",
    "/admin/panel", "/admin/api", "/api/v1/admin",
    "/user/admin", "/staff/admin", "/manage/admin",
    "/admin/export", "/admin/backup", "/admin/config",
]
_ADMIN_URL_SUFFS = ["", "?tab=overview", "?page=1", "/edit", "/list",
                    "/create", "/view", "#settings", "?sort=date"]

_ADMIN_PROSE = [
    "logged in as administrator",
    "contact the system administrator",
    "admin panel is available to staff only",
    "request admin access from your manager",
    "admin privileges are required",
    "the admin user was created successfully",
    "only admin accounts can export data",
    "admin rights have been revoked",
    "super admin can manage all users",
    "admin role was assigned",
    "administrator email is admin@company.com",
    "this page requires admin role",
    "admin access granted",
    "non-admin users see a limited view",
    "admin tools are under maintenance",
    "contact your admin for help",
    "database admin approved the change",
    "admin portal requires two-factor auth",
    "site admin blocked the account",
    "admin group includes three members",
    "the admin dashboard shows usage stats",
    "grant admin role to power users",
    "store admin manages product listings",
    "forum admin moderates posts",
    "admin credentials are stored securely",
    "admin interface is on a separate subdomain",
    "admin@example.org sent a notification",
    "admin approved the request",
    "I am the server admin",
    "cloud admin portal login",
]

_ADMIN_UI = [
    "Admin", "Admin Dashboard", "Admin Settings", "Admin Console",
    "Admin Panel", "Go to Admin", "Admin Login", "Admin Portal",
    "Back to Admin", "Admin Menu", "Open Admin View",
    "Admin Notifications", "Admin Tools", "Admin Reports",
    "Site Admin", "Super Admin", "Store Admin", "User Admin",
]


def _admin_context_normal() -> str:
    fn = random.choice([
        lambda: random.choice(_ADMIN_URL_BASES) + random.choice(_ADMIN_URL_SUFFS),
        lambda: random.choice(_ADMIN_PROSE),
        lambda: random.choice(_ADMIN_UI),
    ])
    return fn()


# Injection: CHAR()-encoded (fixes CHAR detection gap)
_CHAR_PAYLOADS = [
    "' OR CHAR(49)=CHAR(49) --",
    "' OR CHAR(49)=CHAR(49) #",
    "' AND CHAR(49)=CHAR(49) --",
    "1 OR CHAR(49)=CHAR(49) --",
    "' UNION SELECT CHAR(117,115,101,114) --",
    "' UNION SELECT CHAR(97,100,109,105,110) --",
    "' UNION SELECT NULL,CHAR(117,115,101,114) --",
    "CHAR(39) OR CHAR(49)=CHAR(49) --",
    "' OR ASCII(CHAR(49))=49 --",
    "' AND CHAR(48)=CHAR(48) --",
    "admin' AND CHAR(49)=CHAR(49) --",
    "' UNION SELECT CHAR(118,101,114,115,105,111,110) --",
    "'; SELECT CHAR(65,68,77,73,78) --",
    "' OR CHAR(49)>CHAR(48) --",
    "' OR 1=CHAR(49)-CHAR(48) --",
    "' AND CHAR(49)=CHAR(49) /**/",
    "1 AND CHAR(49)=CHAR(49) --",
    "' UNION SELECT CHAR(112,97,115,115) --",
    "CHAR(117,115,101,114) UNION SELECT NULL --",
    "' OR CHAR(49,48)=CHAR(49,48) --",
]


def _char_encoded_f() -> str:
    return random.choice(_CHAR_PAYLOADS)


# Injection: SHUTDOWN / CREATE TABLE stacked queries
_SHUTDOWN_CREATE_PAYLOADS = [
    "'; SHUTDOWN --",
    "'; SHUTDOWN; --",
    "1; SHUTDOWN --",
    "admin'; SHUTDOWN --",
    "'; SHUTDOWN WITH NOWAIT --",
    "'; CREATE TABLE tmp (id INT) --",
    "'; CREATE TABLE backdoor (cmd TEXT) --",
    "'; CREATE TABLE tmp (x TEXT) --",
    "1; CREATE TABLE evil (pass TEXT) --",
    "'; CREATE TABLE shell (cmd TEXT, out TEXT) --",
    "'; CREATE DATABASE hacked --",
    "'; SHUTDOWN; DROP TABLE users --",
    "1'; CREATE TABLE log2 (ts DATETIME) --",
    "' OR 1=1; SHUTDOWN --",
    "'; SHUTDOWN; INSERT INTO users VALUES(1,'hacker') --",
    "x'; CREATE TABLE tokens (tok TEXT) --",
    "'; SHUTDOWN --+",
    "1 OR 1=1; SHUTDOWN #",
    "'; CREATE TABLE tmp2 (x TEXT, y TEXT) --",
    "'; CREATE DATABASE shadow --",
]


def _shutdown_create_f() -> str:
    return random.choice(_SHUTDOWN_CREATE_PAYLOADS)


# Injection: MySQL versioned / conditional comments
_VERSIONED_COMMENT_PAYLOADS = [
    "'/*!50000OR*/1=1 --",
    "'/*!OR*/1=1 --",
    "/*!50000SELECT*/ 1 --",
    "/*!50000UNION*//*!50000SELECT*/ null --",
    "' /*!50000OR*/ '1'='1 --",
    "UN/*!50000ION*/ SE/*!50000LECT*/ null,null --",
    "' /*!AND*/ '1'='1 --",
    "/*!50000DROP*/ TABLE users --",
    "'/*!50000UNION*//*!50000SELECT*/ user() --",
    "' OR /*!50000 1 */=/*!50000 1 */ --",
    "1/*!50000AND*/1=1 --",
    "' /*!50000OR*/ 1/*!50000=*/1 --",
    "1/*!50000OR*/2>1 --",
    "admin'/*!50000--*/",
    "' /*!50000UNION*/ /*!50000SELECT*/ NULL --",
    "'/*!50000OR*/2>1 --",
    "1/*!50000AND*/SLEEP(0) --",
    "' OR/*! */1=1 --",
    "'/*!*/OR/*! */1=1 --",
    "'/*!50000OR*//*!50000'1'*/=/*!50000'1'*/ --",
]


def _versioned_comment_f() -> str:
    return random.choice(_VERSIONED_COMMENT_PAYLOADS)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    n_each = 2000
    normal     = generate_normal(n_each)
    injections = generate_injections(n_each)

    # Phase F targeted additions — guaranteed coverage of known gaps
    targeted_normal = [_admin_context_normal() for _ in range(100)]
    targeted_inject = (
        [_char_encoded_f()    for _ in range(50)] +
        [_shutdown_create_f() for _ in range(50)] +
        [_versioned_comment_f() for _ in range(50)]
    )

    rows = (
        [(text, 0) for text in normal + targeted_normal] +
        [(text, 1) for text in injections + targeted_inject]
    )
    random.shuffle(rows)

    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        writer.writerows(rows)

    n0 = sum(1 for _, l in rows if l == 0)
    n1 = sum(1 for _, l in rows if l == 1)
    print(f"Dataset written to {OUT_PATH}  ({len(rows)} rows)")
    print(f"  label=0 (normal)   : {n0}")
    print(f"  label=1 (injection): {n1}")


if __name__ == "__main__":
    main()
