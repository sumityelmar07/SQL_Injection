"""
Generates a development dataset for model selection and comparison.

Output: data/dev_dataset.csv   columns: [text, label]
  label=0  normal / legitimate input
  label=1  SQL injection attempt

Run:  python data/generate_dev_dataset.py

Purpose
-------
This file is used ONLY to:
  - Compare the old model against the new model during development.
  - Check that improvements on targeted weaknesses do not regress on other
    cases.

It must NEVER be used for training (that is data/dataset.csv) and must
NEVER be used as the fixed holdout (that is data/eval_dataset.csv).

Independence
------------
- Seed: DEV_SEED = 271  (training uses 42, eval uses 137)
- Normal side: heavy on 'admin'-in-legitimate-context examples that exposed
  the Phase E false positives.
- Injection side: heavy on CHAR() encoding, SHUTDOWN, CREATE TABLE, and
  MySQL versioned-comment obfuscation — the four root causes of Phase E false
  negatives.
- Overlap with dataset.csv and eval_dataset.csv is checked and reported.

Category table
--------------
NORMAL (500 total)
  A  admin_url          — URL paths that contain the word 'admin'
  B  admin_prose        — prose sentences where 'admin' is a role/noun
  C  admin_ui           — UI labels, page titles, nav links with 'admin'
  D  general_normal     — broad normal inputs (usernames, email, search)
  E  apostrophe_name    — names containing apostrophes (covered in eval too)

INJECTION (500 total)
  F  char_encoded       — CHAR()-based encoding variants
  G  shutdown_create    — SHUTDOWN, CREATE TABLE stacked queries
  H  versioned_comment  — MySQL /*!50000...*/ execution comments
  I  classic_varied     — tautologies, UNION, time-based from broader set
  J  blind_and_error    — blind boolean and error-based with new patterns
"""

import csv, os, random

DEV_SEED       = 271
N_PER_CATEGORY = 100  # 5 categories × 100 = 500 per class

random.seed(DEV_SEED)

OUT_PATH   = os.path.join(os.path.dirname(__file__), "dev_dataset.csv")
TRAIN_PATH = os.path.join(os.path.dirname(__file__), "dataset.csv")
EVAL_PATH  = os.path.join(os.path.dirname(__file__), "eval_dataset.csv")


# ===========================================================================
# NORMAL
# ===========================================================================

# --- A: admin in URL paths ---
_ADMIN_URL_PREFIXES  = ["/admin", "/admin/", "/admin/dashboard", "/admin/users",
                        "/admin/settings", "/admin/logs", "/admin/reports",
                        "/admin/panel", "/admin/api", "/api/v1/admin",
                        "/user/admin", "/staff/admin", "/manage/admin"]
_ADMIN_URL_SUFFIXES  = ["", "?tab=overview", "?page=1", "/edit", "/list",
                        "/create", "/delete", "/view", "#settings"]

def _admin_url() -> str:
    base = random.choice(_ADMIN_URL_PREFIXES)
    suf  = random.choice(_ADMIN_URL_SUFFIXES)
    return base + suf


# --- B: admin in prose / role context ---
_ADMIN_PROSE = [
    "logged in as administrator",
    "your administrator account is active",
    "contact the system administrator",
    "admin panel is available to staff only",
    "request admin access from your manager",
    "admin privileges are required for this action",
    "the admin user was created successfully",
    "only admin accounts can export data",
    "reset via the admin console",
    "admin rights have been revoked",
    "super admin can manage all users",
    "view admin activity log",
    "admin role was assigned",
    "administrator email is admin@company.com",
    "this page requires admin role",
    "admin access granted",
    "admin account set up complete",
    "non-admin users see a limited view",
    "admin tools are under maintenance",
    "contact your admin for help",
    "admin approved the request",
    "I am the server admin",
    "database admin approved the change",
    "cloud admin portal login",
    "admin portal requires two-factor auth",
    "site admin blocked the account",
    "admin@example.org sent a notification",
    "updated by admin on Monday",
    "admin group includes three members",
    "the admin dashboard shows usage stats",
    "admin can unlock any account",
    "grant admin role to power users",
    "store admin manages product listings",
    "forum admin moderates posts",
    "co-admin has limited privileges",
    "helpdesk admin opened the ticket",
    "admin credentials are stored securely",
    "the admin changed the password policy",
    "admin-only feature flag enabled",
    "admin interface is on a separate subdomain",
]

def _admin_prose() -> str:
    return random.choice(_ADMIN_PROSE)


# --- C: admin in UI labels / navigation ---
_ADMIN_UI = [
    "Admin",
    "Admin Dashboard",
    "Admin Settings",
    "Admin Console",
    "Admin Panel",
    "Go to Admin",
    "Admin Login",
    "Admin Portal",
    "Back to Admin",
    "Admin Menu",
    "Open Admin View",
    "Admin Notifications",
    "Admin Tools",
    "Admin Reports",
    "Site Admin",
    "Super Admin",
    "Store Admin",
    "User Admin",
    "Product Admin",
    "Admin Home",
]

def _admin_ui() -> str:
    return random.choice(_ADMIN_UI)


# --- D: general normal inputs ---
_USERNAMES = ["alice_w", "bob.jones99", "carol_m", "dave_t", "eve123",
              "frank_b", "grace.h", "heidip", "ivanm", "judy_k"]
_EMAILS    = ["user@example.com", "test.user@mail.org", "contact@demo.net",
              "info@sample.io", "hello@work.co", "support@help.org"]
_SEARCHES  = ["laptop bag", "wireless keyboard", "coffee table", "running shoes",
              "phone case", "desk lamp", "notebook", "travel mug"]
_PHRASES   = ["order placed", "account created", "settings saved", "profile updated",
              "item added to cart", "payment confirmed", "subscription renewed",
              "password changed", "email verified", "address updated"]

def _general_normal() -> str:
    fn = random.choice([
        lambda: random.choice(_USERNAMES),
        lambda: random.choice(_EMAILS),
        lambda: random.choice(_SEARCHES),
        lambda: random.choice(_PHRASES),
        lambda: str(random.randint(1, 99999)),
    ])
    return fn()


# --- E: names with apostrophes ---
_APOS_NAMES = [
    "O'Brien", "O'Reilly", "O'Sullivan", "D'Angelo", "D'Arcy",
    "it's working", "don't show this", "user's cart", "admin's note",
    "today's date", "yesterday's orders", "Smith's profile",
    "I'm logged in", "you're registered", "we've confirmed",
    "that's the admin page", "here's the admin link",
    "O'Connor's account", "O'Neill's order", "customer's address",
]

def _apostrophe_name() -> str:
    return random.choice(_APOS_NAMES)


_NORMAL_GENS = [
    (_admin_url,       "A"),
    (_admin_prose,     "B"),
    (_admin_ui,        "C"),
    (_general_normal,  "D"),
    (_apostrophe_name, "E"),
]

def generate_normal_dev(n_per_cat: int) -> list[str]:
    results = []
    for fn, _ in _NORMAL_GENS:
        for _ in range(n_per_cat):
            results.append(fn())
    return results


# ===========================================================================
# INJECTION
# ===========================================================================

_COMMENTS = ["--", "--+", "#", "/**/"]

# --- F: CHAR()-encoded injections ---
# CHAR(49) = '1', CHAR(48) = '0', CHAR(39) = "'", etc.
_CHAR_PAYLOADS = [
    "' OR CHAR(49)=CHAR(49) --",
    "' OR CHAR(49)=CHAR(49) #",
    "' OR CHAR(49)=CHAR(49) /**/",
    "' AND CHAR(49)=CHAR(49) --",
    "1 OR CHAR(49)=CHAR(49) --",
    "' UNION SELECT CHAR(117,115,101,114) --",
    "' UNION SELECT CHAR(117,115,101,114) #",
    "' UNION SELECT CHAR(97,100,109,105,110) --",
    "' UNION SELECT NULL,CHAR(117,115,101,114) --",
    "CHAR(39) OR CHAR(49)=CHAR(49) --",
    "' OR ASCII(CHAR(49))=49 --",
    "' AND CHAR(48)=CHAR(48) --",
    "1 AND CHAR(49)=CHAR(49) --",
    "admin' AND CHAR(49)=CHAR(49) --",
    "' OR CHAR(49,48)=CHAR(49,48) --",
    "' UNION SELECT CHAR(118,101,114,115,105,111,110) --",
    "'; SELECT CHAR(65,68,77,73,78) --",
    "' OR CHAR(49)>CHAR(48) --",
    "CHAR(117,115,101,114) UNION SELECT NULL --",
    "' OR 1=CHAR(49)-CHAR(48) --",
]

def _char_encoded() -> str:
    return random.choice(_CHAR_PAYLOADS)


# --- G: SHUTDOWN and CREATE TABLE stacked queries ---
_SHUTDOWN_CREATE = [
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
    "'; CREATE DATABASE test2 --",
    "'; SHUTDOWN; DROP TABLE users --",
    "1'; CREATE TABLE log2 (ts DATETIME) --",
    "' OR 1=1; SHUTDOWN --",
    "'; SHUTDOWN; INSERT INTO users VALUES(1,'hacker') --",
    "x'; CREATE TABLE tokens (tok TEXT) --",
    "'; CREATE TABLE tmp2 (x TEXT, y TEXT) --",
    "'; SHUTDOWN --+",
    "1 OR 1=1; SHUTDOWN #",
]

def _shutdown_create() -> str:
    return random.choice(_SHUTDOWN_CREATE)


# --- H: MySQL versioned / conditional comments ---
_VERSIONED_COMMENT = [
    "'/*!50000OR*/1=1 --",
    "'/*!OR*/1=1 --",
    "'/*!50000OR*//*!50000'1'*/=/*!50000'1'*/ --",
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
]

def _versioned_comment() -> str:
    return random.choice(_VERSIONED_COMMENT)


# --- I: classic varied (tautologies, UNION, time-based) ---
def _classic_varied() -> str:
    cmt = random.choice(_COMMENTS)
    n   = random.randint(1, 9)
    return random.choice([
        f"' OR '1'='1 {cmt}",
        f"' OR {n}={n} {cmt}",
        f"' UNION SELECT null,null {cmt}",
        f"' UNION SELECT null,null,null {cmt}",
        f"1 AND SLEEP({n}) {cmt}",
        f"' AND SLEEP({n}) {cmt}",
        f"'; DROP TABLE users {cmt}",
        f"' UNION SELECT username,password FROM users {cmt}",
        f"admin' {cmt}",
        f"' OR 1=1 {cmt}",
        f"1' OR '1'='1 {cmt}",
        f"' OR 'x'='x {cmt}",
        f"1 OR 1=1 {cmt}",
        f"' AND 1=1 {cmt}",
        f"1; SELECT version() {cmt}",
    ])


# --- J: blind boolean and error-based with new patterns ---
def _blind_and_error() -> str:
    cmt = random.choice(_COMMENTS)
    n   = random.randint(1, 9)
    return random.choice([
        f"' AND length(username)>{n} {cmt}",
        f"' AND substring(username,1,1)='a' {cmt}",
        f"' AND ASCII(SUBSTRING(password,1,1))>64 {cmt}",
        f"1 AND (SELECT COUNT(*) FROM users)>0 {cmt}",
        f"' AND EXTRACTVALUE(1,CONCAT(0x7e,version())) {cmt}",
        f"' AND UPDATEXML(1,CONCAT(0x7e,user()),1) {cmt}",
        f"' AND (SELECT 1 FROM information_schema.tables LIMIT 1)=1 {cmt}",
        f"1 AND EXISTS(SELECT * FROM users) {cmt}",
        f"' AND (SELECT table_name FROM information_schema.tables LIMIT 1)='users' {cmt}",
        f"' OR (SELECT COUNT(*) FROM users WHERE username='admin')>0 {cmt}",
        f"1 AND 1=(SELECT 1/0) {cmt}",
        f"' AND exp(~(SELECT*FROM(SELECT version())a)) {cmt}",
        f"' AND gtid_subset(version(),0) {cmt}",
        f"1' AND ORD(SUBSTR(username,1,1))>64 {cmt}",
        f"' AND BENCHMARK({n*100000},SHA1('a')) {cmt}",
    ])


_INJECTION_GENS = [
    (_char_encoded,      "F"),
    (_shutdown_create,   "G"),
    (_versioned_comment, "H"),
    (_classic_varied,    "I"),
    (_blind_and_error,   "J"),
]

def generate_injection_dev(n_per_cat: int) -> list[str]:
    results = []
    for fn, _ in _INJECTION_GENS:
        for _ in range(n_per_cat):
            results.append(fn())
    return results


# ===========================================================================
# Overlap check
# ===========================================================================

def _load_norm_set(path: str) -> set[str]:
    import csv as _csv
    s = set()
    if not os.path.exists(path):
        return s
    with open(path, newline="", encoding="utf-8") as f:
        for row in _csv.DictReader(f):
            s.add(" ".join(row["text"].lower().split()))
    return s


# ===========================================================================
# Main
# ===========================================================================

def main():
    random.seed(DEV_SEED)
    normal     = generate_normal_dev(N_PER_CATEGORY)
    injections = generate_injection_dev(N_PER_CATEGORY)

    rows = [(t, 0) for t in normal] + [(t, 1) for t in injections]
    random.shuffle(rows)

    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        writer.writerows(rows)

    n0 = sum(1 for _, l in rows if l == 0)
    n1 = sum(1 for _, l in rows if l == 1)
    print(f"Dev dataset written to {OUT_PATH}  ({len(rows)} rows)")
    print(f"  label=0 (normal)   : {n0}")
    print(f"  label=1 (injection): {n1}")

    all_texts = [t for t, _ in rows]
    for ref_path, ref_name in [(TRAIN_PATH, "dataset.csv"), (EVAL_PATH, "eval_dataset.csv")]:
        ref_set = _load_norm_set(ref_path)
        if not ref_set:
            print(f"\n{ref_name}: not found — overlap check skipped")
            continue
        exact = sum(1 for t in all_texts if " ".join(t.lower().split()) in ref_set)
        n_ov  = sum(1 for t, l in rows if l == 0 and " ".join(t.lower().split()) in ref_set)
        i_ov  = sum(1 for t, l in rows if l == 1 and " ".join(t.lower().split()) in ref_set)
        print(f"\nOverlap vs {ref_name}:")
        print(f"  Total near-duplicates : {exact}")
        print(f"    Normal class        : {n_ov}")
        print(f"    Injection class     : {i_ov}")

    print("\nLimitation: overlap check catches exact strings and whitespace/case")
    print("variants only. Structural variants (same pattern, different numbers)")
    print("are not flagged.")


if __name__ == "__main__":
    main()
