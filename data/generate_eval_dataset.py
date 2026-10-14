"""
Generates an INDEPENDENT evaluation dataset for the SQL injection classifier.

Output: data/eval_dataset.csv  with columns [text, label]
  label=0  normal input
  label=1  injection attempt

Run:  python data/generate_eval_dataset.py

Independence guarantees
-----------------------
- Uses EVAL_SEED=137 (training used RANDOM_SEED=42 in generate_dataset.py).
- Normal categories include several types absent from training data:
  names with apostrophes, product descriptions, user bios, dates, prices,
  URL paths, and a different set of SQL-in-context phrases.
- Injection categories include spacing and capitalisation variations, different
  SQL dialects (MySQL / MSSQL / PostgreSQL / SQLite), and obfuscation patterns.
- Exact-duplicate and near-duplicate overlap with dataset.csv is checked and
  reported at generation time (and also by tests/test_eval_dataset.py).

Evaluation methodology note
----------------------------
This file is used ONLY by ml/evaluate.py.  It must NEVER be passed to
ml/train.py.  The model is evaluated once on this fixed set after all model
and preprocessing choices have been finalised.  Do not tune the model against
this file.

Category table
--------------
NORMAL (500 total, 50 per category)
  A  names_apostrophe   — forenames/surnames containing a single apostrophe
  B  product_desc       — realistic product listing text
  C  user_bio           — short user-profile sentences
  D  email_varied       — email addresses with diverse formats/domains
  E  phone_number       — formatted telephone numbers
  F  date_format        — dates in ISO, US, and natural-language formats
  G  price_format       — currency and numeric amounts
  H  url_path           — URL-style path strings
  I  sql_context_phrase — sentences where SQL words appear in plain English
  J  compound_mixed     — combinations of the above types

INJECTION (500 total, ~50 per category)
  K  tautology_varied        — spacing / capitalisation / quote-style variants
  L  union_select_varied     — column count, whitespace, and keyword-case variants
  M  stacked_query_varied    — different DDL/DML commands after semicolon
  N  blind_boolean_varied    — AND/OR boolean payloads
  O  time_based_multi_db     — SLEEP/WAITFOR/pg_sleep/BENCHMARK variants
  P  error_based_varied      — EXTRACTVALUE, UPDATEXML, type-error tricks
  Q  file_operation          — LOAD_FILE / INTO OUTFILE variants
  R  comment_obfuscated      — inline-comment splitting and special-comment syntax
  S  info_schema_probe        — probing system tables by various names
  T  encoding_variant        — hex literals, URL-encoded digits, CHAR() tricks
"""

import csv
import os
import random

EVAL_SEED = 137
random.seed(EVAL_SEED)

OUT_PATH      = os.path.join(os.path.dirname(__file__), "eval_dataset.csv")
TRAIN_PATH    = os.path.join(os.path.dirname(__file__), "dataset.csv")
N_PER_CATEGORY = 50   # 10 categories × 50 = 500 per class


# ===========================================================================
# NORMAL categories
# ===========================================================================

# --- A: names with apostrophes ---
# Training data has no apostrophe-containing names.
# Tests whether the model and anomaly checker tolerate legitimate Irish/French
# names, possessives, and contractions without raising a false positive.
_APOSTROPHE_NAMES = [
    "O'Brien", "O'Reilly", "O'Sullivan", "O'Connor", "O'Neill",
    "O'Malley", "O'Doherty", "O'Shea", "O'Callaghan", "O'Rourke",
    "D'Angelo", "D'Arcy", "D'Amico", "D'Cruz", "D'Souza",
    "O'Brian", "O'Donnell", "O'Farrell", "O'Grady", "O'Halloran",
    "O'Keefe", "O'Leary", "O'Mahony", "O'Quinlan", "O'Regan",
    "it's fine", "don't worry", "I'm logged in", "that's correct",
    "user's profile", "admin's page", "today's orders", "yesterday's log",
    "company's website", "product's price", "buyer's address", "seller's name",
    "Smith's account", "Jones's email", "Brown's order", "Taylor's cart",
    "isn't available", "wasn't found", "couldn't load", "shouldn't retry",
    "they're confirmed", "you're registered", "we're processing", "I've ordered",
    "there's an error", "here's your link",
]


def _name_apostrophe() -> str:
    return random.choice(_APOSTROPHE_NAMES)


# --- B: product descriptions ---
# Realistic e-commerce product text.  Contains numbers, hyphens, units.
_PRODUCTS = [
    "Samsung 65-inch QLED 4K Smart TV",
    "Nike Air Max 270 running shoes size 10",
    "Apple MacBook Pro 14-inch M3 chip 16GB RAM",
    "Organic fair-trade ground coffee 500g",
    "Sony WH-1000XM5 noise-cancelling headphones",
    "IKEA KALLAX shelf unit 77x77cm white",
    "Levi's 501 Original Fit jeans W32 L32",
    "Canon EOS R10 mirrorless camera body only",
    "USB-C to Lightning cable 1m braided",
    "Instant Pot Duo 7-in-1 electric pressure cooker 6qt",
    "Kindle Paperwhite 11th gen 8GB waterproof",
    "Dyson V15 Detect cordless vacuum cleaner",
    "Dell 27-inch 4K USB-C monitor S2722QC",
    "Logitech MX Master 3S wireless mouse",
    "Philips Hue white and colour ambiance starter kit",
    "HP LaserJet Pro M404dn printer",
    "Breville Barista Express espresso machine",
    "Osprey Farpoint 40 travel backpack",
    "New Balance 990v5 grey men's size 9",
    "Bose QuietComfort 45 Bluetooth headphones",
    "Anker 65W USB-C GaN charger 4-port",
    "Ergotron LX desk mount dual monitor arm",
    "LG 34-inch ultrawide curved monitor",
    "Nespresso Vertuo Next coffee machine",
    "Weber Spirit II E-310 gas grill",
    "Garmin Forerunner 255 GPS running watch",
    "Hydro Flask 32oz wide-mouth water bottle",
    "Patagonia Men's Down Sweater Hoody",
    "Victorinox Swiss Army Traveller Lite watch",
    "Ring Video Doorbell Pro 2",
    "Nest Learning Thermostat 3rd gen",
    "Tile Mate 4-pack Bluetooth tracker",
    "Moleskine Classic Notebook large ruled black",
    "Seagate Backup Plus 4TB portable hard drive",
    "WD Blue 1TB 2.5-inch SATA SSD",
    "Razer DeathAdder V3 gaming mouse",
    "SteelSeries Arctis Nova Pro wireless headset",
    "ASUS ROG Strix B550-F Gaming motherboard",
    "Corsair Vengeance 32GB DDR4 3200MHz RAM",
    "NZXT H510 mid-tower ATX case",
    "Oakley Frogskins sunglasses polished black",
    "Fitbit Charge 5 activity tracker",
    "Jabra Evolve2 65 wireless headset UC",
    "Plantronics Voyager 5200 Bluetooth headset",
    "Belkin 12-outlet power strip surge protector",
    "Philips 55PUS8507 4K OLED TV",
    "KitchenAid Artisan Series 5qt stand mixer red",
    "Roomba i7+ robot vacuum with self-emptying base",
    "Keurig K-Slim coffee maker single serve",
    "Braun Series 9 Pro electric shaver",
]


def _product_desc() -> str:
    return random.choice(_PRODUCTS)


# --- C: user bios ---
# Short profile sentences.  May contain SQL words in innocent contexts
# (e.g. "select", "join", "union") without being injections.
_BIOS = [
    "Software engineer with 5 years of experience in Python",
    "Graphic designer based in New York City",
    "Marketing manager at a mid-size e-commerce company",
    "Final-year computer science student at UCL",
    "Freelance photographer specialising in portrait work",
    "Data analyst with a background in finance",
    "Product manager who likes to join hackathons",
    "I enjoy hiking and reading science fiction novels",
    "DevOps engineer passionate about automation",
    "UX researcher with experience in user testing",
    "I select my projects carefully based on impact",
    "Open-source contributor and conference speaker",
    "Retired teacher now learning to code",
    "I like to order specialty coffee from small roasters",
    "Node.js developer interested in backend performance",
    "Junior developer working on my first React app",
    "I have been in the industry for over 20 years",
    "Startup founder with a background in healthcare",
    "Cybersecurity enthusiast studying for my OSCP",
    "Content creator on YouTube and Twitch",
    "Musician and part-time web developer",
    "I help small businesses create online stores",
    "Business analyst who bridges tech and operations",
    "I joined the company three months ago",
    "Passionate about machine learning and NLP",
    "I run a group of Python meetups in London",
    "Currently working on a TypeScript migration",
    "Mobile developer on iOS and Android platforms",
    "I like to drop into local coffee shops to work",
    "Former nurse retraining as a software developer",
    "Research scientist at a biotech startup",
    "Building a SaaS product in my spare time",
    "I set up automated backups for all my projects",
    "Interested in distributed systems and databases",
    "I create tutorials about web accessibility",
    "Team lead managing a group of eight engineers",
    "I have expertise in SQL performance tuning",
    "Working on a new feature for our mobile app",
    "I use Postgres and MySQL for most projects",
    "Full-stack developer fluent in six languages",
    "I select the best tools for each job",
    "Not sure what my next project will be yet",
    "Currently between jobs and upskilling in cloud",
    "I joined the waitlist for the new product",
    "Deeply interested in privacy and data rights",
    "I update my blog about twice a month",
    "Learning Rust for systems programming",
    "I group my tasks by priority each morning",
    "Tinkerer who builds electronics at home",
    "Remote worker based in Lisbon, Portugal",
]


def _user_bio() -> str:
    return random.choice(_BIOS)


# --- D: email addresses ---
_EMAIL_FIRST = ["jane", "michael", "sara", "tom", "lisa", "paul", "nina",
                "james", "priya", "chen", "fatima", "luke", "anna", "derek"]
_EMAIL_LAST  = ["white", "kumar", "zhang", "garcia", "murphy", "osei",
                "novak", "patel", "costa", "kim", "schneider", "ali"]
_EMAIL_DOMAINS = ["gmail.com", "outlook.com", "yahoo.co.uk", "proton.me",
                  "icloud.com", "hotmail.fr", "web.de", "work.io",
                  "company.org", "university.edu", "nhs.net", "gov.uk"]


def _email_varied() -> str:
    first  = random.choice(_EMAIL_FIRST)
    last   = random.choice(_EMAIL_LAST)
    sep    = random.choice([".", "_", ""])
    num    = str(random.randint(10, 99)) if random.random() < 0.4 else ""
    domain = random.choice(_EMAIL_DOMAINS)
    return f"{first}{sep}{last}{num}@{domain}"


# --- E: phone numbers ---
_PHONE_FORMATS = [
    "+1-{:03d}-{:03d}-{:04d}",
    "+44 {0:04d} {1:06d}",
    "({:03d}) {:03d}-{:04d}",
    "{:03d}.{:03d}.{:04d}",
    "+33 {:d} {:02d} {:02d} {:02d} {:02d}",
    "+49 {:03d} {:07d}",
]


def _phone_number() -> str:
    a, b, c = random.randint(200, 999), random.randint(200, 999), random.randint(1000, 9999)
    fmt = random.choice(_PHONE_FORMATS)
    try:
        return fmt.format(a, b, c)
    except Exception:
        return f"+1-{a}-{b}-{c}"


# --- F: date formats ---
_MONTHS = ["January", "February", "March", "April", "May", "June",
           "July", "August", "September", "October", "November", "December"]
_MONTH_SHORT = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _date_format() -> str:
    y = random.randint(2020, 2026)
    m = random.randint(1, 12)
    d = random.randint(1, 28)
    fmt = random.choice([
        f"{y}-{m:02d}-{d:02d}",
        f"{d:02d}/{m:02d}/{y}",
        f"{m:02d}-{d:02d}-{y}",
        f"{_MONTHS[m-1]} {d}, {y}",
        f"{d} {_MONTH_SHORT[m-1]} {y}",
        f"{_MONTH_SHORT[m-1]} {d}th {y}",
        f"{d:02d}.{m:02d}.{y}",
    ])
    return fmt


# --- G: price and numeric formats ---
def _price_format() -> str:
    amount = round(random.uniform(0.99, 9999.99), 2)
    currency = random.choice(["$", "€", "£", "CHF ", "¥"])
    fmt = random.choice([
        f"{currency}{amount:,.2f}",
        f"{amount:.2f} USD",
        f"{int(amount)} items",
        f"{random.randint(1, 100)}% off",
        f"{amount:.0f}",
        f"#{random.randint(1000, 99999)}",
    ])
    return fmt


# --- H: URL paths ---
_URL_SEGMENTS = ["products", "category", "search", "user", "order",
                 "checkout", "account", "admin", "api", "v1", "v2",
                 "items", "detail", "review", "cart", "wishlist"]
_URL_SLUGS = ["nike-air-max", "red-dress", "laptop-bag", "wireless-mouse",
              "coffee-beans", "user-settings", "order-history",
              "shipping-address", "payment-methods", "product-reviews"]


def _url_path() -> str:
    depth = random.randint(1, 4)
    parts = random.choices(_URL_SEGMENTS, k=depth)
    slug  = random.choice(_URL_SLUGS) if random.random() < 0.5 else ""
    path  = "/" + "/".join(parts)
    if slug:
        path += "/" + slug
    if random.random() < 0.3:
        path += f"?page={random.randint(1, 10)}"
    return path


# --- I: SQL keywords in innocent English context ---
# These are distinct from the _NATURAL_PHRASES in generate_dataset.py,
# testing a broader variety of contexts.
_SQL_CONTEXT_PHRASES = [
    "I need to select a new password",
    "please update my shipping address",
    "create a new support ticket",
    "delete the draft I saved yesterday",
    "insert a new row in the spreadsheet",
    "drop the file into the upload box",
    "where is the nearest store located",
    "join the loyalty programme for rewards",
    "from the menu please choose a category",
    "I like the table of contents on this page",
    "the column header is missing from the report",
    "limit the results to this month only",
    "not sure which option to select",
    "or you can call our support line",
    "and the order will ship within 3 days",
    "between 9am and 5pm on weekdays",
    "group the items by delivery date",
    "having trouble with my password reset",
    "like new condition never opened",
    "null and void after 30 days",
    "exists in the product catalogue",
    "in case of emergency contact us",
    "on the order confirmation page",
    "set as the default payment method",
    "cast iron cookware lasts a lifetime",
    "convert the file to PDF format",
    "execute the plan as discussed",
    "schema for the new API endpoint",
    "offset the cost with loyalty points",
    "the database of registered users",
    "alter the delivery address before dispatch",
    "grant access to the shared drive",
    "we have stock of this item",
    "if the order is not found contact support",
    "the inner join of these two spreadsheets",
    "outer packaging may be damaged in transit",
    "all values are inclusive of VAT",
    "unique identifier for each order",
    "trigger a refund from the returns page",
    "view the transaction history",
    "index your company in our directory",
    "replace the batteries every six months",
    "truncate long descriptions in the preview",
    "union of two mailing lists was merged",
    "begin the checkout process here",
    "commit to a subscription plan today",
    "rollback period is 30 days",
    "lock in the early-bird price now",
    "distinct packaging for gift orders",
    "average delivery time is 3 to 5 days",
]


def _sql_context_phrase() -> str:
    return random.choice(_SQL_CONTEXT_PHRASES)


# --- J: compound/mixed ---
def _compound_mixed() -> str:
    generators = [
        _name_apostrophe,
        _product_desc,
        _user_bio,
        _email_varied,
        _phone_number,
        _date_format,
        _price_format,
        _url_path,
        _sql_context_phrase,
    ]
    # Sometimes combine two elements (e.g. name + email)
    if random.random() < 0.3:
        a = random.choice(generators)()
        b = random.choice(generators)()
        return f"{a} / {b}"
    return random.choice(generators)()


_NORMAL_GENERATORS_EVAL = [
    (_name_apostrophe,   "A"),
    (_product_desc,      "B"),
    (_user_bio,          "C"),
    (_email_varied,      "D"),
    (_phone_number,      "E"),
    (_date_format,       "F"),
    (_price_format,      "G"),
    (_url_path,          "H"),
    (_sql_context_phrase,"I"),
    (_compound_mixed,    "J"),
]


def generate_normal_eval(n_per_cat: int) -> list[str]:
    samples = []
    for fn, _ in _NORMAL_GENERATORS_EVAL:
        for _ in range(n_per_cat):
            samples.append(fn())
    return samples


# ===========================================================================
# INJECTION categories
# ===========================================================================

_COMMENT_STYLES = ["--", "--+", "#", "/**/", "/*!*/", "-- -"]
_QUOTES = ["'", '"']


# --- K: tautology with varied spacing, capitalisation, quote styles ---
def _tautology_varied() -> str:
    q   = random.choice(_QUOTES)
    cmt = random.choice(_COMMENT_STYLES)
    sp  = " " * random.randint(1, 3)
    op  = random.choice(["OR", "or", "Or", "oR", "||"])
    n   = random.randint(1, 9)
    variants = [
        f"{q}{sp}{op}{sp}{q}1{q}={q}1{sp}{cmt}",
        f"{q}{sp}{op}{sp}{n}{sp}={sp}{n}",
        f"1{sp}{op}{sp}1=1{sp}{cmt}",
        f"{q}{sp}{op}{sp}{q}x{q}={q}x{q}",
        f"admin{q}{sp}{cmt}",
        f"{q}{sp}{op}{sp}{n}={n}--",
        f"1{q}{sp}{op}{sp}{q}1{q}={q}1",
        f"{q}{sp}OR{sp}TRUE{sp}{cmt}",
        f"{q}{sp}OR{sp}NULL IS NULL{sp}{cmt}",
        f"1 {op} 2>1 {cmt}",
    ]
    return random.choice(variants)


# --- L: UNION SELECT with column count, spacing, keyword-case variants ---
def _union_select_varied() -> str:
    cols  = random.randint(1, 6)
    nulls = ", ".join(["null"] * cols)
    cmt   = random.choice(_COMMENT_STYLES)
    sp    = " " * random.randint(1, 3)
    u     = random.choice(["UNION", "Union", "union", "UNION ALL", "union all"])
    s     = random.choice(["SELECT", "Select", "select"])
    variants = [
        f"'{sp}{u}{sp}{s}{sp}{nulls}{sp}{cmt}",
        f"-1{sp}{u}{sp}{s}{sp}{nulls}",
        f"0{sp}{u}{sp}{s}{sp}username,password FROM users{sp}{cmt}",
        f"'{sp}{u}{sp}{s}{sp}1,2,3{sp}{cmt}",
        f"'{sp}{u}{sp}{s}{sp}@@version{sp}{cmt}",
        f"'{sp}{u}{sp}{s}{sp}user(),database(){sp}{cmt}",
        f"' {u} {s} NULL,NULL,NULL,NULL {cmt}",
        f"999 {u} {s} {nulls} {cmt}",
    ]
    return random.choice(variants)


# --- M: stacked queries ---
def _stacked_varied() -> str:
    cmt = random.choice(_COMMENT_STYLES)
    variants = [
        "'; DROP TABLE users --",
        "'; DROP TABLE orders --",
        "'; DROP TABLE sessions --",
        "'; TRUNCATE TABLE users --",
        "'; DELETE FROM users WHERE 1=1 --",
        "'; DELETE FROM orders --",
        "'; INSERT INTO users VALUES('evil','x@x.com','pw','admin') --",
        "'; UPDATE users SET password='hacked' WHERE 1=1 --",
        "'; UPDATE users SET role='admin' --",
        "'; ALTER TABLE users ADD COLUMN backdoor TEXT --",
        "'; CREATE TABLE tmp (x TEXT) --",
        f"1; EXEC xp_cmdshell('whoami') {cmt}",
        f"1; EXEC xp_cmdshell('net user') {cmt}",
        f"1; EXECUTE sp_configure 'show advanced options', 1 {cmt}",
        "'; CALL sleep(5) --",
        "'; SHUTDOWN --",
        f"x'; COMMIT; DROP TABLE users; BEGIN {cmt}",
        f"1'; BEGIN TRANSACTION; DELETE FROM logs; COMMIT {cmt}",
    ]
    return random.choice(variants)


# --- N: blind boolean ---
def _blind_boolean_varied() -> str:
    cmt = random.choice(_COMMENT_STYLES)
    n   = random.randint(1, 9)
    op  = random.choice(["AND", "and", "And"])
    variants = [
        f"1 {op} {n}={n} {cmt}",
        f"1 {op} {n+1}={n} {cmt}",
        f"' {op} '1'='1 {cmt}",
        f"' {op} '1'='2 {cmt}",
        f"1' {op} 1=1 {cmt}",
        f"1' {op} 1=2 {cmt}",
        f"' {op} length(username)>0 {cmt}",
        f"' {op} substring(username,1,1)='a' {cmt}",
        f"1 {op} (SELECT COUNT(*) FROM users)>0 {cmt}",
        f"' {op} ASCII(SUBSTRING(password,1,1))>64 {cmt}",
        f"1 {op} EXISTS(SELECT * FROM users) {cmt}",
        f"x' {op} 1=1 {cmt}",
    ]
    return random.choice(variants)


# --- O: time-based, multiple database dialects ---
def _time_based_multi_db() -> str:
    secs = random.randint(1, 10)
    cmt  = random.choice(_COMMENT_STYLES)
    variants = [
        # MySQL
        f"' AND SLEEP({secs}) {cmt}",
        f"1 AND SLEEP({secs}) {cmt}",
        f"' OR SLEEP({secs}) {cmt}",
        f"'; SELECT SLEEP({secs}) {cmt}",
        f"' AND BENCHMARK({secs * 100000},MD5('a')) {cmt}",
        # MSSQL
        f"'; WAITFOR DELAY '0:0:{secs}' {cmt}",
        f"1; WAITFOR DELAY '0:0:{secs}'",
        f"'; IF 1=1 WAITFOR DELAY '0:0:{secs}' {cmt}",
        # PostgreSQL
        f"'; SELECT pg_sleep({secs}) {cmt}",
        f"1; SELECT pg_sleep({secs}) {cmt}",
        f"' AND (SELECT pg_sleep({secs})) IS NOT NULL {cmt}",
        # SQLite
        f"' AND randomblob({secs * 100000000}) IS NOT NULL {cmt}",
    ]
    return random.choice(variants)


# --- P: error-based ---
def _error_based_varied() -> str:
    cmt = random.choice(_COMMENT_STYLES)
    variants = [
        f"' AND EXTRACTVALUE(1,CONCAT(0x7e,version())) {cmt}",
        f"' AND EXTRACTVALUE(1,CONCAT(0x7e,database())) {cmt}",
        f"' AND EXTRACTVALUE(1,CONCAT(0x7e,user())) {cmt}",
        f"' AND UPDATEXML(1,CONCAT(0x7e,version()),1) {cmt}",
        f"' AND UPDATEXML(1,CONCAT(0x7e,database()),1) {cmt}",
        f"' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) {cmt}",
        f"' AND exp(~(SELECT*FROM(SELECT version())a)) {cmt}",
        f"' OR 1 GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)) HAVING MIN(0) {cmt}",
        f"' AND gtid_subset(version(),0) {cmt}",
        f"' AND json_keys((SELECT CONVERT((SELECT CONCAT(username,0x7e,password) FROM users LIMIT 1) USING utf8))) {cmt}",
        f"1 AND 1=(SELECT 1/0) {cmt}",
        f"' AND (SELECT * FROM (SELECT(SLEEP(0)))a) {cmt}",
    ]
    return random.choice(variants)


# --- Q: file operations ---
def _file_operation() -> str:
    cmt = random.choice(_COMMENT_STYLES)
    variants = [
        f"' UNION SELECT LOAD_FILE('/etc/passwd') {cmt}",
        f"' UNION SELECT LOAD_FILE('/etc/shadow') {cmt}",
        f"' UNION SELECT LOAD_FILE('/etc/hosts') {cmt}",
        f"' UNION SELECT LOAD_FILE('/proc/version') {cmt}",
        f"' UNION SELECT NULL,LOAD_FILE('/etc/passwd') {cmt}",
        f"' INTO OUTFILE '/var/www/html/shell.php'",
        f"' INTO DUMPFILE '/tmp/out.txt'",
        f"1 UNION SELECT '<?php system($_GET[cmd])?>' INTO OUTFILE '/var/www/html/x.php'",
        f"' UNION SELECT NULL INTO OUTFILE '/tmp/test.txt' {cmt}",
        f"'; COPY users TO '/tmp/users.csv' {cmt}",
    ]
    return random.choice(variants)


# --- R: comment-obfuscated ---
def _comment_obfuscated() -> str:
    variants = [
        "'/**/OR/**/1=1/**/--",
        "' /*!OR*/ '1'='1",
        "UN/**/ION SE/**/LECT null,null --",
        "' OR/**/ 1/**/=/**/1 --",
        "SE/**/LECT * FR/**/OM users --",
        "' UN/*!50000ION*/SE/*!50000LECT*/ null --",
        "'  /*!50000OR*/  1=1 --",
        "1/*!AND*/1=1 --",
        "' /*!50000UNION*/ /*!50000SELECT*/ null --",
        "1 /*!50000AND*/ 1=1",
        "SELE/**/CT user() --",
        "' OR 1=1/*!--*/",
        "'/*!50000OR*//*!50000'1'*/=/*!50000'1'*/",
        "1 OR/**/ 1/**/ =/**/ 1 --",
        "' /*!OR*/ /*!1*/=/*!1*/ --",
    ]
    return random.choice(variants)


# --- S: information schema / system table probing ---
def _info_schema_probe() -> str:
    cmt = random.choice(_COMMENT_STYLES)
    variants = [
        f"' UNION SELECT table_name FROM information_schema.tables {cmt}",
        f"' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' {cmt}",
        f"' UNION SELECT table_schema FROM information_schema.schemata {cmt}",
        f"1 AND 1=(SELECT 1 FROM information_schema.tables LIMIT 1)",
        f"' UNION SELECT user,password FROM mysql.user {cmt}",
        f"' UNION SELECT name FROM sysobjects WHERE xtype='U' {cmt}",
        f"' UNION SELECT name FROM syscolumns {cmt}",
        f"' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database() {cmt}",
        f"' UNION SELECT NULL,table_name FROM information_schema.tables {cmt}",
        f"' AND (SELECT 1 FROM information_schema.tables WHERE table_name='users')=1 {cmt}",
        f"' UNION SELECT username,password FROM users {cmt}",
        f"' UNION SELECT relname FROM pg_class WHERE relkind='r' {cmt}",
        f"' UNION SELECT name FROM sqlite_master WHERE type='table' {cmt}",
    ]
    return random.choice(variants)


# --- T: encoding-based variants ---
def _encoding_variant() -> str:
    cmt = random.choice(_COMMENT_STYLES)
    variants = [
        # CHAR() function to avoid string literals
        f"' UNION SELECT CHAR(117,115,101,114) {cmt}",
        f"' OR CHAR(49)=CHAR(49) {cmt}",
        # hex literals
        f"' OR 0x31=0x31 {cmt}",
        f"' UNION SELECT 0x61646d696e {cmt}",
        f"1 AND 0x31=0x31 {cmt}",
        # URL-encoded digits in SQL payload
        f"' %4fR '1'='1 {cmt}",
        f"' %6fR 1=1 {cmt}",
        # Double-encoded quotes
        f"%27 OR %271%27=%271 {cmt}",
        f"%27%20OR%20%271%27%3D%271 {cmt}",
        # Numeric string comparison
        f"' OR '1' LIKE '1 {cmt}",
        f"' OR '1' REGEXP '1 {cmt}",
        f"' OR 1 IN (1) {cmt}",
        f"' OR 1 BETWEEN 0 AND 2 {cmt}",
        # CONCAT to reconstruct keywords
        f"' UNION SELECT CONCAT(username,0x3a,password) FROM users {cmt}",
        f"' UNION SELECT CONCAT(0x7e,version(),0x7e) {cmt}",
    ]
    return random.choice(variants)


_INJECTION_GENERATORS_EVAL = [
    (_tautology_varied,       "K"),
    (_union_select_varied,    "L"),
    (_stacked_varied,         "M"),
    (_blind_boolean_varied,   "N"),
    (_time_based_multi_db,    "O"),
    (_error_based_varied,     "P"),
    (_file_operation,         "Q"),
    (_comment_obfuscated,     "R"),
    (_info_schema_probe,      "S"),
    (_encoding_variant,       "T"),
]


def generate_injection_eval(n_per_cat: int) -> list[str]:
    samples = []
    for fn, _ in _INJECTION_GENERATORS_EVAL:
        for _ in range(n_per_cat):
            samples.append(fn())
    return samples


# ===========================================================================
# Overlap check
# ===========================================================================

def _load_training_texts() -> set[str]:
    """Return the set of lowercased, whitespace-collapsed training samples."""
    import csv as _csv
    texts = set()
    if not os.path.exists(TRAIN_PATH):
        return texts
    with open(TRAIN_PATH, newline="", encoding="utf-8") as f:
        for row in _csv.DictReader(f):
            texts.add(" ".join(row["text"].lower().split()))
    return texts


def check_overlap(eval_texts: list[str], training_set: set[str]) -> dict:
    exact     = sum(1 for t in eval_texts if t in training_set)
    near_dup  = sum(1 for t in eval_texts
                    if " ".join(t.lower().split()) in training_set)
    return {"exact": exact, "near_duplicate": near_dup, "total_eval": len(eval_texts)}


# ===========================================================================
# Main
# ===========================================================================

def main():
    normal     = generate_normal_eval(N_PER_CATEGORY)
    injections = generate_injection_eval(N_PER_CATEGORY)

    all_texts = normal + injections
    rows = (
        [(t, 0) for t in normal] +
        [(t, 1) for t in injections]
    )
    random.shuffle(rows)

    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        writer.writerows(rows)

    print(f"Eval dataset written to {OUT_PATH}  ({len(rows)} rows)")
    print(f"  label=0 (normal)   : {sum(1 for _, l in rows if l == 0)}")
    print(f"  label=1 (injection): {sum(1 for _, l in rows if l == 1)}")

    # Overlap report
    training_set = _load_training_texts()
    if training_set:
        result = check_overlap(all_texts, training_set)
        print(f"\nOverlap check vs training data (dataset.csv):")
        print(f"  Exact matches          : {result['exact']}")
        print(f"  Near-duplicates (case/space normalised): {result['near_duplicate']}")
        print(f"  Remaining limitation: this check only catches exact and whitespace/case")
        print(f"  variants. Semantically equivalent payloads with different column counts")
        print(f"  or random numbers are not flagged. Some structural overlap in injection")
        print(f"  patterns is unavoidable — all SQL injections share core syntax.")
    else:
        print("\n(dataset.csv not found — overlap check skipped)")


if __name__ == "__main__":
    main()
