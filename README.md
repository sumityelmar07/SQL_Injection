# SQL Injection Detection and Prevention Framework

A college-level project demonstrating layered defense against SQL injection attacks.

---

## What This Project Demonstrates

| Layer | Mechanism | Purpose |
|---|---|---|
| Prevention | Parameterized SQL queries | Injection has **no effect** on the database |
| Detection 1 | Regex signature engine | Matches known attack patterns |
| Detection 2 | Rule-based anomaly checks | Catches suspicious input structure |
| Detection 3 | TF-IDF + Logistic Regression | Generalizes to novel variants |
| Code Scanner | Static Analysis (SAST Engine) | Upload & scan source code (.py, .php, .js, .java, .sql) for dynamic SQL flaws |
| Risk scoring | Weighted combination | Single 0-100 score per request |
| Logging | SQLite attack log | Every suspicious input is recorded |
| Dashboard | Flask admin panel | Review all events, view ML metrics |

---

## Quickstart

### 1. Install dependencies

```bash
python3 -m pip install -r requirements.txt
```

### 2. Generate the synthetic dataset and train the ML model

```bash
python3 data/generate_dataset.py
python3 ml/train.py
python3 ml/evaluate.py   # optional: prints full metrics
```

### 3. Run the app

```bash
python3 run.py
```

Open http://127.0.0.1:5000 in your browser.

### 4. Pre-seeded admin account

| Username | Password  | Role  |
|----------|-----------|-------|
| admin    | Admin@1234 | admin |

Register any additional accounts through the `/register` page.

---

## Running the Test Suite

```bash
python3 -m pytest tests/ -v
```

Expected: **141 tests pass**.

---

## How to Demonstrate SQL Injection Detection

1. Log in with the admin account or any registered account.
2. Navigate to **User Search** (`/search`).
3. Try these inputs:

| Input | What it tests |
|---|---|
| `alice` | Normal input — SAFE |
| `' OR '1'='1` | Classic tautology — SUSPICIOUS/BLOCKED |
| `' UNION SELECT null,null --` | UNION injection — BLOCKED |
| `'; DROP TABLE users; --` | Stacked query — BLOCKED |
| `' AND SLEEP(5) --` | Time-based blind — BLOCKED |
| `%27%20OR%20%271%27%3D%271` | URL-encoded tautology — caught after normalization |

4. Go to **Admin Dashboard** (`/admin`) to see all logged events.

---

## Project Structure

```
sql_injection/
├── app/               Flask application (routes, models, config)
├── detection/         Detection pipeline (normalizer, signatures, anomaly, ML, scorer)
├── data/              Synthetic dataset generator
├── ml/                Model training and evaluation scripts
├── tests/             Automated test suite (pytest)
├── templates/         HTML pages
├── static/            CSS and JavaScript
├── instance/app.db    User database (created at startup)
├── logs/attacks.db    Attack event log (created at startup)
└── run.py             Entry point
```

---

## Key Security Decisions

**Parameterized queries everywhere.**
Every database query uses `?` placeholders. Example from `models.py`:
```python
db.execute("SELECT * FROM users WHERE username = ?", (username,))
```
This ensures user input is always treated as data, never as SQL code.

**Passwords hashed with bcrypt.**
No plaintext passwords are ever written to disk.

**No database errors exposed to users.**
All exceptions are caught by Flask error handlers. Only a generic message is shown in the browser; the full traceback goes to the server console.

**Detection does not replace secure queries.**
The detection layer is an alarm system. Even if every check were fooled, parameterized queries would still prevent actual injection.

---

## ML Model Notes

- Trained on 4000 synthetically generated samples (2000 normal, 2000 injection).
- Feature extraction: TF-IDF character n-grams (2–4 characters).
- Classifier: Logistic Regression.
- The 1.0 F1 score reflects that the synthetic test set uses the same patterns as training. Real-world performance on novel, unseen payloads would be lower — the signature and anomaly layers cover those gaps.

---

## Local / Isolated Use Only

This project is a local demonstration tool. Do not:
- Deploy it on a public server
- Test it against any website you do not own
- Use the detection module as the sole defense in a production application
