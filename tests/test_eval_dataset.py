"""
Tests for the independent evaluation dataset and ML evaluation methodology.

These tests verify:
  - eval_dataset.csv exists, has correct structure, and contains valid data.
  - No normal-class row in eval_dataset.csv is an exact duplicate of a row
    in dataset.csv (the training source).
  - The saved model loads consistently and produces stable predictions.
  - Metrics computed on a small, known fixture match hand-calculated values.
  - The metrics.json file produced by ml/evaluate.py has all required keys
    and values in the expected ranges.
"""

import sys, os, csv, json, pickle
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

PROJ         = os.path.join(os.path.dirname(__file__), "..")
TRAIN_PATH   = os.path.join(PROJ, "data", "dataset.csv")
EVAL_PATH    = os.path.join(PROJ, "data", "eval_dataset.csv")
MODEL_PATH   = os.path.join(PROJ, "ml", "model.pkl")
METRICS_PATH = os.path.join(PROJ, "ml", "metrics.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _norm(text: str) -> str:
    """Case-insensitive, whitespace-collapsed key for near-duplicate detection."""
    return " ".join(text.lower().split())


# ---------------------------------------------------------------------------
# eval_dataset.csv structure and content
# ---------------------------------------------------------------------------

def test_eval_dataset_exists():
    assert os.path.exists(EVAL_PATH), (
        f"eval_dataset.csv not found at {EVAL_PATH}. "
        "Run: python data/generate_eval_dataset.py"
    )


def test_eval_dataset_has_correct_columns():
    rows = _load_csv(EVAL_PATH)
    assert rows, "eval_dataset.csv is empty"
    assert "text"  in rows[0], "Missing column: text"
    assert "label" in rows[0], "Missing column: label"


def test_eval_dataset_size():
    rows = _load_csv(EVAL_PATH)
    assert len(rows) == 1000, f"Expected 1000 rows, got {len(rows)}"


def test_eval_dataset_class_balance():
    rows = _load_csv(EVAL_PATH)
    n0 = sum(1 for r in rows if r["label"] == "0")
    n1 = sum(1 for r in rows if r["label"] == "1")
    assert n0 == 500, f"Expected 500 normal rows (label=0), got {n0}"
    assert n1 == 500, f"Expected 500 injection rows (label=1), got {n1}"


def test_eval_dataset_labels_valid():
    rows = _load_csv(EVAL_PATH)
    bad  = [r["label"] for r in rows if r["label"] not in ("0", "1")]
    assert not bad, f"Invalid label values found: {bad[:5]}"


def test_eval_dataset_no_empty_inputs():
    rows = _load_csv(EVAL_PATH)
    empty = [i for i, r in enumerate(rows) if not r["text"].strip()]
    assert not empty, f"Empty text at rows: {empty[:5]}"


def test_eval_dataset_no_normal_duplicates_with_training():
    """
    No normal-class (label=0) eval row may be an exact near-duplicate of any
    training row.  This is the critical independence guarantee: the false-
    positive measurement is not contaminated by training examples.

    Injection-class overlap is checked and reported separately; some structural
    similarity is unavoidable because SQL syntax is finite.
    """
    if not os.path.exists(TRAIN_PATH):
        pytest.skip("dataset.csv not found — overlap check skipped")

    train_set   = {_norm(r["text"]) for r in _load_csv(TRAIN_PATH)}
    eval_normal = [r["text"] for r in _load_csv(EVAL_PATH) if r["label"] == "0"]

    overlaps = [t for t in eval_normal if _norm(t) in train_set]
    assert not overlaps, (
        f"{len(overlaps)} normal eval rows are near-duplicates of training rows:\n"
        + "\n".join(f"  {t!r}" for t in overlaps[:10])
    )


def test_eval_dataset_injection_overlap_is_bounded():
    """
    Injection overlap with training data should be less than 20%.
    Some overlap is expected (SQL syntax is finite); this test sets a ceiling.
    """
    if not os.path.exists(TRAIN_PATH):
        pytest.skip("dataset.csv not found — overlap check skipped")

    train_set    = {_norm(r["text"]) for r in _load_csv(TRAIN_PATH)}
    eval_inject  = [r["text"] for r in _load_csv(EVAL_PATH) if r["label"] == "1"]
    overlaps     = [t for t in eval_inject if _norm(t) in train_set]
    overlap_rate = len(overlaps) / len(eval_inject)

    assert overlap_rate < 0.20, (
        f"Injection overlap rate {overlap_rate:.1%} exceeds 20% ceiling. "
        f"({len(overlaps)} of {len(eval_inject)} rows)"
    )


# ---------------------------------------------------------------------------
# Model consistency
# ---------------------------------------------------------------------------

def test_model_file_exists():
    assert os.path.exists(MODEL_PATH), f"model.pkl not found at {MODEL_PATH}"


def test_model_loads_and_predicts():
    """Model loads cleanly and returns a probability in [0, 1]."""
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

    prob = model.predict_proba(["' OR '1'='1"])[0]
    assert len(prob) == 2, "predict_proba should return two class probabilities"
    assert 0.0 <= prob[1] <= 1.0, f"Injection probability {prob[1]} out of range"


def test_model_normal_input_low_probability():
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    prob = model.predict_proba(["alice_smith"])[0][1]
    assert prob < 0.5, f"Normal input 'alice_smith' got ML prob {prob:.3f} >= 0.5"


def test_model_attack_input_high_probability():
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    prob = model.predict_proba(["' UNION SELECT null,null --"])[0][1]
    assert prob > 0.5, (
        f"Known injection got ML prob {prob:.3f} < 0.5"
    )


def test_model_predictions_are_deterministic():
    """Calling predict_proba twice on the same input returns the same result."""
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    input_text = "' OR 1=1 --"
    p1 = model.predict_proba([input_text])[0][1]
    p2 = model.predict_proba([input_text])[0][1]
    assert p1 == p2, "Model predictions are not deterministic"


# ---------------------------------------------------------------------------
# Metrics on a small, known fixture (hand-verifiable)
# ---------------------------------------------------------------------------

def test_metrics_on_known_fixture():
    """
    Manually compute accuracy, precision, recall, F1, and FPR on a 6-sample
    fixture with known ground truth, then verify against sklearn's output.

    Fixture:
      y_true = [0, 0, 0, 1, 1, 1]
      y_pred = [0, 0, 1, 0, 1, 1]
      TN=2  FP=1  FN=1  TP=2
      Accuracy  = 4/6 = 0.6667
      Precision = TP/(TP+FP) = 2/3 = 0.6667
      Recall    = TP/(TP+FN) = 2/3 = 0.6667
      F1        = 2*P*R/(P+R) = 0.6667
      FPR       = FP/(FP+TN) = 1/3 = 0.3333
    """
    from sklearn.metrics import (accuracy_score, precision_score,
                                 recall_score, f1_score, confusion_matrix)

    y_true = [0, 0, 0, 1, 1, 1]
    y_pred = [0, 0, 1, 0, 1, 1]

    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    cm   = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr  = fp / (fp + tn)

    assert abs(acc  - 4/6) < 1e-6, f"Accuracy mismatch: {acc}"
    assert abs(prec - 2/3) < 1e-6, f"Precision mismatch: {prec}"
    assert abs(rec  - 2/3) < 1e-6, f"Recall mismatch: {rec}"
    assert abs(f1   - 2/3) < 1e-6, f"F1 mismatch: {f1}"
    assert abs(fpr  - 1/3) < 1e-6, f"FPR mismatch: {fpr}"
    assert tn == 2 and fp == 1 and fn == 1 and tp == 2


# ---------------------------------------------------------------------------
# metrics.json content
# ---------------------------------------------------------------------------

def test_metrics_json_exists():
    assert os.path.exists(METRICS_PATH), (
        f"metrics.json not found. Run: python ml/evaluate.py"
    )


def test_metrics_json_required_keys():
    with open(METRICS_PATH) as f:
        m = json.load(f)
    required = {"accuracy", "precision", "recall", "f1", "false_positive_rate",
                "roc_auc", "confusion_matrix", "test_samples", "eval_source"}
    missing = required - m.keys()
    assert not missing, f"metrics.json is missing keys: {missing}"


def test_metrics_json_values_in_range():
    with open(METRICS_PATH) as f:
        m = json.load(f)
    for key in ("accuracy", "precision", "recall", "f1",
                "false_positive_rate", "roc_auc"):
        val = m[key]
        assert 0.0 <= val <= 1.0, f"metrics.json[{key!r}] = {val} is out of [0, 1]"


def test_metrics_json_eval_source_is_independent():
    """eval_source field must reference eval_dataset.csv, not dataset.csv."""
    with open(METRICS_PATH) as f:
        m = json.load(f)
    src = m.get("eval_source", "")
    assert "eval_dataset" in src, (
        f"metrics.json eval_source should reference eval_dataset.csv, got: {src!r}"
    )


def test_metrics_json_confusion_matrix_shape():
    with open(METRICS_PATH) as f:
        m = json.load(f)
    cm = m["confusion_matrix"]
    assert len(cm) == 2 and len(cm[0]) == 2, "Confusion matrix must be 2×2"
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    assert tn + fp + fn + tp == m["test_samples"], (
        "Confusion matrix cell sum must equal test_samples"
    )


def test_metrics_json_test_samples_matches_eval_dataset():
    """test_samples in metrics.json must equal the row count of eval_dataset.csv."""
    with open(METRICS_PATH) as f:
        m = json.load(f)
    rows = _load_csv(EVAL_PATH)
    assert m["test_samples"] == len(rows), (
        f"metrics.json test_samples={m['test_samples']} but "
        f"eval_dataset.csv has {len(rows)} rows"
    )
