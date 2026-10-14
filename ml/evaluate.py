"""
Independent evaluation of the trained SQL injection classifier.

Uses data/eval_dataset.csv — a purpose-built holdout set that is SEPARATE
from data/dataset.csv (the training source).  The model is never tuned
against this file.

Metrics saved to ml/metrics.json for display on the admin dashboard.

Run:  python ml/evaluate.py

Phase E change
--------------
Previous version (Phase D) reconstructed the train/test split from
dataset.csv using the same random seed as train.py, meaning the "test set"
was drawn from the same narrow synthetic distribution as training.  That
produced perfect 1.0 scores with no diagnostic value.

This version evaluates on eval_dataset.csv, which was generated
independently (EVAL_SEED=137, different input categories, never passed to
train.py).  The resulting scores are therefore an honest measurement of
generalisation, not a memorisation check.

Metric glossary
---------------
Accuracy   : fraction of all predictions that were correct
Precision  : of all inputs flagged as injection, what fraction really were
Recall     : of all actual injections, what fraction the model caught
F1         : harmonic mean of precision and recall
FPR        : false-positive rate = FP / (FP + TN)
             the fraction of legitimate inputs wrongly flagged as injection
ROC-AUC    : area under the ROC curve; 1.0 = perfect, 0.5 = random coin flip

Why 1.0 on synthetic data does not mean real-world security
------------------------------------------------------------
- Both training and evaluation data are machine-generated from a fixed set
  of templates.  A real attacker uses novel encoding, obfuscation, and
  multi-step payloads not represented here.
- The classifier is one of three signals (signatures, anomaly, ML).  Its
  score alone does not determine blocking.
- Genuine evaluation requires a mix of real-world payloads (from public
  datasets such as CSIC 2010, SecBench, or OWASP) and real user traffic.
  That is outside the scope of this college project.
"""

import os
import sys
import json
import pickle

import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, classification_report,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detection.normalizer import normalize

EVAL_DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "eval_dataset.csv")
MODEL_PATH        = os.path.join(os.path.dirname(__file__), "model.pkl")
METRICS_PATH      = os.path.join(os.path.dirname(__file__), "metrics.json")


def main():
    for path, name in [(EVAL_DATASET_PATH, "eval_dataset"), (MODEL_PATH, "model")]:
        if not os.path.exists(path):
            print(f"ERROR: {name} not found at {path}")
            print("  Generate it with:  python data/generate_eval_dataset.py")
            sys.exit(1)

    # Load the independent evaluation set — never split or reuse training data.
    df = pd.read_csv(EVAL_DATASET_PATH)
    print(f"Evaluation dataset: {len(df)} rows  "
          f"(normal={( df.label==0).sum()}, injection={(df.label==1).sum()})")

    X_test = df["text"].apply(normalize).tolist()
    y_test = df["label"].tolist()

    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    auc  = roc_auc_score(y_test, y_proba)
    cm   = confusion_matrix(y_test, y_pred)

    tn, fp, fn, tp = cm.ravel()
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0

    print("=" * 55)
    print("ML Model Evaluation — INDEPENDENT eval_dataset.csv")
    print("=" * 55)
    print(f"  Accuracy            : {acc:.4f}")
    print(f"  Precision           : {prec:.4f}")
    print(f"  Recall              : {rec:.4f}")
    print(f"  F1 Score            : {f1:.4f}")
    print(f"  False-Positive Rate : {fpr:.4f}  ({fp} FP out of {fp+tn} normal inputs)")
    print(f"  ROC-AUC             : {auc:.4f}")
    print()
    print(f"Confusion Matrix  (rows=actual, cols=predicted)")
    print(f"  TN={tn}  FP={fp}")
    print(f"  FN={fn}  TP={tp}")
    print()
    print(classification_report(y_test, y_pred, target_names=["normal", "injection"]))

    # Show false positives (legit inputs misclassified as injection)
    fps = [(df.iloc[i]["text"], y_proba[i])
           for i in range(len(y_test)) if y_test[i] == 0 and y_pred[i] == 1]
    if fps:
        print(f"False positives ({len(fps)} total — legitimate inputs flagged as injection):")
        for text, prob in sorted(fps, key=lambda x: -x[1])[:10]:
            print(f"  [{prob:.3f}] {text!r}")
        print()

    # Show false negatives (injections the model missed)
    fns = [(df.iloc[i]["text"], y_proba[i])
           for i in range(len(y_test)) if y_test[i] == 1 and y_pred[i] == 0]
    if fns:
        print(f"False negatives ({len(fns)} total — injections the model missed):")
        for text, prob in sorted(fns, key=lambda x: x[1])[:10]:
            print(f"  [{prob:.3f}] {text!r}")
        print()

    metrics = {
        "accuracy":           round(acc,  4),
        "precision":          round(prec, 4),
        "recall":             round(rec,  4),
        "f1":                 round(f1,   4),
        "false_positive_rate": fpr,
        "roc_auc":            round(auc,  4),
        "confusion_matrix":   cm.tolist(),
        "test_samples":       len(y_test),
        "eval_source":        "eval_dataset.csv (independent of training data)",
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics saved to {METRICS_PATH}")


if __name__ == "__main__":
    main()
