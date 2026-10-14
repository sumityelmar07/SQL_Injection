"""
Train the SQL injection classifier.

Steps:
  1. Load data/dataset.csv  (generate it first with: python data/generate_dataset.py)
  2. Normalize each sample with detection.normalizer
  3. Split 80/20 train/test
  4. Build a pipeline: TF-IDF character n-grams → Logistic Regression
  5. Train and save to ml/model.pkl
  6. Print a quick accuracy summary (full metrics are in evaluate.py)

Run:  python ml/train.py
"""

import os
import sys
import pickle

import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Allow importing detection module from project root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detection.normalizer import normalize

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "dataset.csv")
MODEL_PATH   = os.path.join(os.path.dirname(__file__), "model.pkl")


def main():
    if not os.path.exists(DATASET_PATH):
        print("Dataset not found. Run:  python data/generate_dataset.py")
        sys.exit(1)

    print("Loading dataset...")
    df = pd.read_csv(DATASET_PATH)
    print(f"  {len(df)} rows  |  label=0: {(df.label==0).sum()}  label=1: {(df.label==1).sum()}")

    # Normalize every sample the same way the live pipeline does.
    print("Normalizing inputs...")
    X = df["text"].apply(normalize).tolist()
    y = df["label"].tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # TF-IDF with character n-grams (2-4 chars) captures SQL fragments
    # like "or ", "1=1", "'--" even with slight spacing variations.
    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(2, 4),
            max_features=20_000,
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(
            C=5.0,
            max_iter=1000,
            random_state=42,
            solver="lbfgs",
        )),
    ])

    print("Training...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Quick accuracy on test set: {acc:.4f}")
    print("Run  python ml/evaluate.py  for full metrics.")

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()
