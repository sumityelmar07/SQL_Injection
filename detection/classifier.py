"""
Machine-learning classifier.

Loads the trained scikit-learn pipeline (TF-IDF + Logistic Regression)
from ml/model.pkl and exposes a single predict() function that returns
a probability 0.0-1.0.

If the model file does not exist yet (i.e. ml/train.py has not been run),
predict() returns 0.0 so the rest of the detection pipeline still works.
"""

import os
import pickle
from flask import current_app


_model = None          # cached after first load
_model_loaded = False  # True even if load failed, to avoid repeated attempts


def _load_model():
    global _model, _model_loaded
    if _model_loaded:
        return

    try:
        model_path = current_app.config["MODEL_PATH"]
    except RuntimeError:
        # Called outside an app context (e.g. in unit tests without a real app).
        model_path = os.path.join(
            os.path.dirname(__file__), "..", "ml", "model.pkl"
        )

    if os.path.exists(model_path):
        with open(model_path, "rb") as f:
            _model = pickle.load(f)
    # If file is missing, _model stays None and predict() returns 0.0.
    _model_loaded = True


def predict(normalized_input: str) -> float:
    """
    Return the probability (0.0 – 1.0) that *normalized_input* is an injection.
    Returns 0.0 if the model has not been trained yet.
    """
    _load_model()
    if _model is None:
        return 0.0
    proba = _model.predict_proba([normalized_input])[0]
    # Classes are [0=normal, 1=injection]; return the injection probability.
    classes = list(_model.classes_)
    if 1 in classes:
        return float(proba[classes.index(1)])
    return 0.0


def reload_model():
    """Force a fresh load from disk (call after re-training)."""
    global _model, _model_loaded
    _model = None
    _model_loaded = False
    _load_model()
