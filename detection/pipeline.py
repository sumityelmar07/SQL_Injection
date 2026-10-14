"""
Detection pipeline entry point.

Call inspect(raw_input) from any route handler.  Returns a dict with
all signals and the final decision — ready to log or act on.
"""

import json

from .normalizer import normalize
from .signatures import check_signatures
from .anomaly import check_anomalies
from .classifier import predict
from .risk_scorer import compute_risk

try:
    from flask import current_app
    _has_flask = True
except ImportError:
    _has_flask = False


def inspect(raw_input: str) -> dict:
    """
    Run the full detection pipeline on *raw_input*.

    Returns
    -------
    {
        "normalized"    : str,
        "signature_hit" : str | None,   # name of the matching signature
        "signature_score": int,
        "anomaly_score" : int,
        "ml_score"      : float,
        "risk_score"    : int,
        "decision"      : str,          # SAFE | SUSPICIOUS | LIKELY_ATTACK | DEFINITE_ATTACK
    }
    """
    normalized = normalize(raw_input)

    sig_matches, sig_score = check_signatures(normalized)
    ano_score = check_anomalies(normalized)
    ml_prob = predict(normalized)

    config = None
    if _has_flask:
        try:
            config = current_app.config
        except RuntimeError:
            pass  # outside app context — use defaults

    risk_score, decision = compute_risk(sig_score, ano_score, ml_prob, config)

    # Encode all matching signature names as a JSON array string.
    # Storing every hit (not just the best) gives the attack log full forensic
    # detail. None means no signatures matched at all.
    sig_hit_json = json.dumps([m.name for m in sig_matches]) if sig_matches else None

    return {
        "normalized":      normalized,
        "signature_hit":   sig_hit_json,
        "signature_score": sig_score,
        "anomaly_score":   ano_score,
        "ml_score":        ml_prob,
        "risk_score":      risk_score,
        "decision":        decision,
    }
