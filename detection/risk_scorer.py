"""
Risk scorer.

Combines the three detection signals into a single integer 0-100 and
maps it to a human-readable decision label.

Weights are read from the Flask app config so they can be tuned without
changing this file.  Outside an app context (unit tests) default weights
are used.
"""

_DEFAULT_WEIGHTS = {
    "signature": 0.40,
    "anomaly":   0.25,
    "ml":        0.35,
}

DECISION_SAFE     = "SAFE"
DECISION_SUSP     = "SUSPICIOUS"
DECISION_LIKELY   = "LIKELY_ATTACK"
DECISION_DEFINITE = "DEFINITE_ATTACK"


def compute_risk(signature_score: int, anomaly_score: int, ml_probability: float,
                 config=None) -> tuple[int, str]:
    """
    Compute the weighted risk score and return (score: int, decision: str).

    Parameters
    ----------
    signature_score  : 0-100 from signatures.check_signatures()
    anomaly_score    : 0-100 from anomaly.check_anomalies()
    ml_probability   : 0.0-1.0 from classifier.predict()
    config           : Flask app.config dict (optional; uses defaults if None)
    """
    if config:
        w_sig = config.get("WEIGHT_SIGNATURE", _DEFAULT_WEIGHTS["signature"])
        w_ano = config.get("WEIGHT_ANOMALY",   _DEFAULT_WEIGHTS["anomaly"])
        w_ml  = config.get("WEIGHT_ML",        _DEFAULT_WEIGHTS["ml"])
        t_susp    = config.get("RISK_SUSPICIOUS", 30)
        t_block   = config.get("RISK_BLOCK",      60)
        t_definite = config.get("RISK_DEFINITE",  80)
    else:
        w_sig, w_ano, w_ml = (_DEFAULT_WEIGHTS[k] for k in ("signature", "anomaly", "ml"))
        t_susp, t_block, t_definite = 30, 60, 80

    raw = (w_sig * signature_score) + (w_ano * anomaly_score) + (w_ml * ml_probability * 100)
    score = min(100, max(0, round(raw)))

    if score >= t_definite:
        decision = DECISION_DEFINITE
    elif score >= t_block:
        decision = DECISION_LIKELY
    elif score >= t_susp:
        decision = DECISION_SUSP
    else:
        decision = DECISION_SAFE

    return score, decision
