"""Transparent batch quality screening, not proof of model-performance drift."""
import json
from .data import FEATURES, SensorValidator

def quality_report(frame, reference):
    SensorValidator().validate(frame)
    result={}
    for c in FEATURES[1:]:
        ref=reference[c]; delta=abs(float(frame[c].mean())-ref['mean'])/max(ref['std'],1e-12)
        result[c]={'missing_fraction':float(frame[c].isna().mean()),'standardized_mean_shift':delta,
                   'review_required':bool(delta>1 or frame[c].isna().mean()>.05)}
    return {'checks':result,'warning':'Heuristic review thresholds, not a statistical guarantee or automatic retraining command'}
