from __future__ import annotations

from pathlib import Path

import joblib

from detector.src.features import FEATURE_NAMES
from detector.src.features import extract_features
from detector.src.models import DetectorEvent


Alert = dict[str, object]


class IForestScorer:
    def __init__(self, model_path: Path, threshold: float):
        self.model = joblib.load(model_path)
        self.threshold = threshold

    def score_response_details(self, response_event: DetectorEvent, query_event: DetectorEvent):
        response_dict = {
            "query_name": response_event.query_name,
            "answers": response_event.answers,
            "authority": response_event.authority,
            "additional": response_event.additional,
            "timestamp": response_event.timestamp,
        }
        query_dict = {"timestamp": query_event.timestamp}
        feature_vector = extract_features(response_dict, query_dict)
        raw_score = float(self.model.score_samples(feature_vector.reshape(1, -1))[0])
        decision_score = float(self.model.decision_function(feature_vector.reshape(1, -1))[0])
        return {
            "domain": response_event.query_name,
            "transaction_id": response_event.transaction_id,
            "decision_score": decision_score,
            "raw_score": raw_score,
            "threshold": self.threshold,
            "feature_vector": feature_vector.tolist(),
            "feature_names": FEATURE_NAMES,
            "timestamp": response_event.timestamp.isoformat(),
        }

    def score_response(self, response_event: DetectorEvent, query_event: DetectorEvent):
        details = self.score_response_details(response_event, query_event)
        decision_score = float(details["decision_score"])

        if decision_score >= self.threshold:
            return None

        return {
            "alert_type": "iforest_anomaly",
            "severity": "HIGH",
            "domain": details["domain"],
            "transaction_id": details["transaction_id"],
            "response_index": None,
            "anomaly_score": round(-decision_score, 4),
            "decision_score": round(decision_score, 4),
            "raw_score": round(float(details["raw_score"]), 4),
            "threshold": details["threshold"],
            "feature_vector": details["feature_vector"],
            "feature_names": details["feature_names"],
            "timestamp": details["timestamp"],
        }
