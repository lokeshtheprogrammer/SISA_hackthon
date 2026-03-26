import numpy as np
import logging
import re
from typing import List, Dict, Tuple, Any

try:
    from sklearn.ensemble import IsolationForest
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False

logger = logging.getLogger("asdip.ml")

class AnomalyDetector:
    def __init__(self):
        self.enabled = _SKLEARN_AVAILABLE
        self.is_trained = False
        if self.enabled:
            # contamination=0.1 means 10% expected anomalies
            self.model = IsolationForest(contamination=0.1, random_state=42)
        else:
            logger.warning("sklearn unavailable — Disabling ML anomaly detection.")

    def _extract_features(self, parsed_logs: List[Dict]) -> np.ndarray:
        features = []
        for entry in parsed_logs:
            line = entry.get("original", "")
            up   = line.upper()
            
            # Feature extraction
            length_feat = float(len(line))
            digit_count = float(sum(c.isdigit() for c in line))
            error_flag  = 1.0 if ("ERROR" in up or "EXCEPTION" in up) else 0.0
            warn_flag   = 1.0 if ("WARN" in up) else 0.0
            sensitive_kw = 1.0 if any(k in up for k in ["PASSWORD", "TOKEN", "KEY", "SECRET"]) else 0.0
            
            tokens = line.split()
            unique_ratio = (len(set(tokens)) / len(tokens)) if tokens else 0.0
            
            # Time feature
            pattern = re.compile(r"(\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\d{2}:\d{2}:\d{2})")
            time_feat = 1.0 if pattern.search(line) else 0.0
            
            features.append([
                length_feat, digit_count, error_flag, 
                warn_flag, sensitive_kw, unique_ratio, time_feat
            ])
        return np.array(features)

    def detect_anomalies(self, parsed_logs: List[Dict]) -> List[int]:
        """Returns list of 1-indexed anomalous line numbers."""
        if not self.enabled or len(parsed_logs) < 5:
            return []

        X = self._extract_features(parsed_logs)
        
        try:
            if not self.is_trained and len(X) > 50:
                self.model.fit(X)
                self.is_trained = True
            
            if self.is_trained:
                preds = self.model.predict(X)
                # Find indices of -1 (anomalies)
                anomaly_indices = [i + 1 for i, p in enumerate(preds) if p == -1]
                return anomaly_indices
            else:
                return []
        except Exception as e:
            logger.error(f"Anomaly detection fitting error: {e}")
            return []

    def predict(self, parsed_logs: List[Dict]) -> Dict[str, Any]:
        """
        Predicts if the overall batch is anomalous.
        Returns: { "anomaly": bool, "score": float }
        """
        if not self.enabled or not parsed_logs:
            return {"anomaly": False, "score": 0.0}
        
        X = self._extract_features(parsed_logs)
        try:
            if not self.is_trained and len(X) > 50:
                self.model.fit(X)
                self.is_trained = True
            
            if not self.is_trained:
                return {"anomaly": False, "score": 0.0}
            
            # decision_function returns the anomaly score (lower is more anomalous)
            # We normalize it so higher is more anomalous
            scores = self.model.decision_function(X)
            avg_score = float(np.mean(scores))
            
            # scores are usually centered around 0. Negative = anomaly.
            # We'll transform it to a 0-1 range where 1 is highly anomalous.
            # Simple heuristic: 1.0 - (avg_score + 0.5) scaled
            normalized_score = max(0.0, min(1.0, 0.5 - avg_score))
            
            is_anomaly = avg_score < 0
            
            return {
                "anomaly": bool(is_anomaly),
                "score": round(normalized_score, 4)
            }
        except Exception as e:
            logger.error(f"Anomaly prediction error: {e}")
            return {"anomaly": False, "score": 0.0}
