try:
    from sentence_transformers import SentenceTransformer
    from sklearn.metrics.pairwise import cosine_similarity
    import numpy as np
    _HF_AVAILABLE = True
except ImportError:
    _HF_AVAILABLE = False
import logging

logger = logging.getLogger("asdip.hf_anomaly")

class HFAnomalyDetector:
    def __init__(self):
        self.enabled = _HF_AVAILABLE
        if self.enabled:
            logger.info("Initializing HF Anomaly Detector (all-MiniLM-L6-v2)")
            # Set to CPU by default if GPU is not available to avoid hangs
            self.model = SentenceTransformer('all-MiniLM-L6-v2', device='cpu')
        else:
            logger.warning("sentence-transformers not available.")

    def detect(self, parsed_logs):
        if not self.enabled: return []

        lines = [entry["original"] for entry in parsed_logs if entry.get("original", "").strip()]
        
        if len(lines) < 5:
            return []

        try:
            embeddings = self.model.encode(lines)

            # Compute similarity matrix
            sim_matrix = cosine_similarity(embeddings)

            anomaly_scores = []
            for i in range(len(sim_matrix)):
                # Average similarity of a line with others
                score = np.mean(sim_matrix[i])
                anomaly_scores.append(score)

            # Low similarity = anomaly
            threshold = np.percentile(anomaly_scores, 20)

            anomalies = [
                i+1 for i, score in enumerate(anomaly_scores)
                if score < threshold
            ]
            
            # detect outlier clusters
            for i, score in enumerate(anomaly_scores):
                if score < threshold * 0.8 and (i+1) not in anomalies:
                    anomalies.append(i+1)
                    
            return anomalies
        except Exception as e:
            logger.error(f"HF Anomaly Error: {e}")
            return []
