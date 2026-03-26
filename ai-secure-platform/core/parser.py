import logging
from typing import List, Dict

try:
    from drain3 import TemplateMiner
    from drain3.template_miner_config import TemplateMinerConfig
    _DRAIN3_AVAILABLE = True
except ImportError:
    _DRAIN3_AVAILABLE = False

logger = logging.getLogger("asdip.parser")

class LogParser:
    def __init__(self):
        self.miner = None
        self.drain3_available = _DRAIN3_AVAILABLE
        if self.drain3_available:
            config = TemplateMinerConfig()
            config.parametrize_numeric_tokens = True
            self.miner = TemplateMiner(config=config)
            logger.info("✅ Drain3 template miner loaded")
        else:
            logger.warning("⚠️ drain3 not installed — falling back to raw strings")

    def parse_logs(self, logs: str) -> List[Dict]:
        lines = logs.splitlines()
        parsed = []
        for i, line in enumerate(lines, 1):
            if not line.strip():
                parsed.append({
                    "line_number": i,
                    "original": line,
                    "template": line,
                    "cluster_id": -1,
                    "change_type": "none"
                })
                continue
                
            if self.miner:
                try:
                    result = self.miner.add_log_message(line)
                    parsed.append({
                        "line_number": i,
                        "original": line,
                        "template": result["template_mined"],
                        "cluster_id": result["cluster_id"],
                        "change_type": result.get("change_type", "none")
                    })
                except Exception:
                    parsed.append({
                        "line_number": i,
                        "original": line,
                        "template": line,
                        "cluster_id": -1,
                        "change_type": "none"
                    })
            else:
                parsed.append({
                    "line_number": i,
                    "original": line,
                    "template": line,
                    "cluster_id": -1,
                    "change_type": "none"
                })
        return parsed

    def get_clusters(self) -> List[Dict]:
        if not self.miner:
            return []
        clusters = []
        for cluster in self.miner.drain.clusters:
            clusters.append({
                "cluster_id": cluster.cluster_id,
                "template": cluster.get_template(),
                "size": cluster.size,
            })
        return sorted(clusters, key=lambda c: c["size"], reverse=True)
