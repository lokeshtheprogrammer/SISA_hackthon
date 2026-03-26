from typing import List, Dict, Tuple


class RiskEngine:
    def __init__(self):
        self.weights = {
            "password":          6,  "secret_key":      6,
            "credit_card":       6,  "ssn":             6,
            "aws_key":           8,  "connection_string": 7,
            "api_key":           5,  "token":           5,
            "github_token":      5,  "debug_mode":      3,
            "stack_trace":       3,  "url_leak":        2,
            "phone":             2,  "private_ip":      2,
            "email":             1,  "ip_address":      1,
            "sql_injection":    10,  "sql_credentials": 6,
            "sql_sensitive_leak": 8,
        }

    def calculate(self, findings: List[Dict], is_brute_force: bool,
                  suspicious_ips: Dict = None, error_storm: bool = False,
                  anomaly_lines: List[int] = None) -> Tuple[int, str]:
        if anomaly_lines is None: anomaly_lines = []
        score = 0
        for f in findings:
            score += self.weights.get(f.get("type", ""), 1)

        # Extra signals
        if is_brute_force:
            score += 10
        if suspicious_ips:
            score += min(len(suspicious_ips) * 2, 8)
        if error_storm:
            score += 4
            
        if len(anomaly_lines) > 5:
            score += 5
            
        types = [f.get("type") for f in findings]

        # Combo attack detection
        if "password" in types and "api_key" in types:
            score += 10

        if "token" in types and "api_key" in types:
            score += 8

        if score >= 20:
            level = "critical"
        elif score >= 10:
            level = "high"
        elif score >= 4:
            level = "medium"
        else:
            level = "low"

        return score, level
