import re
from collections import defaultdict
from typing import List, Dict


class CorrelationEngine:
    def __init__(self):
        self.brute_force_re = re.compile(
            r"(?i)(failed login|login attempt|authentication failed|invalid password|"
            r"unauthorized|access denied|invalid credentials|login failed|"
            r"wrong password|bad credentials|401|forbidden|403)"
        )
        self.ip_re = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        )

    def detect_bruteforce(self, parsed_logs: list) -> bool:
        hits = [i for i, entry in enumerate(parsed_logs)
                if self.brute_force_re.search(entry["original"])]
        return any(
            len([h for h in hits if hits[i] <= h <= hits[i] + 20]) >= 3
            for i in range(len(hits))
        )

    def detect_log_spike(self, parsed_logs: list) -> bool:
        ts_re = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2})")
        buckets: Dict[str, int] = {}
        for entry in parsed_logs:
            m = ts_re.search(entry["original"])
            if m:
                bucket = m.group(1)[:16]
                buckets[bucket] = buckets.get(bucket, 0) + 1
        if len(buckets) < 2:
            return False
        vals = list(buckets.values())
        avg = sum(vals) / len(vals)
        return any(v > avg * 5 and v > 20 for v in vals)

    def detect_suspicious_ips(self, parsed_logs: list) -> Dict[str, int]:
        """Returns dict of IP -> request count for IPs with suspicious frequency."""
        ip_counts: Dict[str, int] = defaultdict(int)
        for entry in parsed_logs:
            for ip in self.ip_re.findall(entry["original"]):
                # Skip private IPs from IP frequency analysis
                if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")):
                    ip_counts[ip] += 1
        # Return IPs appearing more than 5 times (suspicious)
        return {ip: cnt for ip, cnt in ip_counts.items() if cnt > 5}

    def detect_error_storm(self, parsed_logs: list) -> bool:
        """Detect if error rate exceeds 50% of total log lines."""
        error_re = re.compile(r"(?i)\b(error|exception|fatal|critical|fail)\b")
        errors = sum(1 for e in parsed_logs if error_re.search(e["original"]))
        total = len(parsed_logs)
        return total > 10 and (errors / total) > 0.5
