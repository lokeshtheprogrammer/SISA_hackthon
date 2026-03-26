import re
from typing import List, Dict, Tuple


class Detector:
    def __init__(self):
        self.patterns = {
            "email":       re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
            "api_key":     re.compile(r"(?:sk|pk|rk|ak)-[A-Za-z0-9\-]{16,}|(?:api[_-]?key|apikey)\s*[=:\"'`]\s*\S{16,}", re.IGNORECASE),
            "password":    re.compile(r"(?i)(password|passwd|pwd|pass)\s*[=:\"'`]\s*\S+"),
            "token":       re.compile(r"(?i)(token|auth|bearer|jwt|access_token|refresh_token)\s*[=:\"'`]\s*[A-Za-z0-9._\-]{8,}"),
            "phone":       re.compile(r"\b\d{10}\b|\+?(?:\d[\s\-.]?){9,14}\d\b"),
            "stack_trace": re.compile(r"(Traceback \(most recent call last\)|Error:|Exception:|at \w+\.\w+\([\w.]+:\d+\)|NullPointerException|StackOverflowError)"),
            "ssn":         re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            "credit_card": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
            "secret_key":  re.compile(r"(?i)(secret|private_key|client_secret|app_secret|signing_key)\s*[=:\"'`]\s*\S+"),
            "ip_address":  re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
            "url_leak":    re.compile(r"https?://[^\s\"'<>]+"),
            "debug_mode":  re.compile(r"(?i)(debug\s*[=:]\s*(?:true|1|on|yes)|debug\s*mode\s*(?:on|enabled)|verbose\s*[=:]\s*true|dev(?:elopment)?\s*mode|logging\.DEBUG|level\s*=\s*DEBUG)"),
            "private_ip":  re.compile(r"\b(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b"),
            "aws_key":     re.compile(r"(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}"),
            "github_token":re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
            "connection_string": re.compile(r"(?i)(mongodb|mysql|postgres|postgresql|redis|amqp|jdbc)://[^\s\"'<>]+"),
        }

        self.finding_risk = {
            "password":    "critical", "secret_key":  "critical",
            "credit_card": "critical", "ssn":         "critical",
            "aws_key":     "critical", "connection_string": "critical",
            "api_key":     "high",     "token":       "high",
            "github_token":"high",     "debug_mode":  "high",
            "stack_trace": "medium",   "url_leak":    "medium",
            "private_ip":  "medium",
            "email":       "low",      "phone":       "low",
            "ip_address":  "low",
        }

    def detect(self, parsed_logs: List[Dict]) -> Tuple[List[Dict], Dict]:
        findings = []
        type_counts = {}
        seen = set()

        for entry in parsed_logs:
            line = entry["original"]
            template = entry["template"]

            for ftype, pattern in self.patterns.items():
                targets = set()
                combined = line + " " + template
                for m in pattern.finditer(combined):
                    targets.add(m.group(0) if isinstance(m.group(0), str) else m.group(0)[0])

                for match_str in targets:
                    finding_key = f"{entry.get('line_number')}-{ftype}-{match_str}"
                    if finding_key in seen: continue
                    seen.add(finding_key)
                    findings.append({
                        "line":         entry.get("line_number"),
                        "line_number":  entry.get("line_number"),
                        "line_content": line.strip(),
                        "template":     template,
                        "cluster_id":   entry.get("cluster_id"),
                        "type":         ftype,
                        "value":        match_str,
                        "match":        match_str,
                        "risk":         self.finding_risk.get(ftype, "low"),
                    })
                    type_counts[ftype] = type_counts.get(ftype, 0) + 1

        return findings, type_counts
