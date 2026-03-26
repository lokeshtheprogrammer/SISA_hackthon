import re
from typing import List, Dict, Tuple

class SQLDetector:
    """Detects SQL Injection and related sensitive info in raw SQL strings."""
    
    PATTERNS = {
        "sql_injection": re.compile(r"(?i)(UNION\s+SELECT|DROP\s+TABLE|OR\s+1\s*=\s*1|UPDATE\s+\w+\s+SET|DELETE\s+FROM|GRANT\s+ALL|ALTER\s+TABLE|EXEC\s+\(|SHUTDOWN|TRUNCATE\s+TABLE)"),
        "sql_credentials": re.compile(r"(?i)(password|user|passwd|pwd)\s*[=:]\s*['\"]?\w+['\"]?"),
        "sql_sensitive_leak": re.compile(r"(?i)(SELECT\s+.*\s+FROM\s+INFORMATION_SCHEMA|FROM\s+pg_catalog|FROM\s+mysql\.)"),
    }

    def detect(self, raw_sql: str) -> Tuple[List[Dict], Dict]:
        """Runs SQL-specific regex detection."""
        findings = []
        tc = {}
        lines = raw_sql.splitlines()

        for idx, l in enumerate(lines):
            line_no = idx + 1
            for ftype, pattern in self.PATTERNS.items():
                matches = pattern.findall(l)
                # findall might return tuples if there are capture groups
                for m in matches:
                    m_val = m if isinstance(m, str) else m[0]
                    # Format for V5 response: "line", "value", "type", "risk"
                    finding = {
                        "type": ftype,
                        "value": m_val,
                        "risk": "high" if ftype == "sql_injection" else "medium",
                        "line": line_no # V5 uses "line" (renamed later if needed, but here we set "line")
                    }
                    findings.append(finding)
                    tc[ftype] = tc.get(ftype, 0) + 1

        return findings, tc
