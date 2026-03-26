import re


class Masker:
    def mask_data(self, text: str) -> str:
        # Passwords
        text = re.sub(r"(?i)((?:password|passwd|pwd|pass)\s*[=:\"'`]\s*)(\S+)", r"\1[REDACTED]", text)
        # API Keys (OpenAI style)
        text = re.sub(r"(sk-[A-Za-z0-9\-]{4})[A-Za-z0-9\-]+", r"\1****", text)
        # AWS Keys
        text = re.sub(r"((?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{4})[A-Z0-9]{12}", r"\1****", text)
        # GitHub tokens
        text = re.sub(r"(gh[pousr]_[A-Za-z0-9_]{4})[A-Za-z0-9_]{32,}", r"\1****", text)
        # Generic api_key= patterns
        text = re.sub(r"(?i)(api[_-]?key\s*[=:\"'`]\s*.{4}).{12,}", r"\1****", text)
        # Emails
        text = re.sub(r"([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", r"****@\2", text)
        # Credit cards
        text = re.sub(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", r"****-****-****-****", text)
        # SSN
        text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", r"***-**-****", text)
        # Tokens
        text = re.sub(r"(?i)((?:token|auth|bearer|jwt|access_token)\s*[=:\"'`]\s*.{4}).{8,}", r"\1****", text)
        # Phone numbers (aggressive)
        text = re.sub(r"\+?(?:\d[\s\-.]?){9,14}\d", r"***-***-****", text)
        # Connection strings (mask credentials portion)
        text = re.sub(r"((?:mongodb|mysql|postgres|redis|jdbc)://)([^:@/]+):([^@/]+)@", r"\1****:****@", text)
        # Secret keys
        text = re.sub(r"(?i)((?:secret|private_key|client_secret|signing_key)\s*[=:\"'`]\s*)(\S+)", r"\1[REDACTED]", text)
        return text
