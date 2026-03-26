from core.llm_engine import LLMEngine
import logging

logger = logging.getLogger("asdip.ai")

class AIInsightEngine:
    def __init__(self):
        self.llm = LLMEngine()

    async def generate_insight(self, raw_text: str, findings: list, type_counts: dict, score: int, level: str, anomalies: list, brute_force: bool, log_spike: bool, clusters: list) -> dict:
        data = {
            "raw_text": raw_text,
            "findings": findings,
            "type_counts": type_counts,
            "score": score,
            "level": level,
            "anomalies": anomalies,
            "brute_force": brute_force,
            "log_spike": log_spike,
            "clusters": clusters
        }
        
        # Skip AI for low risk
        if score < 8:
            return self._fallback(findings, type_counts, score, level, anomalies, brute_force, log_spike)
            
        # Call LLM
        ai_res = await self.llm.get_insights(data)
        
        # If LLM fails or returns empty, use fallback
        if not ai_res or not ai_res.get("summary"):
            return self._fallback(findings, type_counts, score, level, anomalies, brute_force, log_spike)

        return ai_res

    def _fallback(self, findings, type_counts, score, level, anomalies, brute_force, log_spike) -> dict:
        insights_list, remediation = [], []
        
        tc = type_counts
        if "password" in tc and "api_key" in tc:
            insights_list.append("Possible data breach: credentials + API keys exposed together")
            remediation.append("Immediately rotate all credentials and audit access logs")
            
        if "api_key"     in tc: insights_list.append(f"API key(s) exposed — {tc['api_key']} occurrence(s). Rotate immediately."); remediation.append("Rotate all exposed API keys in your secrets manager")
        if "password"    in tc: insights_list.append(f"Plaintext password(s) found — {tc['password']} occurrence(s)."); remediation.append("Use a secrets manager (Vault/AWS SSM); never log credentials")
        if "token"       in tc: insights_list.append(f"Auth token(s) present — {tc['token']} occurrence(s)."); remediation.append("Revoke and rotate all exposed auth tokens immediately")
        if "secret_key"  in tc: insights_list.append(f"Secret key(s) found — {tc['secret_key']} occurrence(s). Critical exposure."); remediation.append("Audit all secret_key usage and rotate")
        if "stack_trace" in tc: insights_list.append(f"Stack traces detected — {tc['stack_trace']} error(s) leaking internals."); remediation.append("Disable verbose stack traces in production; use error IDs")
        if "credit_card" in tc: anomalies.append("Credit card numbers found — PCI-DSS violation"); remediation.append("Tokenize payment data; never log raw card numbers")
        if "ssn"         in tc: anomalies.append("SSNs found — HIPAA/PII violation"); remediation.append("Mask/redact SSNs at the application layer before logging")
        if "debug_mode"  in tc: anomalies.append("Debug mode enabled in logs — information disclosure risk"); remediation.append("Disable debug mode in all production configurations")
        if "private_ip"  in tc: insights_list.append(f"Internal IP addresses exposed — {tc['private_ip']} occurrence(s). Network topology leak."); remediation.append("Redact internal IPs from logs shipped externally")
        if "url_leak"    in tc: insights_list.append(f"URLs with potential sensitive params logged — {tc['url_leak']} occurrence(s)."); remediation.append("Strip query params and credentials from logged URLs")
        if brute_force: anomalies.append("Brute-force login pattern detected"); remediation.append("Enable account lockout + rate limiting + CAPTCHA")
        if log_spike: anomalies.append("Log volume spike detected — possible DoS or application error storm"); remediation.append("Set up log rate alerts and circuit-breaker patterns")
        if "email"       in tc: insights_list.append(f"Email addresses logged — {tc['email']} address(es). Review GDPR compliance.")
        
        if anomalies and isinstance(anomalies[0], int):
            anomalies.append(f"Isolation Forest ML flagged {len(anomalies)} anomalous log lines.")
            remediation.append("Review ML flagged lines for unusual patterns.")

        if not insights_list and not anomalies: insights_list.append("No high-severity patterns detected. Maintain standard security hygiene.")
        
        return {
            "summary": f"Fallback rule-based scan: {len(findings)} findings detected. Risk Level: {level.upper()}.",
            "insights": insights_list or ["No significant cleartext sensitive data exposed."],
            "anomalies": anomalies,
            "remediation": remediation or ["Implement standard security logging hygiene."],
            "content_type": "Application log",
            "severity_justification": f"Risk score is {score}"
        }
