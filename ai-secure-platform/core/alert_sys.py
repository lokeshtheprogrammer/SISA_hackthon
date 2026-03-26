import os, httpx, asyncio, logging

logger = logging.getLogger("asdip.alerts")

class AlertSystem:
    def __init__(self):
        self.webhook_url = os.environ.get("ALERT_WEBHOOK_URL", "")
        self.email_recipient = os.environ.get("ALERT_EMAIL", "")

    def generate_alert(self, level: str) -> str:
        if level == "critical":
            return "💥 CRITICAL RISK ALERT - IMMEDIATE ACTION REQUIRED"
        elif level == "high":
            return "🚨 HIGH RISK ALERT"
        elif level == "medium":
            return "⚠️ Medium Risk"
        return "✅ Safe"

    async def trigger_alerts(self, level: str, scan_id: str, findings_count: int):
        """Asynchronously trigger external alerts (Webhook/Slack/Email)."""
        if level not in ["high", "critical"]:
            return

        alert_msg = self.generate_alert(level)
        payload = {
            "alert": alert_msg,
            "scan_id": scan_id,
            "findings": findings_count,
            "level": level,
            "timestamp": os.environ.get("CURRENT_TIME", "")
        }

        if self.webhook_url:
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(self.webhook_url, json=payload, timeout=5.0)
                    logger.info(f"Alert webhook sent for {scan_id}")
            except Exception as e:
                logger.error(f"Failed to send alert webhook: {e}")
        
        if self.email_recipient:
            # Stub for email notification (e.g. via SendGrid/SES)
            logger.info(f"Email alert queued for {self.email_recipient}")
