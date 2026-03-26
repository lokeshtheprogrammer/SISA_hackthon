import os
import json
import logging
import asyncio
from typing import Dict, Any
import openai

logger = logging.getLogger("asdip.llm")


class LLMEngine:
    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY", "")
        if self.api_key and not self.api_key.startswith("sk-REPLACE"):
            openai.api_key = self.api_key
        else:
            self.api_key = ""  # treat placeholder as missing
        self.model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
        self.fallback_model = os.environ.get("LLM_FALLBACK_MODEL", "gpt-3.5-turbo")
        self.total_tokens_used = 0

    async def get_insights(self, data: Dict[str, Any], use_fallback: bool = False) -> Dict[str, Any]:
        if not self.api_key:
            logger.warning("OPENAI_API_KEY not configured. Using rule-based fallback.")
            return {}

        model_to_use = self.fallback_model if use_fallback else self.model
        prompt = self._build_prompt(data)
        
        try:
            # Timeout after 15 seconds
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    openai.chat.completions.create,
                    model=model_to_use,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are a Principal Security AI Engineer. Analyze security scan data "
                                "and return a concise JSON response. Be specific and actionable."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.2,
                    max_tokens=1000,
                ),
                timeout=15.0
            )
            
            usage = getattr(response, 'usage', None)
            if usage:
                self.total_tokens_used += usage.total_tokens
                logger.info(f"LLM Tokens Used: {usage.total_tokens} (Total: {self.total_tokens_used})")

            content = response.choices[0].message.content
            result = json.loads(content)
            return {
                "summary":               result.get("summary", ""),
                "insights":              result.get("risks", []),
                "remediation":           result.get("fixes", []),
                "anomalies":             data.get("anomalies", []),
                "severity_justification": f"Risk Score: {data.get('score', 0)} — {data.get('level', 'unknown').upper()}",
                "content_type":          data.get("input_type", "text"),
                "model_used":            model_to_use,
            }
        except asyncio.TimeoutError:
            logger.error(f"LLM API timeout for model {model_to_use}")
            if not use_fallback:
                return await self.get_insights(data, use_fallback=True)
            return {}
        except Exception as e:
            logger.error(f"LLM API call failed ({model_to_use}): {e}")
            if not use_fallback:
                return await self.get_insights(data, use_fallback=True)
            return {}

    def _build_prompt(self, data: Dict[str, Any]) -> str:
        findings_summary = json.dumps(
            [{"type": f["type"], "risk": f["risk"], "line": f.get("line")} for f in data.get("findings", [])[:30]],
            indent=2,
        )
        return f"""Analyze this security scan and provide actionable insights.

RISK SCORE: {data.get('score', 0)} | LEVEL: {data.get('level', 'unknown').upper()}
BRUTE FORCE: {data.get('brute_force', False)} | LOG SPIKE: {data.get('log_spike', False)}
ML ANOMALIES: {len(data.get('anomalies', []))} flagged lines
TYPE COUNTS: {json.dumps(data.get('type_counts', {}), indent=2)}
FINDINGS (sample): {findings_summary}
LOG SAMPLE (first 1500 chars):
{data.get('raw_text', '')[:1500]}

Return EXACTLY this JSON (no extra keys):
{{
  "summary": "2-3 sentence executive summary of the security posture.",
  "risks": ["Specific risk 1 with impact", "Specific risk 2 with impact"],
  "fixes": ["Actionable fix 1 with tool/command", "Actionable fix 2"]
}}"""
