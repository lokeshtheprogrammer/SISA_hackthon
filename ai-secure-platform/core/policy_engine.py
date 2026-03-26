from typing import Optional, Dict

class PolicyEngine:
    def __init__(self):
        self.policies = {
            "low": {"action": "allowed"},
            "medium": {"action": "allowed"},
            "high": {"action": "masked"},
            "critical": {"action": "blocked"}
        }

    def get_action(self, risk_level: str) -> str:
        """Returns the default action for a risk level (allowed / masked / blocked)."""
        policy = self.policies.get(risk_level.lower(), self.policies["low"])
        return policy["action"]

    def evaluate(self, risk_level: str, options: dict) -> dict:
        """
        Logic:
        - If block_high_risk=True AND risk in ["high","critical"] → blocked
        - Else if mask=True → masked
        - Else → default policy mapping
        """
        risk_level = risk_level.lower()
        
        block_high = options.get("block_high_risk", False)
        mask_opt   = options.get("mask", False)

        if block_high and risk_level in ["high", "critical"]:
            action = "blocked"
        elif mask_opt:
            action = "masked"
        else:
            action = self.get_action(risk_level)

        return {"action": action, "risk_level": risk_level}

    def apply_policy(self, result: dict, options: dict) -> dict:
        """
        Adds "action" (TOP LEVEL) to results.
        Do NOT remove existing fields.
        Returns updated result.
        """
        risk_level = result.get("risk_level", "low")
        evaluation = self.evaluate(risk_level, options)
        
        # Add action top-level
        result["action"] = evaluation["action"]
        # Keep policy object for backward compatibility/rich UI
        result["policy"] = self.policies.get(risk_level.lower(), self.policies["low"])
        
        return result
