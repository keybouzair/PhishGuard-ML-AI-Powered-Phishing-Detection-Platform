import asyncio
import json
from typing import Dict, Any
from core.logger import get_logger, log_execution_time

logger = get_logger("services.llm_risk_engine")

class LLMRiskIntelligenceEngine:
    """
    Ultra Feature 3: LLM Risk Intelligence Engine
    Consumes raw multi-modal signals (ML probability, ThreatIntel APIs, Visual Impersonation score,
    Urgency NLP score) and leverages an LLM to output a human-readable, SIEM-ingestible risk summary.
    """

    def __init__(self):
        logger.info("LLMRiskIntelligenceEngine initialized")

    @log_execution_time(logger)
    async def generate_risk_intelligence(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inputs expected:
        - ml_score: float (0-100)
        - threat_intel_flags: int (count of hits on VT, URLHaus, etc.)
        - visual_impersonation: Dict (from DeepfakeLoginDetector)
        - email_urgency: float (0-100)
        """
        logger.info("Correlating risk intelligence signals")
        
        # 1. Safely parse inputs
        ml_score = inputs.get("ml_score", 0)
        threat_intel_flags = inputs.get("threat_intel_flags", 0)
        visual_info = inputs.get("visual_impersonation", {})
        visual_score = visual_info.get("visual_clone_score", 0)
        email_urgency = inputs.get("email_urgency", 0)
        
        # 2. Heuristic baseline logic before LLM smoothing
        base_risk_score = (ml_score * 0.4) + (visual_score * 0.4) + (email_urgency * 0.2)
        if threat_intel_flags > 0:
            base_risk_score = min(100.0, base_risk_score + 25.0)

        # 3. Prompting the simulated LLM
        final_judgment = await self._prompt_reasoning_llm(
            score=base_risk_score,
            ml=ml_score,
            vt=threat_intel_flags,
            vis=visual_score,
            brand=visual_info.get("suspected_brand")
        )

        result = {
            "final_risk_score": round(base_risk_score, 2),
            "risk_summary": final_judgment["summary"],
            "recommended_action": final_judgment["action"],
            "correlation_id": f"risk_{hash(str(inputs))}"
        }
        
        logger.info("Risk intelligence generated", extra={"extra_fields": {"final_score": result["final_risk_score"], "action": result["recommended_action"]}})
        return result

    async def _prompt_reasoning_llm(self, score: float, ml: float, vt: int, vis: float, brand: str) -> Dict[str, str]:
        """
        Mocks reaching out to an LLM like GPT-4 to write the human-readable summary.
        """
        await asyncio.sleep(0.3)
        
        if score >= 90:
            summary = f"Critical phishing threat detected. The visual pipeline indicates a {vis}% match for {brand or 'a known brand'} credentials. The ML heuristic reinforces this with a {ml}% confidence, and {vt} ThreatIntel engines have flagged the domain."
            action = "Block & Auto-Takedown"
        elif score >= 60:
            summary = f"Suspicious activity noted. Visual similarity to {brand or 'brands'} is moderate ({vis}%), combined with anomalous structural features."
            action = "Monitor & sandbox"
        else:
            summary = "No significant indicators of compromise. ML features and visual DOM layout align with benign patterns."
            action = "Safe"
            
        return {"summary": summary, "action": action}

# Export singleton
llm_risk_engine = LLMRiskIntelligenceEngine()
