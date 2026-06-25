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
        Queries Gemini API to write a human-readable security risk summary and recommend response actions.
        Falls back to mock heuristics if GEMINI_API_KEY is not configured.
        """
        gemini_key = os.environ.get("GEMINI_API_KEY")
        if gemini_key:
            import os
            import requests
            try:
                api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
                
                prompt = (
                    f"Correlate the following multi-modal signals for a scanned URL:\n"
                    f"- Aggregate Risk Score: {score}\n"
                    f"- Machine Learning Phishing Confidence: {ml}%\n"
                    f"- ThreatIntel Engines Detections count: {vt}\n"
                    f"- Visual Impersonation Brand Match: {brand} with {vis}% similarity\n\n"
                    f"Write a concise, high-fidelity security summary/explanation of this threat level suitable for a SOC/SIEM platform, and recommend the best response action.\n"
                    f"Output JSON ONLY in the following format:\n"
                    f'{{"summary": "security summary detail", "action": "recommended action (e.g. Block & Auto-Takedown, Monitor & sandbox, Safe)"}}'
                )
                
                payload = {
                    "contents": [
                        {
                            "parts": [
                                {"text": prompt}
                            ]
                        }
                    ],
                    "generationConfig": {
                        "responseMimeType": "application/json"
                    }
                }
                
                headers = {"Content-Type": "application/json"}
                response = requests.post(api_url, json=payload, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    resp_data = response.json()
                    try:
                        text_response = resp_data["contents"][0]["parts"][0]["text"].strip()
                        if "```json" in text_response:
                            text_response = text_response.split("```json")[1].split("```")[0].strip()
                        elif "```" in text_response:
                            text_response = text_response.split("```")[1].strip()
                        
                        data = json.loads(text_response)
                        return {
                            "summary": data.get("summary"),
                            "action": data.get("action", "Monitor")
                        }
                    except Exception as parse_err:
                        logger.error(f"Failed to parse Gemini content response: {parse_err}. Raw: {text_response}")
                else:
                    logger.error(f"Gemini Content API returned status {response.status_code}: {response.text}")
            except Exception as api_err:
                logger.error(f"Error calling Gemini Content API: {api_err}", exc_info=True)

        # Fallback Mock reasoning
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
