import asyncio
import json
from datetime import datetime
from typing import Dict, Any, List
from core.logger import get_logger
from core.config import settings

logger = get_logger("agents.threat_hunter")


class AutonomousThreatHunter:
    """
    Ultra Feature 1: Autonomous Threat Hunting Agent
    Operates on a continuous async loop to monitor cross-platform signals.
    Employs an OBSERVE -> ANALYZE -> DECIDE -> ACT methodology.
    """

    def __init__(self):
        self.is_running = False
        self.event_queue = asyncio.Queue()
        logger.info("AutonomousThreatHunter initialized")

    async def start_hunting_loop(self):
        """Start the continuous background monitoring loop."""
        self.is_running = True
        logger.info("Threat Hunting Loop Started")
        
        while self.is_running:
            try:
                # Wait for new suspicious events to enter the queue
                event = await self.event_queue.get()
                
                logger.info("Observing new threat event", extra={"extra_fields": {"event_id": event.get("id")}})
                
                # Run the reasoning pipeline
                reasoning_log = await self._reasoning_loop(event)
                
                self.event_queue.task_done()
                
            except Exception as e:
                logger.error("Error in hunting loop", exc_info=True)
                await asyncio.sleep(5)  # Backoff on failure

    def stop_hunting_loop(self):
        self.is_running = False
        logger.info("Threat Hunting Loop Stopped")

    async def ingest_signal(self, source: str, data: Dict[str, Any]):
        """Ingest signals from URL scanners, email parsers, or brand monitors."""
        event = {
            "id": f"evt_{datetime.utcnow().timestamp()}",
            "timestamp": datetime.utcnow().isoformat(),
            "source": source,
            "data": data
        }
        await self.event_queue.put(event)
        logger.info(f"Ingested signal from {source}", extra={"extra_fields": {"signal_source": source}})

    async def _reasoning_loop(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        OBSERVE -> ANALYZE -> DECIDE -> ACT
        """
        # 1. OBSERVE
        observation = self._observe(event)
        
        # 2. ANALYZE (Mocks LLM integration for reasoning)
        analysis = await self._analyze(observation)
        
        # 3. DECIDE
        decision = self._decide(analysis)
        
        # 4. ACT
        action_result = await self._act(decision, event)
        
        # Document reasoning
        reasoning_log = {
            "event_id": event["id"],
            "observation": observation,
            "analysis": analysis,
            "decision": decision,
            "action": action_result,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        logger.info("Reasoning loop complete", extra={"extra_fields": {"reasoning_log": reasoning_log}})
        return reasoning_log

    def _observe(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key artifacts from the event."""
        data = event.get("data", {})
        return {
            "url": data.get("url"),
            "base_score": data.get("risk_score", 0),
            "indicators": data.get("indicators", [])
        }

    async def _analyze(self, observation: Dict[str, Any]) -> str:
        """
        Simulate LLM context correlation.
        In production, this queries the OpenAI/Anthropic API with the observation data.
        """
        score = observation.get("base_score", 0)
        url = observation.get("url", "unknown")
        
        if score > settings.CRITICAL_RISK_THRESHOLD:
            return f"CRITICAL: {url} shows severe phishing indicators. High probability of credential harvesting."
        elif "login" in str(url).lower() and score > 50:
            return f"WARNING: {url} contains authentication keywords with an elevated risk score. Suspicious."
        return f"INFO: {url} appears normative but requires standard monitoring."

    def _decide(self, analysis: str) -> str:
        """Determine what action to take based on the analysis."""
        if "CRITICAL" in analysis:
            return "ESCALATE_AND_TICKET"
        elif "WARNING" in analysis:
            return "DEEPER_SANDBOX_SCAN"
        return "LOG_ONLY"

    async def _act(self, decision: str, event: Dict[str, Any]) -> Dict[str, str]:
        """Execute the chosen action."""
        url = event.get("data", {}).get("url", "unknown")
        result = {"status": "executed", "action": decision, "target": url}
        
        if decision == "ESCALATE_AND_TICKET":
            # Here we would normally plug into Jira/ServiceNow/PagerDuty APIs
            logger.warning(f"Creating highly critical investigation ticket for: {url}")
            result["ticket_id"] = f"INC-{int(datetime.utcnow().timestamp())}"
            
        elif decision == "DEEPER_SANDBOX_SCAN":
            # Throw it into a headless browser sandbox queue
            logger.info(f"Triggering deep sandbox scan for: {url}")
            
        elif decision == "LOG_ONLY":
            logger.info(f"No active response required for: {url}")
            
        return result

# Singleton instance
threat_hunter = AutonomousThreatHunter()
