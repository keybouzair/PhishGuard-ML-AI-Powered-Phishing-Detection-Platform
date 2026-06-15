import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any
from core.logger import get_logger
from core.config import settings

logger = get_logger("agents.response_orchestrator")


class AutonomousResponseOrchestrator:
    """
    Ultra Feature 5: Autonomous Response Orchestrator
    Listens to a risk intelligence queue. If risk_score > CRITICAL_RISK_THRESHOLD (90),
    it autonomously drafts registrar abuse emails, pushes firewall rules, and updates DNS sinkholes.
    """

    def __init__(self):
        self.is_running = False
        self.action_queue = asyncio.Queue()
        logger.info("AutonomousResponseOrchestrator initialized")

    async def start_orchestrator(self):
        """Start the background worker queue for automated response actions."""
        if not settings.ENABLE_ACTIVE_DEFENSE:
            logger.warning("Active Defense is disabled. Orchestrator will not start.")
            return

        self.is_running = True
        logger.info("Autonomous Response Orchestrator Started")
        
        while self.is_running:
            try:
                incident = await self.action_queue.get()
                logger.warning(f"Processing critical incident: {incident['id']}", extra={"extra_fields": {"incident": incident}})
                
                await self._execute_playbook(incident)
                
                self.action_queue.task_done()
            except Exception as e:
                logger.error("Error in response orchestrator loop", exc_info=True)
                await asyncio.sleep(5)

    def stop_orchestrator(self):
        self.is_running = False
        logger.info("Autonomous Response Orchestrator Stopped")

    async def submit_incident(self, risk_intelligence: Dict[str, Any], url: str):
        """Submit a highly-scored event to the orchestration queue."""
        score = risk_intelligence.get("final_risk_score", 0)
        
        if score >= settings.CRITICAL_RISK_THRESHOLD:
            incident = {
                "id": f"INC-{uuid.uuid4().hex[:8]}",
                "url": url,
                "score": score,
                "summary": risk_intelligence.get("risk_summary", "Critical threat detected"),
                "timestamp": datetime.utcnow().isoformat()
            }
            await self.action_queue.put(incident)
            logger.info(f"Critical incident {incident['id']} queued for automated response.")
        else:
            logger.debug(f"Event score {score} is below critical threshold {settings.CRITICAL_RISK_THRESHOLD}. Ignored by Orchestrator.")

    async def _execute_playbook(self, incident: Dict[str, Any]):
        """Execute the standard SOC playbook for a critical phishing URL."""
        url = incident["url"]
        
        # 1. Draft registrar abuse email
        draft = await self._draft_abuse_email(url, incident["summary"])
        
        # 2. Push firewall rule
        await self._push_firewall_rule(url)
        
        # 3. Update DNS sinkhole (e.g., Cloudflare API mock)
        await self._update_dns_sinkhole(url)
        
        # 4. Notify SOC (Mock Slack webhook)
        await self._notify_soc(incident)
        
        logger.info(f"Playbook execution complete for {incident['id']}")

    async def _draft_abuse_email(self, url: str, context: str) -> str:
        """Simulate LLM drafting an abuse/takedown email tailored to the registrar."""
        logger.info(f"Drafting dynamic abuse email for {url}")
        await asyncio.sleep(1)
        draft = f"Subject: URGENT: Brand Impersonation / Phishing on {url}\n\nTo the Abuse Team,\nOur AI SOC has detected critical malicious activity at {url}. Context: {context}\n\nPlease suspend this domain immediately."
        return draft

    async def _push_firewall_rule(self, url: str):
        """Mock pushing an IP/URL block to PaloAlto/Fortinet."""
        logger.info(f"Pushing egress block rule to firewall for {url}")
        await asyncio.sleep(0.5)

    async def _update_dns_sinkhole(self, url: str):
        """Mock updating a Pi-hole or Cloudflare Gateway sinkhole."""
        logger.info(f"Routing {url} to internal DNS sinkhole (127.0.0.1)")
        await asyncio.sleep(0.5)

    async def _notify_soc(self, incident: Dict[str, Any]):
        """Mock sending an urgent Slack/Teams alert to the human SOC team."""
        logger.info(f"Sending critical PagerDuty/Slack alert for incident {incident['id']}")
        await asyncio.sleep(0.2)


# Export singleton
response_orchestrator = AutonomousResponseOrchestrator()
