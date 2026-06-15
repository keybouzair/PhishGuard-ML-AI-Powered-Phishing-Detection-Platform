import asyncio
import json
import random
from typing import Dict, Any, List
from core.logger import get_logger, log_execution_time
from core.config import settings

logger = get_logger("labs.phishing_simulator")


class ZeroDayPhishingSimulator:
    """
    Ultra Feature 4: Zero-Day Phishing Simulation Lab
    A sandboxed red-team generative tool that crafts hypothetical AI-written phishing emails,
    typosquatted domains, and DOM templates to test the SOC detection pipeline.
    """

    def __init__(self):
        if not settings.ENABLE_PHISHING_SIMULATOR:
            logger.warning("Phishing Simulator is disabled in configuration. Instantiated but will deny generation requests.")
        else:
            logger.info("Zero-Day Phishing Simulator Lab Online")

    @log_execution_time(logger)
    async def generate_synthetic_threat(self, threat_type: str = "all") -> Dict[str, Any]:
        """
        Generate a comprehensive synthetic threat payload.
        Allowed types: 'email', 'domain', 'dom', 'all'
        """
        if not settings.ENABLE_PHISHING_SIMULATOR:
            raise PermissionError("Phishing Simulator is currently disabled by enterprise policy.")

        logger.info(f"Generating synthetic {threat_type} threat")
        
        result = {"metadata": {"generated_by": "ZeroDayPhishingSimulator", "type": threat_type}}
        
        # Run generative tasks concurrently
        tasks = []
        if threat_type in ('domain', 'all'):
            result["domain"] = await self._generate_typosquat()
        if threat_type in ('email', 'all'):
            result["email"] = await self._generate_ai_email()
        if threat_type in ('dom', 'all'):
            result["dom_template"] = await self._generate_fake_login_dom()
            
        logger.info("Synthetic threat generated successfully", extra={"extra_fields": {"threat_data": result}})
        return result

    async def _generate_typosquat(self) -> Dict[str, str]:
        """
        Mocks reaching out to an LLM or DNS generator to create highly evasive homograph or typosquatted domains.
        """
        await asyncio.sleep(0.5)
        targets = ["microsoft.com", "paypal.com", "chase.com", "apple.com"]
        base = random.choice(targets)
        
        # Simple local transposition mock
        squatted = base.replace('i', '1').replace('o', '0').replace('l', 'I')
        if squatted == base:
            squatted = base.replace('.', '-login.')
            
        return {
            "target_brand": base,
            "synthetic_domain": squatted,
            "technique": "homograph/typosquatting substitution"
        }

    async def _generate_ai_email(self) -> Dict[str, str]:
        """
        Mocks an LLM generating a highly urgent, context-aware phishing lure.
        """
        await asyncio.sleep(0.8)
        urgencies = ["Account Deletion Warning", "Suspicious Activity Detected", "Invoice #88392 Overdue"]
        subject = random.choice(urgencies)
        
        body = f"""Dear Customer,\n\nWe have detected unusual activity on your account. To prevent immediate suspension, please review and verify your information using the secure link below.\n\nFailure to act within 24 hours will result in permanent loss of access.\n\nThank you,\nSecurity Operations"""
        
        return {
            "subject": subject,
            "body": body,
            "urgency_score": 98.5,
            "persuasion_technique": "Scarcity & Authority"
        }

    async def _generate_fake_login_dom(self) -> Dict[str, str]:
        """
        Mocks the generation of an obfuscated HTML/React template designed to trick standard DOM parsers.
        """
        await asyncio.sleep(0.4)
        return {
            "technique": "CSS grid obfuscation + SVG overlay",
            "snippet": "<html><body style='display:grid'><div id='overlay'>Please log in to Microsoft</div><form><input name='u'/><input type='password' name='p'/></form></body></html>"
        }

# Export singleton
phishing_simulator = ZeroDayPhishingSimulator()
