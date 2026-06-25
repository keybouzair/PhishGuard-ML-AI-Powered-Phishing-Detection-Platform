import asyncio
import json
import random
import os
import requests
from datetime import datetime
import time
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
    async def generate_synthetic_threat(self, threat_type: str = "all", target_brand: str = "Microsoft") -> Dict[str, Any]:
        """
        Generate a comprehensive synthetic threat payload.
        Allowed types: 'email', 'domain', 'dom', 'all'
        """
        if not settings.ENABLE_PHISHING_SIMULATOR:
            raise PermissionError("Phishing Simulator is currently disabled by enterprise policy.")

        logger.info(f"Generating synthetic {threat_type} threat targeting {target_brand}")
        
        result = {
            "metadata": {
                "generated_by": "ZeroDayPhishingSimulator", 
                "type": threat_type,
                "target_brand": target_brand,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        if threat_type in ('domain', 'all'):
            result["domain"] = await self._generate_typosquat(target_brand)
        if threat_type in ('email', 'all'):
            result["email"] = await self._generate_ai_email(target_brand)
        if threat_type in ('dom', 'all'):
            result["dom_template"] = await self._generate_fake_login_dom(target_brand)
            
        logger.info("Synthetic threat generated successfully", extra={"extra_fields": {"threat_data": result}})
        return result

    async def _generate_typosquat(self, brand: str) -> Dict[str, str]:
        """
        Queries Gemini API to create highly evasive homograph or typosquatted domains for a brand.
        Falls back to mock heuristics if GEMINI_API_KEY is not configured.
        """
        gemini_key = os.environ.get("GEMINI_API_KEY") or settings.GEMINI_API_KEY
        if gemini_key:
            try:
                api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
                prompt = (
                    f"Generate a typosquatted or homograph domain variation for the brand: '{brand}'.\n"
                    f"The domain variation should look highly realistic and deceptive.\n"
                    f"Also specify the evasion technique used.\n"
                    f"Output JSON ONLY in the following format:\n"
                    f'{{"target_brand": "{brand}", "synthetic_domain": "evasive-domain-variation.com", "technique": "description of substitution/homograph technique"}}'
                )
                
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"responseMimeType": "application/json"}
                }
                
                response = requests.post(api_url, json=payload, headers={"Content-Type": "application/json"}, timeout=15)
                if response.status_code == 200:
                    resp_data = response.json()
                    text_response = resp_data["contents"][0]["parts"][0]["text"].strip()
                    if "```json" in text_response:
                        text_response = text_response.split("```json")[1].split("```")[0].strip()
                    elif "```" in text_response:
                        text_response = text_response.split("```")[1].strip()
                    
                    data = json.loads(text_response)
                    return {
                        "target_brand": brand,
                        "synthetic_domain": data.get("synthetic_domain", f"{brand.lower().replace('.', '')}-verify.com"),
                        "technique": data.get("technique", "Homograph character replacement")
                    }
            except Exception as e:
                logger.error(f"Gemini domain typosquat generation failed: {e}", exc_info=True)

        # Fallback Mock heuristics
        await asyncio.sleep(0.3)
        base = brand.lower()
        squatted = base.replace('i', '1').replace('o', '0').replace('l', 'I')
        if squatted == base:
            squatted = base.replace('.', '-login.')
        if not (squatted.endswith('.com') or squatted.endswith('.org') or squatted.endswith('.net')):
            squatted = squatted + "-secure-login.com"
            
        return {
            "target_brand": brand,
            "synthetic_domain": squatted,
            "technique": "character substitution / brand suffix insertion (heuristic fallback)"
        }

    async def _generate_ai_email(self, brand: str) -> Dict[str, Any]:
        """
        Queries Gemini API to generate a highly urgent, context-aware phishing lure for a brand.
        Falls back to mock heuristics if GEMINI_API_KEY is not configured.
        """
        gemini_key = os.environ.get("GEMINI_API_KEY") or settings.GEMINI_API_KEY
        if gemini_key:
            try:
                api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
                prompt = (
                    f"Draft a highly context-aware, persuasive phishing email lure targeting users of the brand: '{brand}'.\n"
                    f"The email should use persuasive elements like scarcity, urgency, or authority.\n"
                    f"Also specify the persuasion technique name.\n"
                    f"Output JSON ONLY in the following format:\n"
                    f'{{"subject": "Email Subject Line", "body": "Full body text of the phishing email", "urgency_score": 95, "persuasion_technique": "Name of the psychological trigger/technique used (e.g. Scarcity & Authority)"}}'
                )
                
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"responseMimeType": "application/json"}
                }
                
                response = requests.post(api_url, json=payload, headers={"Content-Type": "application/json"}, timeout=15)
                if response.status_code == 200:
                    resp_data = response.json()
                    text_response = resp_data["contents"][0]["parts"][0]["text"].strip()
                    if "```json" in text_response:
                        text_response = text_response.split("```json")[1].split("```")[0].strip()
                    elif "```" in text_response:
                        text_response = text_response.split("```")[1].strip()
                    
                    data = json.loads(text_response)
                    return {
                        "subject": data.get("subject"),
                        "body": data.get("body"),
                        "urgency_score": float(data.get("urgency_score", 90)),
                        "persuasion_technique": data.get("persuasion_technique", "Authority & Urgency")
                    }
            except Exception as e:
                logger.error(f"Gemini AI email generation failed: {e}", exc_info=True)

        # Fallback Mock heuristics
        await asyncio.sleep(0.4)
        urgencies = ["Account Deletion Warning", "Suspicious Activity Detected", "Action Required: Update payment details"]
        subject = f"[{brand}] {random.choice(urgencies)}"
        body = f"Dear Customer,\n\nWe have detected unusual activity on your {brand} account. To prevent immediate suspension, please review and verify your information using our secure portal.\n\nFailure to act within 24 hours will result in permanent loss of access.\n\nThank you,\n{brand} Security Operations"
        return {
            "subject": subject,
            "body": body,
            "urgency_score": 95.0,
            "persuasion_technique": "Scarcity & Authority (heuristic fallback)"
        }

    async def _generate_fake_login_dom(self, brand: str) -> Dict[str, str]:
        """
        Queries Gemini API to generate an obfuscated login template designed to visually match the brand.
        Falls back to mock heuristics if GEMINI_API_KEY is not configured.
        """
        gemini_key = os.environ.get("GEMINI_API_KEY") or settings.GEMINI_API_KEY
        if gemini_key:
            try:
                api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
                prompt = (
                    f"Generate a realistic fake login page HTML/CSS structure (DOM template) that visually impersonates the brand: '{brand}'.\n"
                    f"The HTML code should use clean Tailwind CSS classes or inline styles for styling and include input fields for username and password to mimic a standard login portal.\n"
                    f"Output JSON ONLY in the following format:\n"
                    f'{{"technique": "Description of the visual trick or styling techniques used", "snippet": "<html>...code...</html>"}}'
                )
                
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"responseMimeType": "application/json"}
                }
                
                response = requests.post(api_url, json=payload, headers={"Content-Type": "application/json"}, timeout=15)
                if response.status_code == 200:
                    resp_data = response.json()
                    text_response = resp_data["contents"][0]["parts"][0]["text"].strip()
                    if "```json" in text_response:
                        text_response = text_response.split("```json")[1].split("```")[0].strip()
                    elif "```" in text_response:
                        text_response = text_response.split("```")[1].strip()
                    
                    data = json.loads(text_response)
                    return {
                        "technique": data.get("technique", "Brand CSS Layout Matching"),
                        "snippet": data.get("snippet", f"<div>Fake {brand} Portal</div>")
                    }
            except Exception as e:
                logger.error(f"Gemini DOM template generation failed: {e}", exc_info=True)

        # Fallback Mock heuristics
        await asyncio.sleep(0.3)
        return {
            "technique": "CSS grid obfuscation + SVG overlay (heuristic fallback)",
            "snippet": f"<html><body class='bg-[#0f0f12] text-white flex justify-center items-center h-screen'><div class='p-8 bg-[#1a1a24] rounded-lg border border-white/10 shadow-xl w-80'><div class='text-center mb-6 font-bold text-lg text-primary'>Sign in to your {brand} Account</div><form class='space-y-4'><input type='email' placeholder='Email' class='w-full p-2 bg-[#0f0f12] border border-white/10 rounded'/><input type='password' placeholder='Password' class='w-full p-2 bg-[#0f0f12] border border-white/10 rounded'/><button class='w-full py-2 bg-primary text-on-primary rounded font-bold hover:bg-primary/80'>Sign In</button></form></div></body></html>"
        }

# Export singleton
phishing_simulator = ZeroDayPhishingSimulator()
