"""
Visual Brand Impersonation Scanner

This module provides the VisualAnalysisService, which uses Playwright to capture
full-page screenshots of a URL and sends the image to a Vision LLM to detect
visual impersonation of major brands.
"""

import os
import time
import json
import uuid
import socket
import ipaddress
import logging
from urllib.parse import urlparse
from typing import Dict, Any, Optional

try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:
    logging.getLogger("security").warning(
        "playwright is not installed. Visual analysis will not work."
    )
    async_playwright = None

# Configure security logger
logger = logging.getLogger("security")


# ---------- A-05: SSRF protection ----------

def _is_safe_target(url: str) -> bool:
    """Validate that a URL resolves to a publicly routable host.

    Blocks private, loopback, link-local, reserved, and multicast addresses.
    Also rejects non-http(s) schemes (e.g. file://, ftp://).
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            logger.warning("SSRF check: rejected scheme %r", parsed.scheme)
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # Resolve the hostname to IP addresses
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            ip = ipaddress.ip_address(sockaddr[0])
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                logger.warning(
                    "SSRF check: rejected %s -> %s (private/reserved)",
                    hostname, ip,
                )
                return False

        return True
    except Exception as e:
        logger.error("SSRF check: error resolving %r: %s", url, e)
        return False


class VisualAnalysisService:
    """Service to detect visual brand impersonation using headless browser automation and Vision LLM."""
    
    def __init__(self, storage_dir: str = "/tmp/phishing_scans"):
        """Initialize the visual analysis service."""
        self.storage_dir = storage_dir
        self.supported_brands = ["Microsoft", "Google", "PayPal", "Apple", "Facebook", "Amazon", "Netflix", "Bank"]
        
        # Ensure secure temporary storage directory exists
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir, exist_ok=True)
            # Restrict permissions to owner only
            try:
                os.chmod(self.storage_dir, 0o700)
            except Exception as e:
                logger.warning(f"Failed to set strict permissions on {self.storage_dir}: {e}")

    async def _capture_screenshot(self, url: str) -> Optional[str]:
        """
        Launch a headless browser, navigate to the URL, and capture a full-page screenshot.
        
        Args:
            url (str): The URL to analyze.
            
        Returns:
            Optional[str]: The absolute path to the saved screenshot, or None if failed.
        """
        if not async_playwright:
            logger.error("Playwright is not installed. Cannot capture screenshot.")
            return None

        # A-05: SSRF guard - block internal/private targets
        if not _is_safe_target(url):
            logger.error("Blocked SSRF attempt for URL: %s", url)
            return None
            
        screenshot_filename = f"scan_{uuid.uuid4().hex}.png"
        screenshot_path = os.path.join(self.storage_dir, screenshot_filename)
        
        try:
            async with async_playwright() as p:
                # Launch Chromium in headless mode
                browser = await p.chromium.launch(headless=True)
                
                # Create a new context with a standard viewport
                context = await browser.new_context(
                    viewport={'width': 1280, 'height': 800},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                )
                
                page = await context.new_page()
                
                # Navigate to the URL with a strict timeout
                try:
                    await page.goto(url, wait_until="networkidle", timeout=15000)
                except PlaywrightTimeoutError:
                    logger.warning(f"Timeout while loading {url} for visual analysis. Attempting screenshot anyway.")
                except Exception as e:
                    logger.error(f"Failed to load URL {url}: {str(e)}")
                    await browser.close()
                    return None
                
                # Capture a full-page screenshot
                await page.screenshot(path=screenshot_path, full_page=True)
                
                await browser.close()
                return screenshot_path
                
        except Exception as e:
            logger.error(f"Error during screenshot capture for {url}: {str(e)}")
            return None

    async def _analyze_with_vision_llm(self, image_path: str, url: str) -> Dict[str, Any]:
        """
        Send the captured screenshot to a Vision LLM API to determine brand impersonation.
        (Mocked implementation - replace with actual API call to GPT-4V or Gemini Pro Vision)
        
        Args:
            image_path (str): Absolute path to the screenshot image.
            url (str): The URL being analyzed.
            
        Returns:
            Dict[str, Any]: Structured detection report.
        """
        # In a real implementation, you would:
        # 1. Base64 encode the image
        # 2. Add an explicit prompt like: "Analyze this screenshot. Does it look like a login page for Microsoft, Google, PayPal, or a Bank? The domain is {url}. If the domain does not match the visual brand, it is phishing."
        # 3. Call OpenAI/Google Gemini API.
        
        logger.info(f"Sending {image_path} to Vision LLM for analysis of {url}")
        
        # Simulating LLM response latency
        import asyncio
        await asyncio.sleep(1)
        
        # Mock detection logic for demonstration purposes.
        # If the URL contains "microsoft" but isn't microsoft.com, we simulate a positive hit.
        url_lower = url.lower()
        
        default_response = {
            "brand_detected": None,
            "impersonation_score": 0,
            "reason": "No recognizable brand impersonation detected visually."
        }
        
        if "microsoft" in url_lower and "microsoft.com" not in url_lower:
            return {
                "brand_detected": "Microsoft",
                "impersonation_score": 95,
                "reason": f"Login UI visually matches Microsoft but domain '{url}' is a mismatch."
            }
        elif "paypal" in url_lower and "paypal.com" not in url_lower:
             return {
                "brand_detected": "PayPal",
                "impersonation_score": 98,
                "reason": f"Visual elements heavily mimic PayPal login, but hosted on unauthorized domain."
            }
             
        # Catch-all mock logic
        has_login_keywords = any(kw in url_lower for kw in ['login', 'secure', 'auth', 'verify'])
        if has_login_keywords:
             return {
                "brand_detected": "Generic Bank/Service",
                "impersonation_score": 60,
                "reason": "Page contains generic login structures that resemble common targeted services."
             }

        return default_response

    def _cleanup_screenshot(self, filepath: str):
        """Securely delete the temporary screenshot file."""
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                logger.debug(f"Successfully cleaned up temporary screenshot {filepath}")
        except Exception as e:
            logger.error(f"Failed to delete temporary screenshot {filepath}: {str(e)}")

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Perform completely automated visual brand impersonation analysis on a URL.
        
        Args:
            url (str): The URL to analyze.
            
        Returns:
            Dict[str, Any]: Structured detection report.
        """
        screenshot_path = await self._capture_screenshot(url)
        
        if not screenshot_path:
            return {
                "status": "error",
                "message": "Failed to capture visual screenshot of the target URL.",
                "brand_detected": None,
                "impersonation_score": 0,
                "reason": "Analysis failed before LLM processing."
            }
            
        try:
            analysis_result = await self._analyze_with_vision_llm(screenshot_path, url)
            
            # Enrich response
            result = {
                "status": "success",
                "url_analyzed": url,
                **analysis_result
            }
            return result
            
        finally:
            # Enforce Zero Trust / Data Privacy: Ensure image is deleted immediately after analysis
            self._cleanup_screenshot(screenshot_path)
