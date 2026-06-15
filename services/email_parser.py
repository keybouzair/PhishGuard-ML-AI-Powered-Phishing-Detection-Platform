"""
Email Intelligence Parser

This module provides the EmailIntelligenceService to parse raw `.eml` files,
extract metadata, find all embedded URLs, and run basic NLP analysis to detect
urgent language often found in phishing campaigns.
"""

import email
from email import policy
from email.message import EmailMessage
import logging
import re
from typing import Dict, Any, List

# Configure logger
logger = logging.getLogger("security")

class EmailIntelligenceService:
    """Service to extract intelligence and URLs from raw .eml files."""
    
    def __init__(self):
        # Common urgency/phishing keyword heuristic
        self.urgency_keywords = [
            r"\burgent\b",
            r"\bimmediate action required\b",
            r"\baccount suspended\b",
            r"\bverify your account\b",
            r"\bpassword expiry\b",
            r"\bunauthorized login\b",
            r"\bupdate payment detail\b",
            r"\bvalidate account\b",
            r"\bclick here immediately\b"
        ]
        
        # Regex to extract URLs strictly starting with http/https
        self.url_pattern = re.compile(
            r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
        )
        
    def _extract_text_body(self, msg: EmailMessage) -> str:
        """Extract plain text and HTML bodies from the email."""
        body_text = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                # Only look at main body (ignore attachments for now)
                if "attachment" not in content_disposition:
                    if content_type == "text/plain":
                        try:
                            body_text += part.get_payload(decode=True).decode('utf-8', errors='ignore') + "\n"
                        except Exception as e:
                            logger.debug(f"Failed to decode text/plain part: {e}")
                            
                    elif content_type == "text/html":
                        try:
                            # We could use bs4 here to strip HTML tags, but regex URL extraction works on raw HTML too.
                            body_text += part.get_payload(decode=True).decode('utf-8', errors='ignore') + "\n"
                        except Exception as e:
                            logger.debug(f"Failed to decode text/html part: {e}")
        else:
            try:
                body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except Exception as e:
                 logger.error(f"Failed to decode single-part body: {e}")
                 
        return body_text

    def _extract_urls(self, text: str) -> List[str]:
        """Extract all unique URLs from text."""
        urls = []
        matches = self.url_pattern.findall(text)
        
        for match in matches:
            url = match[0]
            # Clean up URLs (strip trailing punctuation that regex might catch)
            url = url.strip('.,; "\'')
            
            if url.startswith('http'):
                 urls.append(url)
                 
        return list(set(urls))

    def _analyze_urgency_language(self, text: str) -> Dict[str, Any]:
        """Analyze email body text for common phishing/urgency triggers using regex heuristics."""
        text_lower = text.lower()
        score = 0
        matches_found = []
        
        for pattern in self.urgency_keywords:
            if re.search(pattern, text_lower):
                matches_found.append(pattern.replace(r"\b", ""))
                score += 20  # Arbitrary weighting per matched keyword
                
        # Cap score at 100
        final_score = min(score, 100)
        
        # Determine probability of being AI-generated/malicious based strictly on language layout
        ai_prob = final_score * 0.8  # Simplified heuristic proxy
        
        return {
            "risk_language_score": final_score,
            "matched_keywords": matches_found,
            "ai_generated_probability": round(ai_prob, 2)
        }

    async def parse_eml_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """
        Main entrypoint: Parse an uploaded .eml file.
        
        Args:
            file_data (bytes): Raw bytes of the .eml file.
            filename (str): Name of the file.
            
        Returns:
            Dict[str, Any]: Scan results including metadata, URLs, and language risk score.
        """
        try:
            # Parse raw bytes into Python EmailMessage object
            msg = email.message_from_bytes(file_data, policy=policy.default)
            
            subject = msg.get('Subject', '')
            sender = msg.get('From', '')
            recipient = msg.get('To', '')
            date = msg.get('Date', '')
            
            logger.info(f"Parsing EML from {sender} subject {subject}")
            
            body_text = self._extract_text_body(msg)
            extracted_urls = self._extract_urls(body_text)
            language_analysis = self._analyze_urgency_language(body_text)
            
            return {
                "status": "success",
                "metadata": {
                    "subject": subject,
                    "sender": sender,
                    "recipient": recipient,
                    "date": date
                },
                "urls_extracted": extracted_urls,
                **language_analysis
            }
            
        except Exception as e:
            logger.error(f"Error parsing .eml file {filename}: {str(e)}")
            return {
                "status": "error",
                "message": f"Failed to parse email file: {str(e)}"
            }
