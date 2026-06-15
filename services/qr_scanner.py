"""
QR Code Scanner (Quishing Detection)

This module provides the QRScannerService, which extracts URLs from
uploaded images or PDF files (containing QR codes) using pyzbar and OpenCV.
"""

import os
import io
import logging
from typing import List, Dict, Any, Tuple
import tempfile

try:
    import cv2
    import numpy as np
    from pyzbar.pyzbar import decode, ZBarSymbol
except ImportError:
    print("Warning: opencv-python or pyzbar not installed. QR scanning disabled.")
    cv2, np, decode, ZBarSymbol = None, None, None, None

try:
    import fitz  # PyMuPDF
except ImportError:
    print("Warning: PyMuPDF (fitz) not installed. PDF scanning disabled.")
    fitz = None

# Configure logger
logger = logging.getLogger("security")

class QRScannerService:
    """Service to extract URLs from QR codes in images and PDFs."""
    
    def __init__(self, max_file_size_mb: int = 10):
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        
    def _is_valid_url(self, text: str) -> bool:
        """Basic validation to check if the decoded QR code is a URL."""
        text = text.strip()
        return text.startswith("http://") or text.startswith("https://")
        
    def _decode_image_bytes(self, image_data: bytes) -> List[str]:
        """Decode all QR codes in an image byte payload."""
        if not cv2 or not decode:
            logger.error("QR decoding unavailable")
            return []
            
        urls = []
        try:
            # Convert bytes to numpy array then to OpenCV image
            nparr = np.frombuffer(image_data, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if img is None:
                logger.error("Failed to decode image data into valid OpenCV matrix")
                return urls
            
            # Detect and decode QR codes
            decoded_objects = decode(img, symbols=[ZBarSymbol.QRCODE])
            
            for obj in decoded_objects:
                try:
                    text = obj.data.decode('utf-8')
                    if self._is_valid_url(text):
                        urls.append(text)
                except Exception as e:
                    logger.debug(f"Failed to decode QR object data: {e}")
                    
            return list(set(urls))  # Return unique URLs
            
        except Exception as e:
            logger.error(f"Error during QR extraction from image: {e}")
            return urls
            
    def _extract_images_from_pdf(self, pdf_data: bytes) -> List[bytes]:
        """Extract embedded image streams from a PDF document."""
        if not fitz:
            logger.error("PDF processing unavailable (PyMuPDF missing)")
            return []
            
        image_bytes_list = []
        try:
            # Load PDF from memory safely
            doc = fitz.open(stream=pdf_data, filetype="pdf")
            for page_num in range(len(doc)):
                page = doc.load_page(page_num)
                # Ensure we handle multiple images per page
                images = page.get_images(full=True)
                for img_info in images:
                    xref = img_info[0]
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]
                    if image_bytes:
                        image_bytes_list.append(image_bytes)
            return image_bytes_list
        except Exception as e:
            logger.error(f"Error parsing PDF: {e}")
            return []

    async def extract_urls_from_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        """
        Main entrypoint: Parse an uploaded file and extract embedded URLs via QR codes.
        
        Args:
            file_data (bytes): The raw file bytes.
            filename (str): Original filename, used to guess MIME handling.
            
        Returns:
            Dict[str, Any]: Scan results including extracted URLs.
        """
        # Security: Hard limit file size in RAM
        if len(file_data) > self.max_file_size_bytes:
            return {
                "status": "error",
                "message": f"File exceeds maximum allowed size ({self.max_file_size_bytes} bytes).",
                "urls_found": []
            }
            
        filename_lower = filename.lower()
        extracted_urls = []
        
        # Determine file handling based on extension signature
        if filename_lower.endswith('.pdf'):
            logger.info(f"Processing PDF file for Quishing: {filename}")
            images = self._extract_images_from_pdf(file_data)
            for img_bytes in images:
                 urls = self._decode_image_bytes(img_bytes)
                 extracted_urls.extend(urls)
                 
        elif filename_lower.endswith(('.png', '.jpg', '.jpeg', '.webp')):
             logger.info(f"Processing Image file for Quishing: {filename}")
             urls = self._decode_image_bytes(file_data)
             extracted_urls.extend(urls)
             
        else:
             return {
                 "status": "error",
                 "message": "Unsupported file format. Must be PDF, PNG, JPG, or WEBP.",
                 "urls_found": []
             }
             
        unique_urls = list(set(extracted_urls))
        
        return {
            "status": "success",
            "message": f"Extracted {len(unique_urls)} URLs from QR codes.",
            "urls_found": unique_urls
        }
