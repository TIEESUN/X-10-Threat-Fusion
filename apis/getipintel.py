"""
GetIPIntel API integration - Proxy, VPN & Malicious IP Detection
"""

import logging
from typing import Dict, Any
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class GetIPIntelAPI(BaseAPIClient):
    """GetIPIntel API client for proxy/VPN/bad IP detection"""

    BASE_URL = "http://check.getipintel.net/check.php"

    def __init__(self, contact_email: str, timeout: int = 15):
        """Initialize GetIPIntel API client
        
        Args:
            contact_email: Valid contact email (required by API)
            timeout: Request timeout in seconds (default: 15)
        """
        self.api_key = None  # GetIPIntel doesn't use API keys, just email
        self.contact_email = contact_email
        self.timeout = timeout
        self.session = self._create_session()

    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze IP address using GetIPIntel API
        
        Args:
            observable: IP address to analyze
            
        Returns:
            Analysis results
        """
        # Only handles IP addresses
        if not self._is_valid_ip(observable):
            return {"error": "GetIPIntel only analyzes IP addresses"}
        
        return self._query_ip(observable)

    def _query_ip(self, ip: str) -> Dict[str, Any]:
        """Query IP address from GetIPIntel"""
        
        params = {
            "ip": ip,
            "contact": self.contact_email,
            "format": "json",
            "flags": "b",  # Use dynamic ban lists and dynamic checks (good balance)
            "oflags": "a"  # Include ASN information
        }
        
        try:
            result = self._make_request(self.BASE_URL, method="GET", params=params)
        except Exception as e:
            logger.error(f"GetIPIntel API error for {ip}: {e}")
            return {"error": f"API error: {str(e)}", "source": "GetIPIntel", "observable": ip}
        
        return self._process_response(result, ip)

    def _process_response(self, result: Dict[str, Any], ip: str) -> Dict[str, Any]:
        """Process API response and extract threat data"""
        
        # Check for errors
        if "error" in result:
            return {
                "source": "GetIPIntel",
                "observable": ip,
                "type": "ip",
                "error": result.get("error")
            }
        
        # Check response status
        status = result.get("status", "").lower()
        if status == "error":
            message = result.get("message", "Unknown error")
            error_code = result.get("result", "Unknown")
            return {
                "source": "GetIPIntel",
                "observable": ip,
                "type": "ip",
                "error": f"{message} (Code: {error_code})"
            }
        
        if status != "success":
            return {
                "source": "GetIPIntel",
                "observable": ip,
                "type": "ip",
                "error": "Unexpected response status"
            }
        
        # Extract proxy/VPN score
        try:
            score = float(result.get("result", 0))
        except (TypeError, ValueError):
            score = 0
        
        # Determine threat classification
        is_proxy_vpn = score > 0.90  # High risk threshold
        is_likely_proxy_vpn = score > 0.50  # Moderate risk threshold
        is_suspicious = score > 0.50
        is_malicious = False
        
        # Interpret score
        if score >= 0.99:
            threat_level = "critical"
        elif score >= 0.95:
            threat_level = "high"
        elif score >= 0.75:
            threat_level = "medium"
        elif score >= 0.50:
            threat_level = "low"
        else:
            threat_level = "unknown"
        
        response = {
            "source": "GetIPIntel",
            "observable": ip,
            "type": "ip",
            "score": score,
            "is_proxy_vpn": is_proxy_vpn,
            "is_likely_proxy_vpn": is_likely_proxy_vpn,
            "threat_level": threat_level,
            "is_suspicious": is_suspicious,
            "is_malicious": is_malicious,
            "malicious": 1 if is_malicious else 0,  # For analytics aggregation
            "suspicious": 1 if is_suspicious else 0,  # For analytics aggregation
            "flags_used": result.get("queryFlags", "b"),
            "asn": result.get("ASN"),
            "raw_data": result
        }
        
        return response
