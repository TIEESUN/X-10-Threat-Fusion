"""
IP Detective API integration - Bot/VPN/Proxy detection for IP addresses
"""

import logging
from typing import Dict, Any
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class IPDetectiveAPI(BaseAPIClient):
    """IP Detective API client for detecting bots, VPNs, and proxies"""

    BASE_URL = "https://api.ipdetective.io/"

    def __init__(self, api_key: str, timeout: int = 15):
        """Initialize IP Detective API client
        
        Args:
            api_key: IP Detective API key
            timeout: Request timeout in seconds (default: 15)
        """
        super().__init__(api_key, timeout)

    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze IP address using IP Detective API
        
        Args:
            observable: IP address to analyze
            
        Returns:
            Analysis results
        """
        # Only handles IP addresses
        if not self._is_valid_ip(observable):
            return {"error": "IP Detective only analyzes IP addresses"}
        
        return self._query_ip(observable)

    def _query_ip(self, ip: str) -> Dict[str, Any]:
        """Query IP address from IP Detective"""
        url = f"{self.BASE_URL}ip/{ip}"
        
        headers = {
            "x-api-key": self.api_key,
            "Content-Type": "application/json"
        }
        
        params = {
            "info": "true"  # Get detailed info including type, ASN, country
        }
        
        try:
            result = self._make_request(url, method="GET", headers=headers, params=params)
        except Exception as e:
            logger.error(f"IP Detective API error for {ip}: {e}")
            return {"error": f"API error: {str(e)}", "source": "IP Detective", "observable": ip}
        
        return self._process_response(result, ip)

    def _process_response(self, result: Dict[str, Any], ip: str) -> Dict[str, Any]:
        """Process API response and extract threat data"""
        
        # Check for errors
        if "error" in result:
            return {
                "source": "IP Detective",
                "observable": ip,
                "type": "ip",
                "error": result.get("error")
            }
        
        # Extract data
        is_bot = result.get("bot", False)
        ip_type = result.get("type", "unknown")  # datacenter, bot, vpn, proxy, unknown
        asn = result.get("asn")
        asn_description = result.get("asn_description", "")
        country_code = result.get("country_code", "")
        country_name = result.get("country_name", "")
        
        # Determine threat level
        threat_level = "unknown"
        is_malicious = False
        is_suspicious = False
        
        if is_bot:
            threat_level = "high"
            is_suspicious = True
        
        if ip_type in ["vpn", "proxy"]:
            threat_level = "medium" if threat_level == "unknown" else threat_level
            is_suspicious = True
        elif ip_type == "datacenter":
            threat_level = "medium" if threat_level == "unknown" else threat_level
            is_suspicious = True
        
        response = {
            "source": "IP Detective",
            "observable": ip,
            "type": "ip",
            "is_bot": is_bot,
            "ip_type": ip_type,
            "threat_level": threat_level,
            "is_suspicious": is_suspicious,
            "is_malicious": is_malicious,
            "malicious": 1 if is_malicious else 0,  # For analytics aggregation
            "suspicious": 1 if is_suspicious else 0,  # For analytics aggregation
            "asn": asn,
            "asn_description": asn_description,
            "country_code": country_code,
            "country_name": country_name,
            "raw_data": result
        }
        
        return response
