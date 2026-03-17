"""
IPInfo API integration
"""

import logging
from typing import Dict, Any
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class IPInfoAPI(BaseAPIClient):
    """IPInfo.io API client"""

    BASE_URL = "https://ipinfo.io/"

    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze IP using IPInfo API
        
        Args:
            observable: IP address
            
        Returns:
            Analysis results
        """
        if not self._is_valid_ip(observable):
            return {"error": "IPInfo only supports IP addresses"}
        
        return self._get_ip_info(observable)

    def _get_ip_info(self, ip: str) -> Dict[str, Any]:
        """Get IP information"""
        params = {"token": self.api_key}
        url = f"{self.BASE_URL}{ip}/json"
        
        result = self._make_request(url, params=params)
        
        if "error" in result:
            return result
        
        return {
            "source": "IPInfo",
            "type": "ip",
            "observable": ip,
            "ip": result.get("ip"),
            "hostname": result.get("hostname"),
            "city": result.get("city"),
            "region": result.get("region"),
            "country": result.get("country"),
            "loc": result.get("loc"),
            "org": result.get("org"),
            "timezone": result.get("timezone"),
            "isp": result.get("isp", ""),
            "privacy": result.get("privacy", {}),
            "abuse": result.get("abuse", {}),
            "raw_data": result,
        }
