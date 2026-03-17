"""
Shodan API integration
"""

import logging
from typing import Dict, Any
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class ShodanAPI(BaseAPIClient):
    """Shodan API client"""

    BASE_URL = "https://api.shodan.io/"

    def __init__(self, api_key: str = None, timeout: int = 30):
        """Initialize Shodan API client"""
        super().__init__(api_key, timeout)
        # Validate API key format (basic check)
        if api_key and len(api_key) < 10:
            logger.warning("Shodan API key appears to be invalid (too short)")

    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze IP using Shodan API
        
        Args:
            observable: IP address
            
        Returns:
            Analysis results
        """
        if not self._is_valid_ip(observable):
            return {
                "error": "Shodan only supports IP addresses",
                "source": "Shodan",
            }
        
        return self._get_host_info(observable)

    def _get_host_info(self, ip: str) -> Dict[str, Any]:
        """Get host information from Shodan"""
        # Validate API key is set
        if not self.api_key:
            return {
                "error": "Shodan API key not configured",
                "source": "Shodan",
                "type": "ip",
            }
        
        params = {"key": self.api_key, "minify": True}
        url = f"{self.BASE_URL}shodan/host/{ip}"
        
        result = self._make_request(url, params=params)
        
        if "error" in result:
            logger.warning(f"Shodan API error for {ip}: {result.get('error')}")
            return {
                "error": result.get("error"),
                "source": "Shodan",
                "type": "ip",
            }
        
        return {
            "source": "Shodan",
            "type": "ip",
            "observable": ip,
            "ip": result.get("ip"),
            "country_name": result.get("country_name"),
            "country_code": result.get("country_code"),
            "city": result.get("city"),
            "latitude": result.get("latitude"),
            "longitude": result.get("longitude"),
            "isp": result.get("isp"),
            "organization": result.get("org"),
            "ports": result.get("ports", []),
            "hostnames": result.get("hostnames", []),
            "os": result.get("os"),
            "services": self._extract_services(result),
            "last_update": result.get("last_update"),
            "raw_data": result,
        }

    def _get_honeyscore(self, ip: str) -> Dict[str, Any]:
        """Get honeypot score for IP"""
        params = {"key": self.api_key}
        url = f"{self.BASE_URL}labs/honeyscore/{ip}"
        
        result = self._make_request(url, params=params)
        
        if "error" in result:
            return {"error": result.get("error"), "source": "Shodan"}
        
        return {
            "source": "Shodan",
            "type": "honeyscore",
            "observable": ip,
            "score": result,  # Score is a float between 0 and 1
            "raw_data": result,
        }

    @staticmethod
    def _extract_services(host_data: Dict) -> list:
        """Extract service information from host data"""
        services = []
        
        for item in host_data.get("data", []):
            service = {
                "port": item.get("port"),
                "protocol": item.get("_shodan", {}).get("module", "unknown"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": item.get("data", "").split("\n")[0][:100],  # First line
            }
            services.append(service)
        
        return services
