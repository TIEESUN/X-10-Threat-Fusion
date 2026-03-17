"""
URLhaus API integration - FIXED
"""

import logging
from typing import Dict, Any
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class URLHausAPI(BaseAPIClient):
    """URLhaus API client (no authentication required)"""

    BASE_URL = "https://urlhaus-api.abuse.ch/v1/"

    def __init__(self, api_key: str = None, timeout: int = 15):
        """Initialize URLhaus API client
        
        Args:
            api_key: URLhaus API key (now required for authentication)
            timeout: Request timeout in seconds (default: 15)
        """
        self.api_key = api_key
        self.timeout = timeout
        # Create session
        self.session = self._create_session()


    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze URL or domain using URLhaus API
        
        Args:
            observable: URL or domain
            
        Returns:
            Analysis results
        """
        if not self._is_valid_url(observable) and not self._is_valid_domain(observable):
            return {"error": "Invalid URL or domain"}
        
        if self._is_valid_url(observable):
            return self._query_url(observable)
        else:
            return self._query_domain(observable)

    def _query_url(self, url: str) -> Dict[str, Any]:
        """Query URL from URLhaus"""
        data = {"url": url}
        api_url = f"{self.BASE_URL}url/"
        
        # Debug: Check if API key is set
        if not self.api_key:
            logger.error("URLhaus API key is not set!")
            return {"error": "URLhaus API key is not configured"}
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Auth-Key": self.api_key
        }
        
        logger.debug(f"URLhaus request - URL: {url}, Auth-Key: {self.api_key[:20]}...")
        
        try:
            import requests as req
            response = req.post(
                api_url,
                data=data,
                headers=headers,
                timeout=self.timeout
            )
            logger.debug(f"URLhaus response status: {response.status_code}")
            # Check for 401 before raise_for_status
            if response.status_code == 401:
                logger.error(f"URLhaus API unauthorized (401): {response.text}")
                return {"error": "Unauthorized - Invalid API key"}
            response.raise_for_status()
            result = response.json()
        except Exception as e:
            logger.error(f"URLhaus URL query failed: {e}")
            return {"error": str(e)}
        
        if "error" in result:
            return result
        
        if result.get("query_status") != "ok":
            return {
                "source": "URLhaus",
                "type": "url",
                "observable": url,
                "status": "not_found",
            }
        
        query_result = result
        
        return {
            "source": "URLhaus",
            "type": "url",
            "observable": url,
            "status": query_result.get("url_status"),
            "threat": query_result.get("threat"),
            "tags": query_result.get("tags", []),
            "date_added": query_result.get("date_added"),
            "last_online": query_result.get("last_online"),
            "url_status": query_result.get("url_status"),
            "raw_data": result,
        }

    def _query_domain(self, domain: str) -> Dict[str, Any]:
        """Query domain from URLhaus"""
        data = {"host": domain}
        api_url = f"{self.BASE_URL}host/"
        
        # Debug: Check if API key is set
        if not self.api_key:
            logger.error("URLhaus API key is not set!")
            return {"error": "URLhaus API key is not configured"}
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Auth-Key": self.api_key
        }
        
        logger.debug(f"URLhaus request - Domain: {domain}, Auth-Key: {self.api_key[:20]}...")
        
        try:
            import requests as req
            response = req.post(
                api_url,
                data=data,
                headers=headers,
                timeout=self.timeout
            )
            logger.debug(f"URLhaus response status: {response.status_code}")
            # Check for 401 before raise_for_status
            if response.status_code == 401:
                logger.error(f"URLhaus API unauthorized (401): {response.text}")
                return {"error": "Unauthorized - Invalid API key"}
            response.raise_for_status()
            result = response.json()
        except Exception as e:
            logger.error(f"URLhaus domain query failed: {e}")
            return {"error": str(e)}
        
        if "error" in result:
            return result
        
        if result.get("query_status") == "no_results":
            return {
                "source": "URLhaus",
                "type": "domain",
                "observable": domain,
                "status": "not_found",
                "url_count": 0
            }
        
        if result.get("query_status") != "ok":
            return {
                "source": "URLhaus",
                "type": "domain",
                "observable": domain,
                "status": "not_found",
            }
        
        urls = result.get("urls", [])
        
        return {
            "source": "URLhaus",
            "type": "domain",
            "observable": domain,
            "url_count": len(urls),
            "firstseen": result.get("firstseen"),
            "urls": [self._format_url_entry(u) for u in urls[:10]],
            "raw_data": result,
        }

    @staticmethod
    def _format_url_entry(url_entry: Dict) -> Dict:
        """Format URL entry"""
        return {
            "url": url_entry.get("url", "")[:150],
            "status": url_entry.get("url_status"),
            "threat": url_entry.get("threat"),
            "tags": url_entry.get("tags", []),
            "date_added": url_entry.get("date_added"),
        }
