"""
URLscan API integration
"""

import logging
from typing import Dict, Any
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class URLscanAPI(BaseAPIClient):
    """URLscan.io API client"""

    BASE_URL = "https://urlscan.io/api/v1/"

    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze observable using URLscan API
        
        Args:
            observable: Domain, URL, or IP address
            
        Returns:
            Analysis results
        """
        obs_type = self._classify_observable(observable)
        
        if obs_type == "ip":
            return self._search_by_ip(observable)
        elif obs_type == "domain":
            return self._search_by_domain(observable)
        elif obs_type == "url":
            return self._search_url(observable)
        else:
            return {"error": "Unsupported observable type for URLscan"}

    def _search_url(self, url: str) -> Dict[str, Any]:
        """Search for URL scan results"""
        headers = {
            "API-Key": self.api_key,
            "Content-Type": "application/json",
        }
        
        # First submit the URL for scanning
        submit_data = {"url": url, "visibility": "public"}
        submit_url = f"{self.BASE_URL}scan/"
        
        submit_result = self._make_request(
            submit_url,
            method="POST",
            headers=headers,
            json_data=submit_data,
        )
        
        if "error" in submit_result:
            # If submission fails, try to get existing results
            return self._search_by_url_query(url, headers)
        
        # Return the scan result
        scan_uuid = submit_result.get("uuid")
        
        if not scan_uuid:
            return {"error": "Failed to get scan UUID"}
        
        return {
            "source": "URLscan",
            "type": "url",
            "observable": url,
            "scan_id": scan_uuid,
            "status": "submitted",
            "message": "URL submitted for scanning. Results will be available shortly.",
            "scan_url": f"https://urlscan.io/result/{scan_uuid}/",
            "raw_data": submit_result,
        }

    def _search_by_domain(self, domain: str) -> Dict[str, Any]:
        """Search for scans of a specific domain"""
        headers = {"API-Key": self.api_key}
        params = {"q": f"domain:{domain}"}
        
        search_url = f"{self.BASE_URL}search/"
        result = self._make_request(search_url, headers=headers, params=params)
        
        if "error" in result:
            return result
        
        results = result.get("results", [])
        
        return {
            "source": "URLscan",
            "type": "domain",
            "observable": domain,
            "scan_count": len(results),
            "scans": self._extract_scan_info(results),
            "raw_data": result,
        }

    def _search_by_ip(self, ip: str) -> Dict[str, Any]:
        """Search for scans from a specific IP"""
        headers = {"API-Key": self.api_key}
        params = {"q": f"ip:{ip}"}
        
        search_url = f"{self.BASE_URL}search/"
        result = self._make_request(search_url, headers=headers, params=params)
        
        if "error" in result:
            return result
        
        results = result.get("results", [])
        
        return {
            "source": "URLscan",
            "type": "ip",
            "observable": ip,
            "scan_count": len(results),
            "scans": self._extract_scan_info(results),
            "raw_data": result,
        }

    def _search_by_url_query(self, url: str, headers: Dict) -> Dict[str, Any]:
        """Search for existing scan results for a URL"""
        params = {"q": f"page.url:{url}"}
        
        search_url = f"{self.BASE_URL}search/"
        result = self._make_request(search_url, headers=headers, params=params)
        
        if "error" in result:
            return result
        
        results = result.get("results", [])
        
        if not results:
            return {
                "source": "URLscan",
                "type": "url",
                "observable": url,
                "status": "not_found",
                "message": "No existing scans found for this URL",
            }
        
        return {
            "source": "URLscan",
            "type": "url",
            "observable": url,
            "scan_count": len(results),
            "scans": self._extract_scan_info(results),
            "raw_data": result,
        }

    @staticmethod
    def _extract_scan_info(results: list) -> list:
        """Extract relevant scan information"""
        scans = []
        
        for result in results[:10]:  # Limit to 10 results
            scan_data = {
                "scan_id": result.get("_id"),
                "url": result.get("page", {}).get("url"),
                "domain": result.get("page", {}).get("domain"),
                "ip": result.get("page", {}).get("ip"),
                "country": result.get("page", {}).get("country"),
                "asn": result.get("page", {}).get("asn"),
                "asnname": result.get("page", {}).get("asnname"),
                "timestamp": result.get("task", {}).get("time"),
                "screenshot": result.get("screenshot"),
                "scan_url": f"https://urlscan.io/result/{result.get('_id')}/",
                "malicious": result.get("stats", {}).get("malicious", 0),
                "suspicious": result.get("stats", {}).get("suspicious", 0),
                "unspecified": result.get("stats", {}).get("unspecified", 0),
            }
            scans.append(scan_data)
        
        return scans
