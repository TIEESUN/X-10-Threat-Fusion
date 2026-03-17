"""
VirusTotal API integration
"""

import logging
from typing import Dict, Any
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class VirusTotalAPI(BaseAPIClient):
    """VirusTotal API client"""

    BASE_URL = "https://www.virustotal.com/api/v3/"

    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze observable using VirusTotal API
        
        Args:
            observable: IP, domain, URL, or hash
            
        Returns:
            Analysis results
        """
        obs_type = self._classify_observable(observable)
        
        if obs_type == "unknown":
            return {"error": "Invalid observable format"}
        
        if obs_type == "ip":
            return self._get_ip_report(observable)
        elif obs_type == "domain":
            return self._get_domain_report(observable)
        elif obs_type == "url":
            return self._get_url_report(observable)
        elif obs_type == "hash":
            return self._get_file_report(observable)

    def _get_ip_report(self, ip: str) -> Dict[str, Any]:
        """Get IP reputation report"""
        headers = {"x-apikey": self.api_key}
        url = f"{self.BASE_URL}ip_addresses/{ip}"
        
        result = self._make_request(url, headers=headers)
        
        if "error" in result:
            return result
        
        # Extract relevant data
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        
        return {
            "source": "VirusTotal",
            "type": "ip",
            "observable": ip,
            "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
            "country": attributes.get("country"),
            "asn": attributes.get("asn"),
            "as_owner": attributes.get("as_owner"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "raw_data": result,
        }

    def _get_domain_report(self, domain: str) -> Dict[str, Any]:
        """Get domain reputation report"""
        headers = {"x-apikey": self.api_key}
        url = f"{self.BASE_URL}domains/{domain}"
        
        result = self._make_request(url, headers=headers)
        
        if "error" in result:
            return result
        
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        
        return {
            "source": "VirusTotal",
            "type": "domain",
            "observable": domain,
            "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
            "categories": attributes.get("categories", {}),
            "last_dns_records": attributes.get("last_dns_records", []),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "raw_data": result,
        }

    def _get_url_report(self, url: str) -> Dict[str, Any]:
        """Get URL reputation report"""
        import base64
        
        headers = {"x-apikey": self.api_key}
        
        # VirusTotal needs URL ID (base64 encoded)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"{self.BASE_URL}urls/{url_id}"
        
        result = self._make_request(api_url, headers=headers)
        
        if "error" in result:
            return result
        
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        
        return {
            "source": "VirusTotal",
            "type": "url",
            "observable": url,
            "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
            "categories": attributes.get("categories", {}),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "raw_data": result,
        }

    def _get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """Get file/hash reputation report"""
        headers = {"x-apikey": self.api_key}
        url = f"{self.BASE_URL}files/{file_hash}"
        
        result = self._make_request(url, headers=headers)
        
        if "error" in result:
            return result
        
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        
        return {
            "source": "VirusTotal",
            "type": "file",
            "observable": file_hash,
            "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
            "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
            "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
            "file_size": attributes.get("size"),
            "file_type": attributes.get("type_description"),
            "tags": attributes.get("tags", []),
            "meaningful_name": attributes.get("meaningful_name"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "raw_data": result,
        }
