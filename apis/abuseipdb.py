"""
AbuseIPDB API integration
"""

import logging
from typing import Dict, Any
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class AbuseIPDBAPI(BaseAPIClient):
    """AbuseIPDB API client"""

    BASE_URL = "https://api.abuseipdb.com/api/v2/"

    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze IP using AbuseIPDB API
        
        Args:
            observable: IP address
            
        Returns:
            Analysis results
        """
        if not self._is_valid_ip(observable):
            return {"error": "AbuseIPDB only supports IP addresses"}
        
        return self._check_ip(observable)

    def _check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation"""
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": "",
        }
        
        url = f"{self.BASE_URL}check"
        result = self._make_request(url, headers=headers, params=params)
        
        if "error" in result:
            return result
        
        data = result.get("data", {})
        
        return {
            "source": "AbuseIPDB",
            "type": "ip",
            "observable": ip,
            "ip_address": data.get("ipAddress"),
            "is_whitelisted": data.get("isWhitelisted"),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country_code": data.get("countryCode"),
            "country_name": data.get("countryName"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "hostnames": data.get("hostnames", []),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "reports": self._extract_reports(data.get("reports", [])),
            "raw_data": result,
        }

    @staticmethod
    def _extract_reports(reports: list) -> list:
        """Extract recent reports"""
        formatted_reports = []
        for report in reports[:5]:  # Limit to 5 recent reports
            formatted_reports.append({
                "reporting_date": report.get("reportedAt"),
                "comment": report.get("comment", "")[:100],
                "categories": report.get("categories", []),
                "reporter": report.get("reporterCountCode"),
            })
        return formatted_reports
