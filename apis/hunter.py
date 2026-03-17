"""
Hunter.io API integration

Implements email finder, domain search, email verification, and enrichment using Hunter.io v2 API.
"""

import logging
from typing import Dict, Any
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class HunterAPI(BaseAPIClient):
    """Hunter.io API client"""

    BASE_URL = "https://api.hunter.io/v2"

    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze an observable (domain, email, or person name).
        Returns a consolidated dict with raw_data included.
        """
        # Try as domain first
        if self._is_valid_domain(observable):
            return self._domain_search(observable)
        # Try as email
        elif "@" in observable:
            return self._email_verification(observable)
        else:
            return {"error": "Hunter.io supports domain names and email addresses"}

    def _domain_search(self, domain: str) -> Dict[str, Any]:
        """Domain search - find all emails for a domain"""
        result = {"source": "Hunter.io", "type": "domain", "observable": domain}
        raw = {}

        # Domain search endpoint - get emails from domain
        url = f"{self.BASE_URL}/domain-search"
        params = {"domain": domain, "api_key": self.api_key}
        raw_domain_search = self._make_request(url, params=params)
        # Store only the data portion if available
        if isinstance(raw_domain_search, dict) and "data" in raw_domain_search:
            raw["domain_search"] = raw_domain_search["data"]
        elif raw_domain_search:
            raw["domain_search"] = raw_domain_search

        # Company enrichment - get company info
        company_url = f"{self.BASE_URL}/companies/find"
        company_params = {"domain": domain, "api_key": self.api_key}
        raw_company = self._make_request(company_url, params=company_params)
        # Store only the data portion if available
        if isinstance(raw_company, dict) and "data" in raw_company:
            raw["company"] = raw_company["data"]
        elif raw_company:
            raw["company"] = raw_company

        # Email count - quick overview of email counts by department/seniority
        count_url = f"{self.BASE_URL}/email-count"
        count_params = {"domain": domain, "api_key": self.api_key}
        raw_count = self._make_request(count_url, params=count_params)
        # Store only the data portion if available
        if isinstance(raw_count, dict) and "data" in raw_count:
            raw["email_count"] = raw_count["data"]
        elif raw_count:
            raw["email_count"] = raw_count

        # Extract emails from domain search
        emails = []
        if isinstance(raw_domain_search, dict) and "data" in raw_domain_search:
            domain_data = raw_domain_search["data"]
            if "emails" in domain_data and isinstance(domain_data["emails"], list):
                emails = domain_data["emails"]

        # Extract company data
        company_info = {}
        if isinstance(raw_company, dict) and "data" in raw_company:
            company_info = raw_company["data"]

        # Extract email count data
        email_count_data = {}
        if isinstance(raw_count, dict) and "data" in raw_count:
            email_count_data = raw_count["data"]

        result.update({
            "emails": emails,
            "emails_found": len(emails),
            "company_info": company_info,
            "email_count": email_count_data,
            "raw_data": raw,
        })

        return result

    def _email_verification(self, email: str) -> Dict[str, Any]:
        """Email verification and enrichment"""
        result = {"source": "Hunter.io", "type": "email", "observable": email}
        raw = {}

        # Email verification
        verify_url = f"{self.BASE_URL}/email-verifier"
        verify_params = {"email": email, "api_key": self.api_key}
        raw_verify = self._make_request(verify_url, params=verify_params)
        # Store only the data portion if available
        if isinstance(raw_verify, dict) and "data" in raw_verify:
            raw["verification"] = raw_verify["data"]
        elif raw_verify:
            raw["verification"] = raw_verify

        # Email enrichment - get person info
        enrich_url = f"{self.BASE_URL}/people/find"
        enrich_params = {"email": email, "api_key": self.api_key}
        raw_enrich = self._make_request(enrich_url, params=enrich_params)
        # Store only the data portion if available
        if isinstance(raw_enrich, dict) and "data" in raw_enrich:
            raw["enrichment"] = raw_enrich["data"]
        elif raw_enrich:
            raw["enrichment"] = raw_enrich

        # Extract verification data
        verification_data = {}
        if isinstance(raw_verify, dict) and "data" in raw_verify:
            verification_data = raw_verify["data"]

        # Extract person enrichment data
        person_info = {}
        company_info = {}
        if isinstance(raw_enrich, dict) and "data" in raw_enrich:
            data = raw_enrich["data"]
            person_info = {k: v for k, v in data.items() if k != "company"}
            if "company" in data:
                company_info = data["company"]

        result.update({
            "verification": verification_data,
            "person": person_info,
            "company": company_info,
            "raw_data": raw,
        })

        return result
