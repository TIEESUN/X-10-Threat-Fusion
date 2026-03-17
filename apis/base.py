"""
Base API client with common functionality
"""

import logging
import re
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class BaseAPIClient(ABC):
    """Base class for all API integrations"""

    def __init__(self, api_key: str = None, timeout: int = 30):
        """
        Initialize API client
        
        Args:
            api_key: API key for authentication
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.timeout = timeout
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create requests session with retry strategy"""
        session = requests.Session()
        
        # Base retry configuration
        retry_config = {
            "total": 3,
            "backoff_factor": 1,
            "status_forcelist": [429, 500, 502, 503, 504],
        }
        
        # Handle urllib3 version differences
        # urllib3 2.0+ uses 'allowed_methods', older versions use 'method_whitelist'
        try:
            retry_strategy = Retry(
                allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
                **retry_config
            )
        except TypeError:
            # Fallback for older urllib3 versions (< 2.0)
            retry_strategy = Retry(
                method_whitelist=["HEAD", "GET", "OPTIONS", "POST"],
                **retry_config
            )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    @abstractmethod
    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze an observable
        
        Args:
            observable: IP, domain, URL, or hash to analyze
            
        Returns:
            Dictionary with analysis results
        """
        pass

    def _make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Make HTTP request with error handling
        
        Args:
            url: API endpoint URL
            method: HTTP method (GET, POST, etc.)
            headers: Request headers
            params: Query parameters
            data: Form data
            json_data: JSON body
            
        Returns:
            Response JSON or error dict
        """
        try:
            if method.upper() == "GET":
                response = self.session.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=self.timeout,
                )
            elif method.upper() == "POST":
                response = self.session.post(
                    url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json_data,
                    timeout=self.timeout,
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            
            # Try to parse as JSON
            try:
                return response.json()
            except ValueError:
                return {"raw_response": response.text}

        except requests.exceptions.Timeout:
            logger.error(f"Timeout requesting {url}")
            return {"error": "Request timeout", "status": "timeout"}
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error requesting {url}")
            return {"error": "Connection error", "status": "connection_error"}
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error {e.response.status_code}: {url}")
            if e.response.status_code == 401:
                return {"error": "Unauthorized - Invalid API key", "status": "unauthorized"}
            elif e.response.status_code == 403:
                return {"error": "Forbidden - Invalid API key or insufficient permissions", "status": "forbidden"}
            elif e.response.status_code == 404:
                return {"error": "Not found", "status": "not_found"}
            elif e.response.status_code == 429:
                return {"error": "Rate limited", "status": "rate_limited"}
            else:
                return {"error": str(e), "status": "http_error"}
        except Exception as e:
            logger.error(f"Error requesting {url}: {str(e)}")
            return {"error": str(e), "status": "unknown_error"}

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate IP address"""
        pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(pattern, ip):
            parts = ip.split(".")
            return all(0 <= int(part) <= 255 for part in parts)
        return False

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """Validate domain"""
        pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        return bool(re.match(pattern, domain, re.IGNORECASE))

    @staticmethod
    def _is_valid_url(url: str) -> bool:
        """Validate URL"""
        pattern = r"^https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)$"
        return bool(re.match(pattern, url))

    @staticmethod
    def _is_hash(hash_val: str) -> str:
        """Identify hash type (md5, sha1, sha256)"""
        # Only consider it a hash if it contains only hex characters
        if not re.match(r'^[a-fA-F0-9]+$', hash_val):
            return None
        
        hash_len = len(hash_val)
        if hash_len == 32:
            return "md5"
        elif hash_len == 40:
            return "sha1"
        elif hash_len == 64:
            return "sha256"
        return None

    def _classify_observable(self, observable: str) -> str:
        """Classify observable type"""
        if self._is_valid_ip(observable):
            return "ip"
        elif self._is_valid_url(observable):
            return "url"
        elif self._is_hash(observable):
            return "hash"
        elif self._is_valid_domain(observable):
            return "domain"
        else:
            return "unknown"
