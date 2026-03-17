"""
ThreatFox API integration for threat intelligence
ThreatFox provides indicators of compromise (IOCs) including domains, IPs, URLs, and emails
"""

import requests
import logging
from typing import Dict, Any, Optional, List
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class ThreatFoxAPI(BaseAPIClient):
    """
    Client for ThreatFox API
    Documentation: https://threatfox.abuse.ch/
    """
    
    BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"
    
    def __init__(self, api_key: str):
        """
        Initialize ThreatFox API client
        
        Args:
            api_key: Auth-Key from ThreatFox
        """
        super().__init__(api_key)
        self.auth_key = api_key
    
    def _make_request(self, query_type: str, **kwargs) -> Dict[str, Any]:
        """
        Make authenticated request to ThreatFox API
        
        Args:
            query_type: Type of query (get_iocs, search_ioc, etc.)
            **kwargs: Additional parameters for the query
            
        Returns:
            API response dict
        """
        try:
            # Build request payload
            payload = {
                "query": query_type,
                **kwargs
            }
            
            headers = {
                "Auth-Key": self.auth_key,
                "Content-Type": "application/json"
            }
            
            logger.debug(f"ThreatFox request: {query_type} with payload: {payload}")
            
            response = requests.post(
                self.BASE_URL,
                json=payload,
                headers=headers,
                timeout=15
            )
            response.raise_for_status()
            
            result = response.json()
            logger.debug(f"ThreatFox response: {result}")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"ThreatFox API request failed: {e}")
            return {"query_status": "error", "error": str(e)}
    
    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze an observable (domain, IP, URL, email, or hash)
        Primary method called by app.py for all sources
        
        Args:
            observable: Indicator to search (domain, IP, URL, etc.)
            
        Returns:
            Dict with IOC data or empty dict if not found
        """
        try:
            result = self.search_ioc(observable)
            return result
        except Exception as e:
            logger.error(f"Error analyzing observable in ThreatFox: {e}")
            return {
                "query_status": "error", 
                "error": str(e),
                "source": "ThreatFox"
            }
    
    def search_ioc(self, ioc: str) -> Dict[str, Any]:
        """
        Search for a specific IOC (domain, IP, URL, email, or hash)
        
        Args:
            ioc: The indicator of compromise to search for
            
        Returns:
            Dict with query_status and IOC data if found
        """
        result = {
            "source": "ThreatFox",
            "observable": ioc
        }
        
        try:
            logger.info(f"🔍 ThreatFox: Searching for: {ioc}")
            
            # Try exact match first
            response = self._make_request("search_ioc", search_term=ioc, exact_match=True)
            logger.debug(f"ThreatFox exact match response status: {response.get('query_status')}")
            
            # Check if we got results
            data = response.get("data", [])
            has_results = isinstance(data, list) and len(data) > 0
            
            # If no exact results, try wildcard
            if not has_results and response.get("query_status") in ["no_result", "ok"]:
                logger.info(f"ThreatFox: No exact match found, trying wildcard search...")
                response = self._make_request("search_ioc", search_term=ioc, exact_match=False)
                logger.debug(f"ThreatFox wildcard response status: {response.get('query_status')}")
                data = response.get("data", [])
                has_results = isinstance(data, list) and len(data) > 0
            
            # Process response
            query_status = response.get("query_status", "")
            
            # Handle success (ok with data)
            if query_status == "ok" and isinstance(data, list) and len(data) > 0:
                result.update({
                    "query_status": "ok",
                    "ioc_count": len(data),
                    "iocs": data,
                    "raw_response": response
                })
                logger.info(f"✅ ThreatFox: Found {len(data)} IOC(s) for {ioc}")
                logger.debug(f"ThreatFox data structure: {result}")
            
            # Handle no results (no_result or ok with empty list)
            elif query_status == "no_result" or (query_status == "ok" and (not isinstance(data, list) or len(data) == 0)):
                result.update({
                    "query_status": "ok",
                    "ioc_count": 0,
                    "iocs": [],
                    "message": "No IOCs found in ThreatFox database"
                })
                logger.info(f"ℹ️ ThreatFox: No results found for {ioc}")
            
            # Handle errors
            else:
                result.update({
                    "query_status": "error",
                    "error": query_status if query_status else "Unknown error",
                    "raw_response": response
                })
                logger.warning(f"⚠️ ThreatFox: Error - {query_status}")
        
        except Exception as e:
            logger.error(f"❌ ThreatFox: Error searching IOC: {e}", exc_info=True)
            result.update({"query_status": "error", "error": str(e)})
        
        logger.info(f"ThreatFox returning result with keys: {list(result.keys())}")
        return result
    
    def get_recent_iocs(self, days: int = 7) -> Dict[str, Any]:
        """
        Get recent IOCs from the last X days
        
        Args:
            days: Number of days to look back (default: 7, max: 7)
            
        Returns:
            Dict with query_status and list of IOCs
        """
        # Limit to max 7 days
        days = min(days, 7)
        
        result = {
            "source": "ThreatFox",
            "query_type": "get_iocs",
            "days": days
        }
        
        try:
            response = self._make_request("get_iocs", days=days)
            
            if isinstance(response, dict):
                query_status = response.get("query_status", "")
                
                if query_status == "ok" or query_status == "no_result":
                    data = response.get("data")
                    
                    if isinstance(data, list):
                        result.update({
                            "query_status": "ok",
                            "ioc_count": len(data),
                            "iocs": data
                        })
                    else:
                        result.update({
                            "query_status": "ok",
                            "ioc_count": 0,
                            "iocs": [],
                            "message": "No IOCs found"
                        })
                else:
                    result.update({
                        "query_status": query_status,
                        "error": query_status if query_status else "Unknown error"
                    })
            else:
                result.update({"error": "Invalid response format"})
        
        except Exception as e:
            logger.error(f"Error getting ThreatFox IOCs: {e}")
            result.update({"error": str(e)})
        
        return result
    
    def get_iocs_by_malware(self, malware: str, days: int = 30) -> Dict[str, Any]:
        """
        Get IOCs associated with a specific malware family
        
        Args:
            malware: Malware family name (e.g., win.dridex)
            days: Number of days to look back (default: 30)
            
        Returns:
            Dict with IOCs matching the malware family
        """
        result = {
            "source": "ThreatFox",
            "query_type": "get_iocs_by_malware",
            "malware": malware,
            "days": days
        }
        
        try:
            response = self._make_request("get_iocs", days=days)
            
            if isinstance(response, dict):
                query_status = response.get("query_status", "")
                
                if query_status == "ok" or query_status == "no_result":
                    data = response.get("data")
                    
                    if isinstance(data, list):
                        # Filter by malware family
                        filtered = [ioc for ioc in data if ioc.get("malware") == malware or ioc.get("malware_printable", "").lower() == malware.lower()]
                        
                        result.update({
                            "query_status": "ok",
                            "ioc_count": len(filtered),
                            "iocs": filtered,
                            "total_iocs_checked": len(data)
                        })
                    else:
                        result.update({
                            "query_status": "ok",
                            "ioc_count": 0,
                            "iocs": []
                        })
                else:
                    result.update({
                        "query_status": query_status,
                        "error": query_status if query_status else "Unknown error"
                    })
            else:
                result.update({"error": "Invalid response format"})
        
        except Exception as e:
            logger.error(f"Error getting ThreatFox IOCs by malware: {e}")
            result.update({"error": str(e)})
        
        return result
    
    def get_iocs_by_threat_type(self, threat_type: str, days: int = 30) -> Dict[str, Any]:
        """
        Get IOCs by threat type (botnet_cc, phishing, malware_distribution, etc.)
        
        Args:
            threat_type: Type of threat to filter by
            days: Number of days to look back (default: 30)
            
        Returns:
            Dict with IOCs matching the threat type
        """
        result = {
            "source": "ThreatFox",
            "query_type": "get_iocs_by_threat_type",
            "threat_type": threat_type,
            "days": days
        }
        
        try:
            response = self._make_request("get_iocs", days=days)
            
            if isinstance(response, dict):
                query_status = response.get("query_status", "")
                
                if query_status == "ok" or query_status == "no_result":
                    data = response.get("data")
                    
                    if isinstance(data, list):
                        # Filter by threat type
                        filtered = [ioc for ioc in data if ioc.get("threat_type") == threat_type]
                        
                        result.update({
                            "query_status": "ok",
                            "ioc_count": len(filtered),
                            "iocs": filtered,
                            "total_iocs_checked": len(data)
                        })
                    else:
                        result.update({
                            "query_status": "ok",
                            "ioc_count": 0,
                            "iocs": []
                        })
                else:
                    result.update({
                        "query_status": query_status,
                        "error": query_status if query_status else "Unknown error"
                    })
            else:
                result.update({"error": "Invalid response format"})
        
        except Exception as e:
            logger.error(f"Error getting ThreatFox IOCs by threat type: {e}")
            result.update({"error": str(e)})
        
        return result
