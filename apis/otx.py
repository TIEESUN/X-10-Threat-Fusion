"""
AlienVault OTX API integration - FIXED for slice error
"""

import logging
from typing import Dict, Any, List
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class OTXAlienVaultAPI(BaseAPIClient):
    """AlienVault OTX API client"""

    BASE_URL = "https://otx.alienvault.com/api/v1/"

    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze observable using OTX API
        
        Args:
            observable: IP, domain, or hash
            
        Returns:
            Complete analysis results
        """
        obs_type = self._classify_observable(observable)
        
        if obs_type == "ip":
            return self._get_ip_comprehensive(observable)
        elif obs_type == "domain":
            return self._get_domain_comprehensive(observable)
        elif obs_type == "hash":
            return self._get_file_comprehensive(observable)
        else:
            return {"error": "Unsupported observable type for OTX"}

    def _get_ip_comprehensive(self, ip: str) -> Dict[str, Any]:
        """Get comprehensive IP data from multiple OTX endpoints"""
        headers = {
            "X-OTX-API-KEY": self.api_key,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        
        # Start with general endpoint
        general_url = f"{self.BASE_URL}indicators/IPv4/{ip}/general"
        general = self._make_request(general_url, headers=headers)
        
        # Check for errors
        if "error" in general:
            return {
                "error": general.get("error"),
                "source": "AlienVault OTX",
                "type": "ip",
                "observable": ip,
            }
        
        # Check for HTML response
        if "raw_response" in general:
            raw = str(general.get("raw_response", ""))
            if "<html" in raw.lower() or "<!doctype" in raw.lower():
                return {
                    "error": "Invalid API key - received HTML response",
                    "source": "AlienVault OTX",
                    "type": "ip",
                    "observable": ip,
                }
        
        # Extract pulse info safely
        pulse_info = general.get("pulse_info", {})
        if pulse_info is None:
            pulse_info = {}
        
        pulses = self._extract_pulses(pulse_info)
        pulse_count = 0
        if isinstance(pulse_info, dict):
            pulse_count = pulse_info.get("count", 0)
        
        # Build base result
        result = {
            "source": "AlienVault OTX",
            "type": "ip",
            "observable": ip,
            "reputation": general.get("reputation", 0),
            "validity": general.get("validity"),
            "type_title": general.get("type_title"),
            "whois": general.get("whois"),
            "asn": general.get("asn"),
            "pulses": pulses,
            "pulse_count": pulse_count,
        }
        
        # Try additional endpoints
        self._add_geo_data(result, f"{self.BASE_URL}indicators/IPv4/{ip}/geo", headers)
        self._add_malware_data(result, f"{self.BASE_URL}indicators/IPv4/{ip}/malware", headers)
        self._add_url_data(result, f"{self.BASE_URL}indicators/IPv4/{ip}/url_list", headers)
        self._add_passive_dns_data(result, f"{self.BASE_URL}indicators/IPv4/{ip}/passive_dns", headers)
        
        return result

    def _get_domain_comprehensive(self, domain: str) -> Dict[str, Any]:
        """Get comprehensive domain data from multiple OTX endpoints"""
        headers = {
            "X-OTX-API-KEY": self.api_key,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        
        # Start with general endpoint
        general_url = f"{self.BASE_URL}indicators/domain/{domain}/general"
        general = self._make_request(general_url, headers=headers)
        
        # Check for errors
        if "error" in general:
            return {
                "error": general.get("error"),
                "source": "AlienVault OTX",
                "type": "domain",
                "observable": domain,
            }
        
        # Check for HTML response
        if "raw_response" in general:
            raw = str(general.get("raw_response", ""))
            if "<html" in raw.lower() or "<!doctype" in raw.lower():
                return {
                    "error": "Invalid API key - received HTML response",
                    "source": "AlienVault OTX",
                    "type": "domain",
                    "observable": domain,
                }
        
        # Extract pulse info safely
        pulse_info = general.get("pulse_info", {})
        if pulse_info is None:
            pulse_info = {}
        
        pulses = self._extract_pulses(pulse_info)
        pulse_count = 0
        if isinstance(pulse_info, dict):
            pulse_count = pulse_info.get("count", 0)
        
        # Build base result
        result = {
            "source": "AlienVault OTX",
            "type": "domain",
            "observable": domain,
            "reputation": general.get("reputation", 0),
            "validity": general.get("validity"),
            "type_title": general.get("type_title"),
            "alexa_rank": general.get("alexa", ""),
            "pulses": pulses,
            "pulse_count": pulse_count,
        }
        
        # Try additional endpoints
        self._add_geo_data(result, f"{self.BASE_URL}indicators/domain/{domain}/geo", headers)
        self._add_malware_data(result, f"{self.BASE_URL}indicators/domain/{domain}/malware", headers)
        self._add_url_data(result, f"{self.BASE_URL}indicators/domain/{domain}/url_list", headers)
        self._add_passive_dns_data(result, f"{self.BASE_URL}indicators/domain/{domain}/passive_dns", headers)
        self._add_whois_data(result, f"{self.BASE_URL}indicators/domain/{domain}/whois", headers)
        self._add_http_scans_data(result, f"{self.BASE_URL}indicators/domain/{domain}/http_scans", headers)
        # Note: related endpoint removed as it returns 404
        
        return result

    def _get_file_comprehensive(self, file_hash: str) -> Dict[str, Any]:
        """Get comprehensive file data from OTX"""
        hash_type = self._is_hash(file_hash)
        if not hash_type:
            return {"error": "Invalid hash format"}
        
        headers = {
            "X-OTX-API-KEY": self.api_key,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        
        # Start with general endpoint
        general_url = f"{self.BASE_URL}indicators/file/{file_hash}/general"
        general = self._make_request(general_url, headers=headers)
        
        # Check for errors
        if "error" in general:
            return {
                "error": general.get("error"),
                "source": "AlienVault OTX",
                "type": "file",
                "observable": file_hash,
                "hash_type": hash_type,
            }
        
        # Check for HTML response
        if "raw_response" in general:
            raw = str(general.get("raw_response", ""))
            if "<html" in raw.lower() or "<!doctype" in raw.lower():
                return {
                    "error": "Invalid API key - received HTML response",
                    "source": "AlienVault OTX",
                    "type": "file",
                    "observable": file_hash,
                    "hash_type": hash_type,
                }
        
        # Extract pulse info safely
        pulse_info = general.get("pulse_info", {})
        if pulse_info is None:
            pulse_info = {}
        
        pulses = self._extract_pulses(pulse_info)
        pulse_count = 0
        if isinstance(pulse_info, dict):
            pulse_count = pulse_info.get("count", 0)
        
        result = {
            "source": "AlienVault OTX",
            "type": "file",
            "observable": file_hash,
            "hash_type": hash_type,
            "reputation": general.get("reputation"),
            "file_class": general.get("file_class"),
            "file_type": general.get("file_type"),
            "pulses": pulses,
            "pulse_count": pulse_count,
        }
        
        # Try analysis endpoint
        try:
            analysis_url = f"{self.BASE_URL}indicators/file/{file_hash}/analysis"
            analysis = self._make_request(analysis_url, headers=headers)
            if "error" not in analysis and analysis:
                result["analysis_info"] = analysis.get("analysis", {})
        except Exception as e:
            logger.debug(f"Failed to fetch analysis for file: {e}")
        
        return result

    def _add_geo_data(self, result: Dict, url: str, headers: Dict) -> None:
        """Add geographic data to result"""
        try:
            data = self._make_request(url, headers=headers)
            if "error" not in data and data:
                result["country_name"] = data.get("country_name")
                result["country_code"] = data.get("country_code")
                result["city"] = data.get("city")
                result["latitude"] = data.get("latitude")
                result["longitude"] = data.get("longitude")
        except Exception as e:
            logger.debug(f"Failed to fetch geo data: {e}")

    def _add_malware_data(self, result: Dict, url: str, headers: Dict) -> None:
        """Add malware data to result"""
        try:
            data = self._make_request(url, headers=headers)
            if "error" not in data and data:
                result["malware_samples"] = self._extract_malware_samples(data)
        except Exception as e:
            logger.debug(f"Failed to fetch malware data: {e}")

    def _add_url_data(self, result: Dict, url: str, headers: Dict) -> None:
        """Add URL list data to result"""
        try:
            data = self._make_request(url, headers=headers)
            if "error" not in data and data:
                result["associated_urls"] = self._extract_url_list(data)
        except Exception as e:
            logger.debug(f"Failed to fetch URL data: {e}")

    def _add_passive_dns_data(self, result: Dict, url: str, headers: Dict) -> None:
        """Add passive DNS data to result"""
        try:
            data = self._make_request(url, headers=headers)
            if "error" not in data and data:
                result["passive_dns_records"] = self._extract_passive_dns(data)
        except Exception as e:
            logger.debug(f"Failed to fetch passive DNS data: {e}")

    def _add_whois_data(self, result: Dict, url: str, headers: Dict) -> None:
        """Add WHOIS data to result"""
        try:
            data = self._make_request(url, headers=headers)
            if "error" not in data and data:
                whois_text = self._extract_whois(data)
                if whois_text:
                    result["whois"] = whois_text
        except Exception as e:
            logger.debug(f"Failed to fetch WHOIS data: {e}")

    def _add_http_scans_data(self, result: Dict, url: str, headers: Dict) -> None:
        """Add HTTP scans data to result"""
        try:
            data = self._make_request(url, headers=headers)
            if "error" not in data and data:
                scans = self._extract_http_scans(data)
                if scans:
                    result["http_scans"] = scans
        except Exception as e:
            logger.debug(f"Failed to fetch HTTP scans data: {e}")

    def _extract_pulses(self, pulse_info: Dict) -> List[Dict]:
        """Extract and format pulse information"""
        if not pulse_info or not isinstance(pulse_info, dict):
            return []
        
        pulses_list = pulse_info.get("pulses", [])
        if not isinstance(pulses_list, list):
            return []
        
        pulses = []
        # Limit to first 10 pulses
        for pulse in pulses_list[0:10]:
            if not isinstance(pulse, dict):
                continue
            
            pulse_data = {
                "id": pulse.get("id"),
                "name": pulse.get("name"),
                "description": str(pulse.get("description", ""))[0:200],
                "created": pulse.get("created"),
                "modified": pulse.get("modified"),
                "author": pulse.get("author_name"),
                "adversary": pulse.get("adversary"),
                "malware_families": pulse.get("malware_families", []),
                "attack_ids": pulse.get("attack_ids", []),
                "industries": pulse.get("industries", []),
                "url": f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
            }
            pulses.append(pulse_data)
        
        return pulses

    def _extract_malware_samples(self, malware_data: Dict) -> List[Dict]:
        """Extract malware sample information"""
        if not malware_data or not isinstance(malware_data, dict):
            return []
        
        data_list = malware_data.get("data", [])
        if not isinstance(data_list, list):
            return []
        
        samples = []
        for sample in data_list[0:10]:
            if not isinstance(sample, dict):
                continue
            
            # Normalize detections to a count
            detections = sample.get("detections")
            detection_count = 0
            
            if isinstance(detections, dict):
                # If detections is a dict (antivirus results), count the keys
                detection_count = len(detections)
            elif isinstance(detections, list):
                # If detections is a list, count the items
                detection_count = len(detections)
            elif isinstance(detections, int):
                # If it's already an int, use it
                detection_count = detections
            elif detections is not None:
                # Try to convert to int
                try:
                    detection_count = int(detections)
                except (TypeError, ValueError):
                    detection_count = 0
            
            samples.append({
                "hash": sample.get("hash"),
                "detections": detection_count,
                "date": sample.get("date"),
            })
        
        return samples

    def _extract_url_list(self, url_data: Dict) -> List[Dict]:
        """Extract associated URL information"""
        if not url_data or not isinstance(url_data, dict):
            return []
        
        url_list = url_data.get("url_list", [])
        if not isinstance(url_list, list):
            return []
        
        urls = []
        for url_entry in url_list[0:20]:
            if not isinstance(url_entry, dict):
                continue
            
            urls.append({
                "url": url_entry.get("url"),
                "hostname": url_entry.get("hostname"),
                "domain": url_entry.get("domain"),
                "date": url_entry.get("date"),
            })
        
        return urls

    def _extract_passive_dns(self, dns_data: Dict) -> List[Dict]:
        """Extract passive DNS records"""
        if not dns_data or not isinstance(dns_data, dict):
            return []
        
        dns_list = dns_data.get("passive_dns", [])
        if not isinstance(dns_list, list):
            return []
        
        records = []
        for record in dns_list[0:20]:
            if not isinstance(record, dict):
                continue
            
            records.append({
                "hostname": record.get("hostname"),
                "address": record.get("address"),
                "record_type": record.get("record_type"),
                "first": record.get("first"),
                "last": record.get("last"),
            })
        
        return records

    def _extract_whois(self, whois_data: Dict) -> str:
        """Extract WHOIS information and format as readable table"""
        if not whois_data or not isinstance(whois_data, dict):
            logger.debug(f"WHOIS data is None or not dict: {type(whois_data)}")
            return None
        
        # The data comes in format: {'data': [{'key': ..., 'name': ..., 'value': ...}], 'related': [...]}
        data_list = whois_data.get("data", [])
        
        if not isinstance(data_list, list) or len(data_list) == 0:
            logger.debug("WHOIS data list is empty or invalid")
            return None
        
        # Format as table
        whois_lines = []
        whois_lines.append("=" * 80)
        whois_lines.append("WHOIS INFORMATION")
        whois_lines.append("=" * 80)
        
        for item in data_list:
            if isinstance(item, dict):
                name = item.get('name', '')
                value = item.get('value', '')
                if name and value:
                    whois_lines.append(f"{name:30s}: {value}")
        
        # Add related domains info
        related = whois_data.get("related", [])
        if related and len(related) > 0:
            whois_lines.append("")
            whois_lines.append("=" * 80)
            whois_lines.append(f"RELATED DOMAINS (showing first 20 of {len(related)})")
            whois_lines.append("=" * 80)
            for idx, rel in enumerate(related[0:20], 1):
                if isinstance(rel, dict):
                    domain = rel.get('domain', '')
                    related_val = rel.get('related', '')
                    whois_lines.append(f"{idx:3d}. {domain:40s} (via {related_val})")
        
        return "\n".join(whois_lines)

    def _extract_http_scans(self, scan_data: Dict) -> List[Dict]:
        """Extract HTTP scan information"""
        if not scan_data or not isinstance(scan_data, dict):
            logger.debug(f"HTTP scan data is None or not dict: {type(scan_data)}")
            return []
        
        # The data comes in format: {'data': [{'key': ..., 'name': ..., 'value': ...}], 'count': N}
        data_list = scan_data.get("data", [])
        
        if not isinstance(data_list, list):
            logger.debug(f"HTTP scan data is not list: {type(data_list)}")
            return []
        
        logger.debug(f"HTTP scan data list length: {len(data_list)}")
        
        # Group by scan (items with same port/protocol)
        scans = []
        current_scan = {}
        
        for item in data_list:
            if not isinstance(item, dict):
                continue
            
            name = item.get('name', '')
            value = item.get('value', '')
            
            # Convert to readable format
            scans.append({
                "field": name,
                "value": value,
            })
        
        logger.debug(f"Extracted {len(scans)} HTTP scan fields")
        return scans

    def _extract_related_domains(self, related_data: Dict) -> List[Dict]:
        """Extract related domains information"""
        if not related_data or not isinstance(related_data, dict):
            logger.debug(f"Related domains data is None or not dict: {type(related_data)}")
            return []
        
        logger.debug(f"Related domains data keys: {related_data.keys()}")
        
        # The related endpoint can return data in different formats
        related_list = related_data.get("data", [])
        
        # Sometimes it's under a different key
        if not related_list:
            related_list = related_data.get("related", [])
        
        if not isinstance(related_list, list):
            logger.debug(f"Related domains data is not list: {type(related_list)}")
            return []
        
        logger.debug(f"Related domains list length: {len(related_list)}")
        
        domains = []
        for item in related_list[0:20]:
            if isinstance(item, str):
                # Sometimes it's just a list of domain strings
                domains.append({
                    "domain": item,
                    "pulses": 0,
                })
            elif isinstance(item, dict):
                # Skip items with no domain
                domain_name = item.get("domain") or item.get("hostname")
                if not domain_name:
                    continue
                
                domains.append({
                    "domain": domain_name,
                    "pulses": item.get("pulses", 0),
                })
        
        logger.debug(f"Extracted {len(domains)} related domains")
        return domains
