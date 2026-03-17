"""
YARAify API Integration - FIXED VERSION
Malware analysis and YARA rule detection
https://yaraify.abuse.ch/api/
"""

import requests
import time
from typing import Dict, Any, Optional, List
import logging
import json

logger = logging.getLogger(__name__)


class YARAifyAPI:
    """YARAify API client for malware analysis and YARA rule detection"""
    
    def __init__(self, api_key: str):
        """
        Initialize YARAify API client
        
        Args:
            api_key: YARAify API key from https://yaraify.abuse.ch/
        """
        self.api_key = api_key
        self.base_url = "https://yaraify-api.abuse.ch/api/v1/"
        self.session = requests.Session()
        
        # Set up session headers
        self.session.headers.update({
            'User-Agent': 'X-10 ThreatFusion Intelligence Aggregator',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Auth-Key': self.api_key
        })
    
    def _make_request(self, query: str, selector: str = "basic") -> Optional[Dict[str, Any]]:
        """
        Make API request to YARAify
        
        Args:
            query: Hash to query (MD5, SHA1, SHA256)
            selector: Query selector (basic, detailed, all)
            
        Returns:
            API response data or None
        """
        try:
            payload = {
                "query": "lookup_hash",
                "search_term": query,
                "selector": selector
            }
            
            response = self.session.post(
                self.base_url,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                logger.warning("YARAify rate limit hit, waiting...")
                time.sleep(60)
                return None
            else:
                logger.error(f"YARAify API error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"YARAify request failed: {e}")
            return None
        except Exception as e:
            logger.error(f"YARAify unexpected error: {e}")
            return None
    
    def analyze_hash(self, hash_value: str) -> Dict[str, Any]:
        """
        Analyze a hash using YARAify API
        
        Args:
            hash_value: MD5, SHA1, or SHA256 hash
            
        Returns:
            Analysis results
        """
        logger.info(f"Analyzing hash {hash_value} with YARAify")
        
        try:
            result = self._make_request(hash_value, "basic")
            
            if not result:
                return {"error": "Failed to query YARAify API"}
            
            if result.get("query_status") == "hash_not_found":
                return {
                    "query_status": "hash_not_found",
                    "message": "Hash not found in YARAify database",
                    "observable": hash_value,
                    "type": "hash"
                }
            
            if result.get("query_status") != "ok":
                return {
                    "query_status": "error",
                    "error": result.get("message", "Unknown error"),
                    "observable": hash_value,
                    "type": "hash"
                }
            
            # Parse the results
            parsed_result = self._parse_results(result, hash_value)
            return parsed_result
            
        except Exception as e:
            logger.error(f"Error analyzing hash {hash_value}: {e}")
            return {"error": str(e)}
    
    def _parse_results(self, raw_data: Dict[str, Any], hash_value: str) -> Dict[str, Any]:
        """Parse YARAify results based on actual API response structure"""
        try:
            parsed = {
                "query_status": "ok",
                "observable": hash_value,
                "type": "hash",
                "raw_data": raw_data
            }
            
            logger.info(f"Raw YARAify response keys: {raw_data.keys()}")
            logger.info(f"Full raw data (first 1000 chars): {json.dumps(raw_data, indent=2, default=str)[:1000]}")
            
            # Based on your console output, the structure is:
            # {"query_status": "ok", "data": {"metadata": {...}, "tasks": [...]}}
            
            if "data" in raw_data:
                data_section = raw_data["data"]
                metadata = {}
                
                # Check if we have metadata (your console shows this structure)
                if "metadata" in data_section:
                    metadata = data_section["metadata"]
                    
                    # Extract file information from metadata
                    parsed["file_name"] = metadata.get("file_name", "")
                    parsed["file_size"] = metadata.get("file_size", 0)
                    parsed["file_type"] = metadata.get("file_type", "")
                    parsed["mime_type"] = metadata.get("file_type_mime", "")
                    
                    # Extract hashes
                    parsed["md5_hash"] = metadata.get("md5_hash", "")
                    parsed["sha1_hash"] = metadata.get("sha1_hash", "")
                    parsed["sha256_hash"] = metadata.get("sha256_hash", "")
                    
                    # Additional hashes
                    parsed["sha3_384"] = metadata.get("sha3_384", "")
                    parsed["imphash"] = metadata.get("imphash", "")
                    parsed["ssdeep"] = metadata.get("ssdeep", "")
                    parsed["tlsh"] = metadata.get("tlsh", "")
                    parsed["telfhash"] = metadata.get("telfhash", "")
                    parsed["gimphash"] = metadata.get("gimphash", "")
                    parsed["dhash_icon"] = metadata.get("dhash_icon", "")
                    
                    # Temporal data
                    parsed["first_seen"] = metadata.get("first_seen", "")
                    parsed["last_seen"] = metadata.get("last_seen", "")
                    parsed["sightings"] = metadata.get("sightings", 0)
                    
                    # File download (check if available)
                    parsed["file_download"] = metadata.get("file_download", "")
                    
                # Check for tasks which might contain additional info
                if "tasks" in data_section and isinstance(data_section["tasks"], list):
                    tasks = data_section["tasks"]
                    yara_rules = []
                    clamav_results = []
                    
                    for task in tasks:
                        if isinstance(task, dict):
                            # Check for static_results in tasks
                            if "static_results" in task and isinstance(task["static_results"], list):
                                for static_result in task["static_results"]:
                                    if isinstance(static_result, dict) and "rule_name" in static_result:
                                        yara_rules.append(static_result)
                            
                            # Check for ClamAV results in tasks
                            if "clamav_results" in task and isinstance(task["clamav_results"], list):
                                clamav_results.extend(task["clamav_results"])
                    
                    parsed["yara_rules"] = len(yara_rules)
                    parsed["yara_rules_list"] = yara_rules
                    
                    # Extract YARA rule names and authors
                    rule_names = []
                    rule_authors = set()
                    for rule in yara_rules:
                        if isinstance(rule, dict):
                            rule_name = rule.get("rule_name", "")
                            if rule_name:
                                rule_names.append(rule_name)
                            author = rule.get("author", "")
                            if author:
                                rule_authors.add(author)
                    
                    parsed["yara_rule_names"] = rule_names
                    parsed["yara_authors"] = list(rule_authors)
                    
                    # ClamAV results
                    parsed["clamav_results"] = clamav_results
                    if clamav_results and len(clamav_results) > 0 and isinstance(clamav_results[0], str):
                        parsed["clamav_signature"] = clamav_results[0]
                    else:
                        parsed["clamav_signature"] = ""
                    
                    # Detection information
                    if yara_rules:
                        # Look for malware family indicators in YARA rules
                        malware_families = []
                        for rule in yara_rules:
                            if isinstance(rule, dict):
                                rule_name = (rule.get("rule_name") or "").lower()
                                description = (rule.get("description") or "").lower()
                                
                                # Common malware family indicators
                                rule_info = rule_name + description
                                if any(keyword in rule_info for keyword in ["miner", "ransomware", "trojan", "backdoor", "botnet"]):
                                    if "miner" in rule_info:
                                        malware_families.append("CoinMiner")
                                    elif "ransomware" in rule_info:
                                        malware_families.append("Ransomware")
                                    elif "trojan" in rule_info:
                                        malware_families.append("Trojan")
                                    elif "backdoor" in rule_info:
                                        malware_families.append("Backdoor")
                                    elif "botnet" in rule_info:
                                        malware_families.append("Botnet")
                        
                        if malware_families:
                            parsed["malware_family"] = malware_families[0]
                            parsed["signature"] = f"YARA:{malware_families[0]}"
                        elif rule_names:
                            parsed["signature"] = f"YARA:{rule_names[0]}"
                            parsed["malware_family"] = ""
                        else:
                            parsed["signature"] = ""
                            parsed["malware_family"] = ""
                    else:
                        parsed["signature"] = ""
                        parsed["malware_family"] = ""
                    
                    # Reporter information (check both metadata and tasks)
                    parsed["reporter"] = metadata.get("reporter", "")
                    
                    # Comments
                    parsed["comments"] = 0
                    parsed["comments_list"] = []
                    
                    # Total results
                    parsed["total_results"] = len(tasks) if isinstance(tasks, list) else 1
                    
                    # Threat classification
                    if parsed.get("signature") or parsed.get("yara_rules", 0) > 0:
                        if "miner" in parsed.get("signature", "").lower():
                            parsed["threat_level"] = "high"
                            parsed["is_malicious"] = True
                        elif parsed.get("yara_rules", 0) > 5:  # Many YARA rules = high confidence
                            parsed["threat_level"] = "high"
                            parsed["is_malicious"] = True
                        elif parsed.get("yara_rules", 0) > 0:
                            parsed["threat_level"] = "medium"
                            parsed["is_malicious"] = True
                        else:
                            parsed["threat_level"] = "low"
                            parsed["is_malicious"] = False
                    else:
                        parsed["threat_level"] = "low"
                        parsed["is_malicious"] = False
                    
                    # Intelligence data
                    parsed["intelligence"] = {
                        "clamav": parsed.get("clamav_signature", ""),
                        "yara_matches": parsed.get("yara_rules", 0),
                        "sightings": parsed.get("sightings", 0),
                        "file_names": [parsed.get("file_name", "")] if parsed.get("file_name") else []
                    }
                    
                    logger.info(f"Successfully parsed YARAify result with {parsed.get('yara_rules', 0)} YARA rules")
                    return parsed
            
            else:
                # No metadata or tasks found - try legacy parsing
                logger.warning("No 'metadata' or 'tasks' found in YARAify response, trying legacy parsing")
                return self._parse_legacy_format(raw_data, hash_value)
                
        except Exception as e:
            logger.error(f"Error parsing YARAify results: {e}", exc_info=True)
            return {
                "query_status": "error",
                "error": f"Failed to parse results: {str(e)}",
                "observable": hash_value,
                "type": "hash",
                "raw_data": raw_data
            }
    
    def _parse_legacy_format(self, raw_data: Dict[str, Any], hash_value: str) -> Dict[str, Any]:
        """Fallback parsing for older response formats"""
        try:
            parsed = {
                "query_status": "ok",
                "observable": hash_value,
                "type": "hash",
                "raw_data": raw_data
            }
            
            # Try the old format where data is an array
            if "data" in raw_data and isinstance(raw_data["data"], list) and len(raw_data["data"]) > 0:
                first_item = raw_data["data"][0]
                
                # Extract file information
                parsed["file_name"] = first_item.get("file_name", "")
                parsed["file_size"] = first_item.get("file_size", 0)
                parsed["file_type"] = first_item.get("file_type", "")
                parsed["mime_type"] = first_item.get("file_type_mime", "")
                
                # Extract hashes
                parsed["md5_hash"] = first_item.get("md5_hash", "")
                parsed["sha1_hash"] = first_item.get("sha1_hash", "")
                parsed["sha256_hash"] = first_item.get("sha256_hash", "")
                
                # Additional hashes
                parsed["sha3_384"] = first_item.get("sha3_384", "")
                parsed["imphash"] = first_item.get("imphash", "")
                parsed["ssdeep"] = first_item.get("ssdeep", "")
                parsed["tlsh"] = first_item.get("tlsh", "")
                parsed["telfhash"] = first_item.get("telfhash", "")
                parsed["gimphash"] = first_item.get("gimphash", "")
                parsed["dhash_icon"] = first_item.get("dhash_icon", "")
                
                # Temporal data
                parsed["first_seen"] = first_item.get("first_seen", "")
                parsed["last_seen"] = first_item.get("last_seen", "")
                parsed["sightings"] = first_item.get("sightings", 0)
                
                # File download
                parsed["file_download"] = first_item.get("file_download", "")
                
                # Set defaults for other fields
                parsed["yara_rules"] = 0
                parsed["yara_rules_list"] = []
                parsed["yara_rule_names"] = []
                parsed["yara_authors"] = []
                parsed["clamav_signature"] = ""
                parsed["signature"] = ""
                parsed["malware_family"] = ""
                parsed["threat_level"] = "low"
                parsed["is_malicious"] = False
                
                return parsed
            
            # If neither format works, return error
            return {
                "query_status": "no_data",
                "message": "Unable to parse YARAify response format",
                "observable": hash_value,
                "type": "hash",
                "raw_data": raw_data
            }
            
        except Exception as e:
            logger.error(f"Error in legacy parsing: {e}")
            return {
                "query_status": "error",
                "error": f"Legacy parsing failed: {str(e)}",
                "observable": hash_value,
                "type": "hash",
                "raw_data": raw_data
            }
    
    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Main analysis method - compatible with other API clients
        
        Args:
            observable: Hash to analyze
            
        Returns:
            Analysis results
        """
        obs_type = self._classify_observable(observable)
        
        if obs_type not in ["MD5", "SHA1", "SHA256"]:
            return {
                "error": "YARAify only supports hash analysis (MD5, SHA1, SHA256)",
                "supported_types": ["MD5", "SHA1", "SHA256"],
                "provided_type": obs_type
            }
        
        return self.analyze_hash(observable)
    
    def _classify_observable(self, observable: str) -> str:
        """
        Classify the observable type
        
        Args:
            observable: String to classify
            
        Returns:
            Observable type
        """
        if len(observable) == 32 and all(c in 'abcdefABCDEF0123456789' for c in observable):
            return "MD5"
        elif len(observable) == 40 and all(c in 'abcdefABCDEF0123456789' for c in observable):
            return "SHA1"
        elif len(observable) == 64 and all(c in 'abcdefABCDEF0123456789' for c in observable):
            return "SHA256"
        else:
            return "Unknown"

  
