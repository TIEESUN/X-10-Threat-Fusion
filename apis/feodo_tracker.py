"""
Feodo Tracker API integration
Provides botnet C2 IP blocklist
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from csv_base import CSVBaseAPI
except ImportError:
    # If running as module
    from .csv_base import CSVBaseAPI

logger = logging.getLogger(__name__)


class FeodoTrackerAPI(CSVBaseAPI):
    """Feodo Tracker API client for botnet C2 IPs"""
    
    def __init__(self, cache_dir: str = "cache"):
        """
        Initialize Feodo Tracker API client
        
        Args:
            cache_dir: Directory to store cached files
        """
        super().__init__(cache_dir=cache_dir)
        logger.info("Feodo Tracker API initialized")
    
    def _get_cache_ttl(self) -> int:
        """Feodo Tracker updates frequently, check every 15 minutes"""
        return 15
    
    def _get_csv_urls(self) -> Dict[str, str]:
        """Get URLs for Feodo Tracker"""
        return {
            "ipblocklist.txt": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            "ipblocklist_recommended.txt": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
            "ipblocklist_aggressive.txt": "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt"
        }
    
    def _parse_ip_blocklist(self, ip_list: List[str]) -> List[Dict[str, Any]]:
        """
        Parse IP blocklist text data
        
        Feodo Tracker format can be:
        1. Just IP addresses (one per line)
        2. CSV format with additional data
        """
        results = []
        
        if not ip_list:
            logger.warning("No IPs to parse in blocklist")
            return results
        
        for ip_line in ip_list:
            try:
                ip_line = ip_line.strip()
                if not ip_line:
                    continue
                
                # Check if it's CSV format or just IP
                if ',' in ip_line:
                    # CSV format: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
                    parts = ip_line.split(',')
                    if len(parts) < 2:
                        continue
                    
                    # First part might be timestamp, second is IP
                    # Try to identify which field is the IP
                    ip_address = None
                    for part in parts:
                        part = part.strip()
                        if '.' in part and part.replace('.', '').isdigit():
                            ip_address = part
                            break
                    
                    if not ip_address:
                        continue
                    
                    result = {
                        "ip_address": ip_address,
                        "source": "FeodoTracker",
                        "first_seen": parts[0] if len(parts) > 0 else "",
                        "port": parts[2] if len(parts) > 2 else "",
                        "status": parts[3] if len(parts) > 3 else "",
                        "last_online": parts[4] if len(parts) > 4 else "",
                        "malware_family": parts[5] if len(parts) > 5 else "",
                        "threat_type": "botnet_c2"
                    }
                else:
                    # Just an IP address
                    ip_address = ip_line.strip()
                    
                    # Validate it looks like an IP
                    if not '.' in ip_address or not all(part.isdigit() for part in ip_address.split('.')):
                        continue
                    
                    result = {
                        "ip_address": ip_address,
                        "source": "FeodoTracker",
                        "first_seen": "",
                        "last_online": "",
                        "port": "",
                        "status": "",
                        "malware_family": "",
                        "threat_type": "botnet_c2"
                    }
                
                results.append(result)
                
            except Exception as e:
                logger.debug(f"Error parsing IP blocklist line '{ip_line}': {e}")
                continue
        
        logger.info(f"Parsed {len(results)} IP blocklist entries")
        return results
    
    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check if IP address is in Feodo Tracker blocklist
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with check results
        """
        logger.info(f"Checking IP {ip_address} in Feodo Tracker")
        
        if not self._ensure_cache_updated():
            logger.error("Failed to update Feodo Tracker cache")
            return {
                "query_status": "error",
                "observable": ip_address,
                "type": "ip",
                "source": "FeodoTracker",
                "error": "Failed to download or access Feodo Tracker data"
            }
        
        all_matches = []
        
        # Check all blocklists
        for blocklist_file in ["ipblocklist.txt", "ipblocklist_recommended.txt", "ipblocklist_aggressive.txt"]:
            ip_list = self._read_text_file(blocklist_file)
            logger.info(f"Read {len(ip_list)} lines from {blocklist_file}")
            
            parsed_ips = self._parse_ip_blocklist(ip_list)
            logger.info(f"Parsed {len(parsed_ips)} IPs from {blocklist_file}")
            
            # Search for IP
            matches = [item for item in parsed_ips if item["ip_address"] == ip_address]
            all_matches.extend(matches)
        
        logger.info(f"Found {len(all_matches)} total matches for IP {ip_address}")
        
        if all_matches:
            # Extract unique values
            ports = list(set(match.get("port", "") for match in all_matches if match.get("port")))
            malware_families = list(set(match.get("malware_family", "") for match in all_matches if match.get("malware_family")))
            statuses = list(set(match.get("status", "") for match in all_matches if match.get("status")))
            
            result = {
                "query_status": "found",
                "observable": ip_address,
                "type": "ip",
                "source": "FeodoTracker",
                "is_malicious": True,
                "threat_level": "high",
                "matches_count": len(all_matches),
                "matches": all_matches,
                "first_seen": all_matches[0].get("first_seen", ""),
                "last_online": all_matches[0].get("last_online", ""),
                "ports": ports,
                "malware_families": malware_families,
                "statuses": statuses,
                "signature": f"FeodoTracker:BotnetC2",
                "intelligence": {
                    "source": "FeodoTracker",
                    "type": "botnet_c2",
                    "confidence": "high",
                    "first_seen": all_matches[0].get("first_seen", ""),
                    "last_online": all_matches[0].get("last_online", ""),
                    "malware_families": malware_families
                }
            }
            
            # Add key findings
            findings = []
            findings.append(f"🚨 FeodoTracker: Found in {len(all_matches)} botnet C2 blocklist(s)")
            if malware_families:
                findings.append(f"🔴 Malware: {', '.join(malware_families)}")
            if ports:
                findings.append(f"🔴 Ports: {', '.join(ports)}")
            if statuses:
                findings.append(f"📊 Status: {', '.join(statuses)}")
            if result["first_seen"]:
                findings.append(f"📅 First seen: {result['first_seen']}")
            if result["last_online"]:
                findings.append(f"📅 Last online: {result['last_online']}")
            result["key_findings"] = findings
            
            return result
        else:
            return {
                "query_status": "not_found",
                "observable": ip_address,
                "type": "ip",
                "source": "FeodoTracker",
                "is_malicious": False,
                "threat_level": "clean",
                "message": "IP address not found in Feodo Tracker blocklists"
            }
    
    def get_blocklist_stats(self) -> Dict[str, Any]:
        """
        Get statistics about current blocklist entries
        
        Returns:
            Dictionary with statistics
        """
        if not self._ensure_cache_updated():
            return {"error": "Failed to update cache"}
        
        all_ips = []
        stats_by_list = {}
        
        for blocklist_file in ["ipblocklist.txt", "ipblocklist_recommended.txt", "ipblocklist_aggressive.txt"]:
            ip_list = self._read_text_file(blocklist_file)
            parsed_ips = self._parse_ip_blocklist(ip_list)
            all_ips.extend(parsed_ips)
            
            stats_by_list[blocklist_file] = len(parsed_ips)
        
        if not all_ips:
            return {"error": "No data available"}
        
        # Calculate statistics
        unique_ips = len(set(item["ip_address"] for item in all_ips))
        unique_malware = len(set(item.get("malware_family", "") for item in all_ips if item.get("malware_family")))
        unique_ports = len(set(item.get("port", "") for item in all_ips if item.get("port")))
        
        # Malware family distribution
        malware_counts = {}
        for item in all_ips:
            malware = item.get("malware_family", "")
            if malware:
                malware_counts[malware] = malware_counts.get(malware, 0) + 1
        
        # Port distribution
        port_counts = {}
        for item in all_ips:
            port = item.get("port", "")
            if port:
                port_counts[port] = port_counts.get(port, 0) + 1
        
        return {
            "total_ips": len(all_ips),
            "unique_ips": unique_ips,
            "unique_malware_families": unique_malware,
            "unique_ports": unique_ports,
            "ips_by_list": stats_by_list,
            "top_malware": dict(sorted(malware_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "top_ports": dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "last_updated": datetime.now().isoformat()
        }
    
    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Main analysis method - compatible with other API clients
        
        Args:
            observable: IP address to analyze
            
        Returns:
            Analysis results
        """
        # Classify observable type
        obs_type = self._classify_observable(observable)
        logger.info(f"Observable {observable} classified as {obs_type}")
        
        if obs_type == "ip":
            return self.check_ip(observable)
        else:
            return {
                "query_status": "not_found",
                "observable": observable,
                "error": "FeodoTracker currently only supports IP address analysis",
                "supported_types": ["ip"],
                "provided_type": obs_type,
                "source": "FeodoTracker"
            }
