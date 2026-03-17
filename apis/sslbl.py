"""
SSLBL (SSL Certificate Blacklist) API integration
Comprehensive support for all SSLBL feeds
"""

import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
import sys
import os
import csv
import io

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from csv_base import CSVBaseAPI
except ImportError:
    from .csv_base import CSVBaseAPI

logger = logging.getLogger(__name__)


class SSLBLAPI(CSVBaseAPI):
    """
    SSLBL API client for malicious SSL/TLS intelligence
    
    Supported feeds:
    - SSL Certificate SHA1 blacklist
    - SSL IP blacklist  
    - JA3 fingerprint blacklist
    """
    
    def __init__(self, cache_dir: str = "cache"):
        """Initialize SSLBL API client"""
        super().__init__(cache_dir=cache_dir)
        logger.info("SSLBL API initialized")
    
    def _get_cache_ttl(self) -> int:
        """SSLBL updates every 5 minutes"""
        return 5
    
    def _get_csv_urls(self) -> Dict[str, str]:
        """Get all SSLBL feed URLs"""
        return {
            "sslblacklist.csv": "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
            "sslipblacklist.csv": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
            "ja3_fingerprints.csv": "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
        }
    
    def _clean_csv_content(self, content: str) -> str:
        """
        Clean CSV content by removing comment blocks but preserving header lines
        
        CRITICAL: Lines like "# ja3_md5,Firstseen,..." are HEADERS, not comments!
        We need to detect and preserve them.
        """
        lines = content.split('\n')
        cleaned_lines = []
        
        for line in lines:
            stripped = line.strip()
            
            # Skip empty lines
            if not stripped:
                continue
            
            # Check if this is a header line (starts with # but contains comma-separated field names)
            if stripped.startswith('#'):
                # Remove the # and check if it looks like a CSV header
                without_hash = stripped[1:].strip()
                
                # Header detection: contains commas and lowercase field names
                if ',' in without_hash and any(keyword in without_hash.lower() 
                    for keyword in ['ja3', 'first', 'last', 'dst', 'ip', 'port', 'reason', 'sha1', 'date']):
                    # This is a header! Remove the # and keep it
                    logger.info(f"Found header line: {without_hash}")
                    cleaned_lines.append(without_hash)
                # Otherwise, skip it (it's a real comment)
            else:
                # Regular data line
                cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)
    
    def _parse_ja3_fingerprints(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse JA3 fingerprints from CSV content
        
        Expected format:
        # ja3_md5,Firstseen,Lastseen,Listingreason
        b386946a5a44d1ddcc843bc75336dfce,2017-07-14 18:08:15,2019-07-27 20:42:54,Dridex
        """
        results = []
        
        try:
            # Clean the CSV (remove comments but keep headers)
            cleaned = self._clean_csv_content(content)
            
            if not cleaned:
                logger.warning("No content after cleaning CSV")
                return results
            
            # Parse with DictReader
            reader = csv.DictReader(io.StringIO(cleaned))
            
            for row in reader:
                try:
                    # Get JA3 hash (try different possible column names)
                    ja3 = (row.get('ja3_md5') or 
                           row.get('JA3_md5') or 
                           row.get('ja3') or 
                           row.get('JA3')).strip().lower()
                    
                    if not ja3 or len(ja3) != 32:
                        continue
                    
                    # Get other fields
                    first_seen = (row.get('Firstseen') or row.get('FirstSeen') or 
                                 row.get('first_seen') or '').strip()
                    last_seen = (row.get('Lastseen') or row.get('LastSeen') or 
                                row.get('last_seen') or '').strip()
                    reason = (row.get('Listingreason') or row.get('reason') or 
                             row.get('Reason') or '').strip()
                    
                    results.append({
                        'ja3_fingerprint': ja3,
                        'first_seen': first_seen,
                        'last_seen': last_seen,
                        'listing_reason': reason,
                        'source': 'SSLBL_JA3'
                    })
                    
                except Exception as e:
                    logger.debug(f"Error parsing JA3 row: {e}")
                    continue
            
            logger.info(f"Parsed {len(results)} JA3 entries")
            
        except Exception as e:
            logger.error(f"Error in JA3 parsing: {e}")
        
        return results
    
    def _parse_ssl_certs(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse SSL certificates (no header in this file)
        Format: Listingdate,SHA1,Listingreason
        """
        results = []
        
        try:
            # This file has no header, just filter comments
            lines = [line.strip() for line in content.split('\n') 
                    if line.strip() and not line.strip().startswith('#')]
            
            for line in lines:
                parts = line.split(',')
                if len(parts) >= 3:
                    sha1 = parts[1].strip().lower()
                    if len(sha1) == 40:  # SHA1 validation
                        results.append({
                            'sha1_hash': sha1,
                            'first_seen': parts[0].strip(),
                            'listing_reason': parts[2].strip(),
                            'source': 'SSLBL'
                        })
            
            logger.info(f"Parsed {len(results)} SSL cert entries")
            
        except Exception as e:
            logger.error(f"Error in SSL cert parsing: {e}")
        
        return results
    
    def _parse_ssl_ips(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse SSL IPs (no header in this file)
        Format: Listingdate,DstIP,DstPort,Listingreason
        """
        results = []
        
        try:
            # This file has no header, just filter comments
            lines = [line.strip() for line in content.split('\n') 
                    if line.strip() and not line.strip().startswith('#')]
            
            for line in lines:
                parts = line.split(',')
                if len(parts) >= 4:
                    ip = parts[1].strip()
                    if '.' in ip:  # Basic IP validation
                        results.append({
                            'ip_address': ip,
                            'port': int(parts[2]) if parts[2].isdigit() else 443,
                            'first_seen': parts[0].strip(),
                            'listing_reason': parts[3].strip(),
                            'source': 'SSLBL'
                        })
            
            logger.info(f"Parsed {len(results)} SSL IP entries")
            
        except Exception as e:
            logger.error(f"Error in SSL IP parsing: {e}")
        
        return results
    
    def check_ja3(self, ja3_fingerprint: str) -> Dict[str, Any]:
        """Check if JA3 fingerprint is in SSLBL blacklist"""
        logger.info(f"Checking JA3 {ja3_fingerprint} in SSLBL")
        
        if not self._ensure_cache_updated():
            return {
                "query_status": "error",
                "observable": ja3_fingerprint,
                "type": "ja3",
                "source": "SSLBL_JA3",
                "error": "Failed to update cache"
            }
        
        cache_path = self._get_cache_path("ja3_fingerprints.csv")
        try:
            with open(cache_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            logger.info(f"Read {len(content)} bytes from ja3_fingerprints.csv")
            
            parsed = self._parse_ja3_fingerprints(content)
            logger.info(f"Parsed {len(parsed)} JA3 entries")
            
            # Search for match (case-insensitive)
            ja3_lower = ja3_fingerprint.lower().strip()
            matches = [item for item in parsed if item['ja3_fingerprint'] == ja3_lower]
            
            logger.info(f"Found {len(matches)} matches for JA3 {ja3_fingerprint}")
            
            if matches:
                return {
                    "query_status": "found",
                    "observable": ja3_fingerprint,
                    "type": "ja3",
                    "source": "SSLBL_JA3",
                    "is_malicious": True,
                    "threat_level": "high",
                    "matches_count": len(matches),
                    "matches": matches,
                    "first_seen": matches[0]['first_seen'],
                    "last_seen": matches[0]['last_seen'],
                    "listing_reasons": list(set(m['listing_reason'] for m in matches if m['listing_reason'])),
                    "signature": "SSLBL_JA3:MaliciousTLS",
                    "intelligence": {
                        "source": "SSLBL_JA3",
                        "type": "malicious_tls",
                        "confidence": "high",
                        "malware_families": list(set(m['listing_reason'] for m in matches if m['listing_reason']))
                    },
                    "key_findings": [
                        f"🚨 SSLBL JA3: Malicious TLS fingerprint found",
                        f"🔴 JA3: {ja3_fingerprint}",
                        f"📅 First seen: {matches[0]['first_seen']}",
                        f"📅 Last seen: {matches[0]['last_seen']}",
                        f"📋 Malware: {', '.join(set(m['listing_reason'] for m in matches if m['listing_reason']))}"
                    ]
                }
            else:
                return {
                    "query_status": "not_found",
                    "observable": ja3_fingerprint,
                    "type": "ja3",
                    "source": "SSLBL_JA3",
                    "is_malicious": False,
                    "threat_level": "clean",
                    "message": "JA3 fingerprint not found in SSLBL blacklist"
                }
        
        except Exception as e:
            logger.error(f"Error checking JA3: {e}", exc_info=True)
            return {
                "query_status": "error",
                "observable": ja3_fingerprint,
                "error": str(e)
            }
    
    def check_sha1(self, sha1_hash: str) -> Dict[str, Any]:
        """Check if SSL certificate SHA1 is in SSLBL blacklist"""
        logger.info(f"Checking SHA1 {sha1_hash} in SSLBL")
        
        if not self._ensure_cache_updated():
            return {
                "query_status": "error",
                "observable": sha1_hash,
                "type": "sha1",
                "source": "SSLBL",
                "error": "Failed to update cache"
            }
        
        cache_path = self._get_cache_path("sslblacklist.csv")
        try:
            with open(cache_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            parsed = self._parse_ssl_certs(content)
            
            # Search for match
            sha1_lower = sha1_hash.lower().strip()
            matches = [item for item in parsed if item['sha1_hash'] == sha1_lower]
            
            if matches:
                return {
                    "query_status": "found",
                    "observable": sha1_hash,
                    "type": "sha1",
                    "source": "SSLBL",
                    "is_malicious": True,
                    "threat_level": "high",
                    "matches_count": len(matches),
                    "matches": matches,
                    "first_seen": matches[0]['first_seen'],
                    "listing_reasons": list(set(m['listing_reason'] for m in matches if m['listing_reason'])),
                    "signature": "SSLBL:MaliciousSSLCert",
                    "key_findings": [
                        f"🚨 SSLBL: Malicious SSL certificate",
                        f"🔴 SHA1: {sha1_hash}",
                        f"📅 First seen: {matches[0]['first_seen']}",
                        f"📋 Malware: {', '.join(set(m['listing_reason'] for m in matches if m['listing_reason']))}"
                    ]
                }
            else:
                return {
                    "query_status": "not_found",
                    "observable": sha1_hash,
                    "type": "sha1",
                    "source": "SSLBL",
                    "is_malicious": False,
                    "threat_level": "clean",
                    "message": "SHA1 not found in SSLBL blacklist"
                }
        
        except Exception as e:
            logger.error(f"Error checking SHA1: {e}")
            return {"query_status": "error", "observable": sha1_hash, "error": str(e)}
    
    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """Check if IP is in SSLBL IP blacklist"""
        logger.info(f"Checking IP {ip_address} in SSLBL")
        
        if not self._ensure_cache_updated():
            return {
                "query_status": "error",
                "observable": ip_address,
                "type": "ip",
                "source": "SSLBL",
                "error": "Failed to update cache"
            }
        
        cache_path = self._get_cache_path("sslipblacklist.csv")
        try:
            with open(cache_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            parsed = self._parse_ssl_ips(content)
            
            # Search for match
            matches = [item for item in parsed if item['ip_address'] == ip_address]
            
            if matches:
                return {
                    "query_status": "found",
                    "observable": ip_address,
                    "type": "ip",
                    "source": "SSLBL",
                    "is_malicious": True,
                    "threat_level": "high",
                    "matches_count": len(matches),
                    "matches": matches,
                    "first_seen": matches[0]['first_seen'],
                    "ports": list(set(str(m['port']) for m in matches)),
                    "listing_reasons": list(set(m['listing_reason'] for m in matches if m['listing_reason'])),
                    "signature": "SSLBL:MaliciousSSL",
                    "key_findings": [
                        f"🚨 SSLBL: Malicious SSL/TLS connection",
                        f"🔴 IP: {ip_address}",
                        f"🔴 Ports: {', '.join(set(str(m['port']) for m in matches))}",
                        f"📅 First seen: {matches[0]['first_seen']}",
                        f"📋 Malware: {', '.join(set(m['listing_reason'] for m in matches if m['listing_reason']))}"
                    ]
                }
            else:
                return {
                    "query_status": "not_found",
                    "observable": ip_address,
                    "type": "ip",
                    "source": "SSLBL",
                    "is_malicious": False,
                    "threat_level": "clean",
                    "message": "IP not found in SSLBL blacklist"
                }
        
        except Exception as e:
            logger.error(f"Error checking IP: {e}")
            return {"query_status": "error", "observable": ip_address, "error": str(e)}
    
    def analyze(self, observable: str) -> Dict[str, Any]:
        """Auto-detect type and check appropriate feed"""
        obs_type = self._classify_observable(observable)
        logger.info(f"Observable {observable} classified as {obs_type}")
        
        if obs_type == "ip":
            return self.check_ip(observable)
        elif obs_type == "sha1":
            return self.check_sha1(observable)
        elif obs_type in ["md5", "ja3"]:
            return self.check_ja3(observable)
        else:
            # Try all types
            for check_func in [self.check_ip, self.check_sha1, self.check_ja3]:
                result = check_func(observable)
                if result.get("query_status") == "found":
                    return result
            
            return {
                "query_status": "not_found",
                "observable": observable,
                "source": "SSLBL",
                "message": "Not found in any SSLBL feed"
            }
