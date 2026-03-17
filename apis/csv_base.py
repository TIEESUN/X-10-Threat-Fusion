"""
Base class for CSV-based threat intelligence sources
"""

import os
import csv
import json
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from abc import ABC, abstractmethod
import hashlib
import re

logger = logging.getLogger(__name__)


class CSVBaseAPI:
    """Base class for CSV-based threat intelligence sources"""
    
    def __init__(self, cache_dir: str = "cache", timeout: int = 30):
        """
        Initialize CSV-based API client
        
        Args:
            cache_dir: Directory to store cached files
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatIntel-Aggregator/1.0'
        })
        
        self.cache_dir = cache_dir
        self.cache_subdir = self.__class__.__name__.lower().replace('api', '')
        self.full_cache_dir = os.path.join(cache_dir, self.cache_subdir)
        self.timestamp_dir = os.path.join(cache_dir, ".timestamps")
        
        # Create directories
        os.makedirs(self.full_cache_dir, exist_ok=True)
        os.makedirs(self.timestamp_dir, exist_ok=True)
        
        # Cache settings
        self.cache_ttl_minutes = self._get_cache_ttl()
        
    @abstractmethod
    def _get_cache_ttl(self) -> int:
        """Get cache TTL in minutes for this source"""
        pass
    
    @abstractmethod
    def _get_csv_urls(self) -> Dict[str, str]:
        """Get CSV URLs for this source"""
        pass
    
    def _get_cache_path(self, filename: str) -> str:
        """Get full path for cached file"""
        return os.path.join(self.full_cache_dir, filename)
    
    def _get_timestamp_path(self, filename: str) -> str:
        """Get path for timestamp file"""
        timestamp_name = f"{self.cache_subdir}_{filename}.timestamp"
        return os.path.join(self.timestamp_dir, timestamp_name)
    
    def _is_cache_valid(self, filename: str) -> bool:
        """Check if cached file is still valid"""
        cache_path = self._get_cache_path(filename)
        timestamp_path = self._get_timestamp_path(filename)
        
        if not os.path.exists(cache_path) or not os.path.exists(timestamp_path):
            return False
        
        try:
            with open(timestamp_path, 'r') as f:
                last_download = datetime.fromisoformat(f.read().strip())
            
            time_diff = datetime.now() - last_download
            return time_diff < timedelta(minutes=self.cache_ttl_minutes)
        except Exception as e:
            logger.error(f"Error checking cache validity: {e}")
            return False
    
    def _download_file(self, url: str, local_path: str) -> bool:
        """Download file from URL"""
        try:
            logger.info(f"Downloading {url}")
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            # Save file
            with open(local_path, 'wb') as f:
                f.write(response.content)
            
            # Update timestamp
            timestamp_path = self._get_timestamp_path(os.path.basename(local_path))
            with open(timestamp_path, 'w') as f:
                f.write(datetime.now().isoformat())
            
            logger.info(f"Successfully downloaded {url}")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error downloading {url}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error downloading {url}: {e}")
            return False
    
    def _ensure_cache_updated(self) -> bool:
        """Ensure all CSV files are cached and up-to-date"""
        urls = self._get_csv_urls()
        success_count = 0
        
        for filename, url in urls.items():
            cache_path = self._get_cache_path(filename)
            
            if not self._is_cache_valid(filename):
                if self._download_file(url, cache_path):
                    success_count += 1
                else:
                    logger.warning(f"Failed to download {filename}, using cached version if available")
                    # Check if we have a cached version at least
                    if os.path.exists(cache_path):
                        success_count += 1
            else:
                success_count += 1
        
        return success_count > 0
    
    def _read_csv_file(self, filename: str) -> List[Dict[str, Any]]:
        """Read CSV file and return as list of dictionaries"""
        cache_path = self._get_cache_path(filename)
        
        if not os.path.exists(cache_path):
            logger.warning(f"CSV file not found: {cache_path}")
            return []
        
        try:
            with open(cache_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Skip comments (lines starting with #)
                lines = [line for line in content.split('\n') if line.strip() and not line.strip().startswith('#')]
                
                if not lines:
                    logger.warning(f"No valid lines in CSV file: {filename}")
                    return []
                
                # Parse CSV
                reader = csv.DictReader(lines)
                data = list(reader)
                logger.info(f"Successfully read {len(data)} rows from {filename}")
                return data
                
        except Exception as e:
            logger.error(f"Error reading CSV file {filename}: {e}")
            return []
    
    def _read_text_file(self, filename: str) -> List[str]:
        """Read text file and return as list of lines"""
        cache_path = self._get_cache_path(filename)
        
        if not os.path.exists(cache_path):
            logger.warning(f"Text file not found: {cache_path}")
            return []
        
        try:
            with open(cache_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Skip comments and empty lines
                lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                logger.info(f"Successfully read {len(lines)} lines from {filename}")
                return lines
                
        except Exception as e:
            logger.error(f"Error reading text file {filename}: {e}")
            return []
    
    def _read_json_file(self, filename: str) -> Dict[str, Any]:
        """Read JSON file and return as dictionary"""
        cache_path = self._get_cache_path(filename)
        
        if not os.path.exists(cache_path):
            logger.warning(f"JSON file not found: {cache_path}")
            return {}
        
        try:
            with open(cache_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
                logger.info(f"Successfully read JSON from {filename}")
                return data
                
        except Exception as e:
            logger.error(f"Error reading JSON file {filename}: {e}")
            return {}
    
    def _classify_observable(self, observable: str) -> str:
        """
        Classify the type of observable (IP, domain, hash, etc.)
        
        Args:
            observable: The observable to classify
            
        Returns:
            Type of observable as string
        """
        observable = observable.strip()
        
        # Check for IPv4
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, observable):
            return "ip"
        
        # Check for MD5 hash (32 hex chars)
        if re.match(r'^[a-fA-F0-9]{32}$', observable):
            return "md5"
        
        # Check for SHA1 hash (40 hex chars)
        if re.match(r'^[a-fA-F0-9]{40}$', observable):
            return "sha1"
        
        # Check for SHA256 hash (64 hex chars)
        if re.match(r'^[a-fA-F0-9]{64}$', observable):
            return "sha256"
        
        # Check for domain
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(domain_pattern, observable):
            return "domain"
        
        # Check for URL
        if observable.startswith(('http://', 'https://', 'ftp://')):
            return "url"
        
        # Check for JA3 fingerprint (32 hex chars, same as MD5)
        # But we already classified MD5 above, so check context
        if re.match(r'^[a-fA-F0-9]{32}$', observable):
            return "ja3"
        
        return "unknown"
