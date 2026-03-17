"""
Ransomware.live API integration - Ransomware intelligence and threat data

API v2 documentation: https://www.ransomware.live/apidocs
Base URL: https://api.ransomware.live/v2
"""

import logging
import re
import time
from typing import Any, Dict, List, Optional

import requests

from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class RansomwareLiveAPI(BaseAPIClient):
    """Ransomware.live API client for ransomware intelligence (v2)."""

    # Updated to v2 base URL per official docs (https://www.ransomware.live/apidocs)
    BASE_URL = "https://api.ransomware.live/v2"

    def __init__(self, api_key: str = "", timeout: int = 30):
        """Initialise Ransomware.live API client.

        Args:
            api_key: Ransomware.live API key (not required for public endpoints).
            timeout: Request timeout in seconds (default 30 — website scraping can be slow).
        """
        super().__init__(api_key, timeout)
        # Public API does not require auth headers for basic queries
        self.public_headers = {
            "Accept": "application/json",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _safe_request(
        self,
        url: str,
        headers: Optional[dict] = None,
        expect_json: bool = True,
        retries: int = 3,
        backoff: float = 1.0,
        allow_redirects: bool = True,
    ):
        """Perform a GET request with retries and robust JSON/text handling.

        Returns parsed JSON when *expect_json* is True and valid JSON is
        received; otherwise returns the raw response text.  Returns None
        after all retry attempts are exhausted.
        """
        headers = headers or self.public_headers

        for attempt in range(1, retries + 1):
            try:
                resp = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                )
            except requests.exceptions.RequestException as exc:
                logger.debug(
                    "Request error for %s (attempt %d/%d): %s",
                    url, attempt, retries, exc,
                )
                if attempt < retries:
                    time.sleep(backoff * attempt)
                    continue
                return None

            if resp.status_code == 200:
                if expect_json:
                    try:
                        return resp.json()
                    except ValueError as exc:
                        logger.debug(
                            "JSON decode error for %s (attempt %d/%d): %s",
                            url, attempt, retries, exc,
                        )
                        if attempt < retries:
                            time.sleep(backoff * attempt)
                            continue
                        return None
                else:
                    return resp.text

            logger.debug("Non-200 response for %s: %s", url, resp.status_code)
            # Retry on 5xx; bail immediately on 4xx
            if 500 <= resp.status_code < 600 and attempt < retries:
                time.sleep(backoff * attempt)
                continue
            return None

        return None

    def _classify_observable(self, observable: str) -> str:
        """Classify an observable string into a rough type.

        Returns one of: ``"IP"``, ``"Domain"``, ``"URL"``, ``"Hash"``, ``"Unknown"``.
        """
        observable = observable.strip()

        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", observable):
            return "IP"

        if observable.startswith(("http://", "https://")):
            return "URL"

        # MD5 / SHA-1 / SHA-256
        if re.match(r"^[0-9a-fA-F]{32}$", observable):
            return "Hash"
        if re.match(r"^[0-9a-fA-F]{40}$", observable):
            return "Hash"
        if re.match(r"^[0-9a-fA-F]{64}$", observable):
            return "Hash"

        if "." in observable and " " not in observable:
            return "Domain"

        return "Unknown"

    def _calculate_inactive_days(self, last_activity: str) -> int:
        """Return the number of days since *last_activity* (ISO-8601 date string).

        Returns 0 if the date cannot be parsed or is empty.
        """
        if not last_activity:
            return 0
        from datetime import datetime, timezone

        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(last_activity[:19], fmt).replace(
                    tzinfo=timezone.utc
                )
                return max(0, (datetime.now(timezone.utc) - dt).days)
            except ValueError:
                continue
        logger.debug("Could not parse last_activity date: %r", last_activity)
        return 0

    # ------------------------------------------------------------------
    # Victim / group search (v2 endpoints)
    # ------------------------------------------------------------------

    def _search_victims(self, keyword: str) -> Dict[str, Any]:
        """Search for victims by keyword using the v2 ``/searchvictims`` endpoint."""
        encoded = requests.utils.quote(keyword, safe="")
        url = f"{self.BASE_URL}/searchvictims/{encoded}"
        data = self._safe_request(url)

        results: Dict[str, Any] = {
            "source": "Ransomware.live",
            "observable": keyword,
            "victims": [],
            "total_victims_found": 0,
            "is_malicious": False,
            "malicious": 0,
            "suspicious": 0,
            "threat_level": "none",
        }

        if not data:
            return results

        victims: List[Dict] = data if isinstance(data, list) else data.get("victims", [])
        results["victims"] = victims
        results["total_victims_found"] = len(victims)
        results["suspicious"] = len(victims)

        if victims:
            results["is_malicious"] = True
            results["malicious"] = 1
            if len(victims) >= 50:
                results["threat_level"] = "critical"
            elif len(victims) >= 10:
                results["threat_level"] = "high"
            else:
                results["threat_level"] = "medium"

        return results

    def _search_groups(self, keyword: str) -> List[Dict[str, Any]]:
        """Return groups whose name contains *keyword* (case-insensitive).

        Fetches the full ``/groups`` list and filters locally — the v2 API does
        not expose a dedicated keyword search for groups.
        """
        url = f"{self.BASE_URL}/groups"
        groups = self._safe_request(url)
        if not groups or not isinstance(groups, list):
            return []

        keyword_lower = keyword.lower()
        return [
            g for g in groups
            if isinstance(g, dict) and keyword_lower in g.get("name", "").lower()
        ]

    def _get_victims_for_group(self, group_name: str) -> List[Dict[str, Any]]:
        """Fetch all victims for a specific group via ``/groupvictims/<group_name>``."""
        encoded = requests.utils.quote(group_name.lower().strip(), safe="")
        url = f"{self.BASE_URL}/groupvictims/{encoded}"
        data = self._safe_request(url)
        if data is None:
            return []
        return data if isinstance(data, list) else data.get("victims", [])

    # ------------------------------------------------------------------
    # Public analysis interface
    # ------------------------------------------------------------------

    def analyze(self, observable: str) -> Dict[str, Any]:
        """Analyse an observable for ransomware-related intelligence.

        Args:
            observable: Domain, IP, hash, or company name.

        Returns:
            Analysis results dict.
        """
        obs_type = self._classify_observable(observable)
        results = self._search_victims(observable)

        if obs_type in ("Domain", "URL", "Unknown") or "." in observable:
            results["associated_groups"] = self._search_groups(observable)
        else:
            results["associated_groups"] = []

        return results

    def analyze_group(self, group_name: str) -> Dict[str, Any]:
        """Analyse a threat group for comprehensive ransomware intelligence.

        Args:
            group_name: Name of the ransomware group.

        Returns:
            Comprehensive group analysis with stats, metadata, and victims.
        """
        response: Dict[str, Any] = {
            "source": "Ransomware.live",
            "group_name": group_name,
            "type": "ransomware_group_analysis",
            "group_info": {},
            "recent_victims": [],
            "victim_domains": [],
            "threat_level": "unknown",
            "is_malicious": False,
            "malicious": 0,
            "suspicious": 0,
            "status": "Active",
            "description": "",
            "history": "",
            "statistics": {
                "total_victims": 0,
                "first_victim_date": "",
                "last_victim_date": "",
                "inactive_days": 0,
                "avg_delay_days": 0.0,
                "infostealer_percentage": 0.0,
            },
            "metadata": {
                "known_locations": 0,
                "ransom_notes": 0,
                "tools_used": 0,
                "vulnerabilities_exploited": 0,
                "ttps_matrix": 0,
                "negotiation_chats": 0,
                "yara_rules": 0,
                "iocs_count": 0,
            },
            "active_regions": [],
            "initial_access_vectors": [],
            "tools_used_list": [],
            "cves": [],
            "related_groups": [],
            "external_links": {},
        }

        comprehensive_data = self._get_comprehensive_group_data(group_name)
        response.update(comprehensive_data)

        # Normalise nested list fields into metadata counts
        try:
            meta = response.setdefault("metadata", {})
            list_fields = [
                "known_locations_list",
                "ransom_notes_list",
                "tools_used_list",
                "vulnerabilities_list",
                "ttps_list",
                "negotiation_chats_list",
                "yara_rules_list",
                "iocs_list",
            ]
            for fld in list_fields:
                if not meta.get(fld):
                    meta[fld] = response.get(fld) or []

            meta.setdefault("known_locations", len(meta.get("known_locations_list", [])))
            meta.setdefault("ransom_notes", len(meta.get("ransom_notes_list", [])))
            meta.setdefault("tools_used", len(meta.get("tools_used_list", [])))
            meta.setdefault(
                "vulnerabilities_exploited",
                len(meta.get("vulnerabilities_list", [])),
            )
            meta.setdefault("ttps_matrix", len(meta.get("ttps_list", [])))
            meta.setdefault(
                "negotiation_chats", len(meta.get("negotiation_chats_list", []))
            )
            meta.setdefault("yara_rules", len(meta.get("yara_rules_list", [])))
            meta.setdefault("iocs_count", len(meta.get("iocs_list", [])))

            if not response.get("targets"):
                response["targets"] = {
                    "top_sectors": [],
                    "top_countries": [],
                    "sector_distribution": {},
                    "country_distribution": {},
                }
        except Exception:
            pass

        # Fetch victims and enrich response
        victims = self._get_victims_for_group(group_name)
        response["recent_victims"] = victims

        victim_domains: set = set()
        for victim in victims:
            if victim.get("website"):
                victim_domains.add(victim["website"])
            # v2 uses "victim" (not "name") for the organization name
            if victim.get("victim") and victim["victim"] != "N/A":
                victim_domains.add(victim["victim"])

        response["victim_domains"] = list(victim_domains)[:20]
        response["suspicious"] = len(victims)
        response["is_malicious"] = bool(victims)

        if not victims:
            response["threat_level"] = "not applicable"
        elif len(victims) >= 100:
            response["threat_level"] = "critical"
        elif len(victims) >= 10:
            response["threat_level"] = "high"
        else:
            response["threat_level"] = "medium"

        return response

    # ------------------------------------------------------------------
    # Comprehensive group data (API + optional website scraping)
    # ------------------------------------------------------------------

    def _get_comprehensive_group_data(self, group_name: str) -> Dict[str, Any]:
        """Retrieve comprehensive group data from the v2 API and website.

        Strategy:
          1. Call ``/group/<group_name>`` for structured metadata.
          2. Scrape ``https://www.ransomware.live/group/<group_name>`` for
             statistics that are not yet exposed by the JSON API.
        """
        comprehensive_data: Dict[str, Any] = {
            "status": "Unknown",
            "description": "",
            "history": "",
            "statistics": {
                "total_victims": 0,
                "first_victim_date": "Unknown",
                "last_victim_date": "Unknown",
                "inactive_days": 0,
                "avg_delay_days": "N/A",
                "infostealer_percentage": 0.0,
            },
            "metadata": {
                "known_locations": 0,
                "known_locations_list": [],
                "ransom_notes": 0,
                "ransom_notes_list": [],
                "tools_used": 0,
                "tools_used_list": [],
                "vulnerabilities_exploited": 0,
                "vulnerabilities_list": [],
                "ttps_matrix": 0,
                "ttps_list": [],
                "negotiation_chats": 0,
                "negotiation_chats_list": [],
                "yara_rules": 0,
                "yara_rules_list": [],
                "iocs_count": 0,
                "iocs_list": [],
            },
            "targets": {
                "top_sectors": [],
                "top_countries": [],
                "sector_distribution": {},
                "country_distribution": {},
            },
            "active_regions": [],
            "initial_access_vectors": [],
            "tools_used_list": [],
            "cves": [],
            "related_groups": [],
            "external_links": {},
            "victim_domains": [],
            "iocs_list": [],
            "total_victims": 0,
        }

        group_lower = group_name.lower().strip()
        encoded_name = requests.utils.quote(group_lower, safe="")

        # ------------------------------------------------------------------
        # STEP 1 — v2 /group/<group_name> endpoint
        # ------------------------------------------------------------------
        logger.info(
            "Fetching group data for '%s' from Ransomware.live v2 API…", group_name
        )
        try:
            url = f"{self.BASE_URL}/group/{encoded_name}"
            group = self._safe_request(url, retries=3, backoff=1.0)

            if group and isinstance(group, dict):
                logger.info("✓ Found '%s' via /group endpoint", group_name)

                locations = group.get("locations", [])
                known_locs_list = [
                    loc["fqdn"]
                    for loc in locations
                    if isinstance(loc, dict) and loc.get("fqdn")
                ]

                # Tools: list of tactic-keyed dicts
                tools_list: Dict[str, List[str]] = {}
                tools_data = group.get("tools", [])
                if isinstance(tools_data, list) and tools_data:
                    first_entry = tools_data[0]
                    if isinstance(first_entry, dict):
                        for tactic, tool_names in first_entry.items():
                            if isinstance(tool_names, list):
                                tools_list[tactic] = tool_names

                def _safe_list(obj, key: str) -> list:
                    val = obj.get(key, [])
                    return val if isinstance(val, list) else []

                comprehensive_data.update(
                    {
                        "status": group.get("status", "Unknown"),
                        "description": group.get("description", ""),
                        "history": group.get(
                            "history", group.get("background", "")
                        ),
                        "statistics": {
                            "total_victims": 0,          # populated from website
                            "first_victim_date": "Unknown",
                            "last_victim_date": "Unknown",
                            "inactive_days": self._calculate_inactive_days(
                                group.get("last_activity", "")
                            ),
                            "avg_delay_days": "N/A",
                            "infostealer_percentage": 0.0,
                        },
                        "metadata": {
                            "known_locations": len(known_locs_list),
                            "known_locations_list": known_locs_list,
                            "ransom_notes": group.get("ransom_notes_count", 0),
                            "ransom_notes_list": _safe_list(group, "ransom_notes"),
                            "tools_used": len(tools_list),
                            "tools_used_list": tools_list,
                            "vulnerabilities_exploited": group.get(
                                "cves_count", group.get("vulnerabilities_count", 0)
                            ),
                            "vulnerabilities_list": _safe_list(group, "cves"),
                            "ttps_matrix": group.get(
                                "ttps_count", group.get("tactics_count", 0)
                            ),
                            "ttps_list": _safe_list(group, "ttps"),
                            "negotiation_chats": group.get("chats_count", 0),
                            "negotiation_chats_list": _safe_list(group, "chats"),
                            "yara_rules": group.get("yara_rules_count", 0),
                            "yara_rules_list": _safe_list(group, "yara_rules"),
                            "iocs_count": group.get("iocs_count", 0),
                            "iocs_list": _safe_list(group, "iocs"),
                        },
                        "active_regions": group.get("active_regions", []),
                        "initial_access_vectors": group.get(
                            "initial_access_vectors", []
                        ),
                        "tools_used_list": tools_list,
                        "cves": _safe_list(
                            group,
                            "exploited_cves" if group.get("exploited_cves") else "cves",
                        ),
                        "related_groups": group.get("related_groups", []),
                        "external_links": group.get("external_links", {}),
                        "victim_domains": [],
                        "iocs_list": _safe_list(group, "iocs"),
                        "total_victims": 0,
                        "targets": {
                            "top_sectors": [],
                            "top_countries": [],
                            "sector_distribution": {},
                            "country_distribution": {},
                        },
                    }
                )

        except requests.exceptions.RequestException as exc:
            logger.debug(
                "API endpoint /group/%s failed: %s", encoded_name, exc
            )

        # ------------------------------------------------------------------
        # STEP 2 — Website scraping for supplementary statistics
        # ------------------------------------------------------------------
        logger.info(
            "Fetching supplementary statistics from website for '%s'…", group_name
        )
        try:
            website_url = f"https://www.ransomware.live/group/{group_lower}"
            html = self._safe_request(
                website_url,
                headers=self.public_headers,
                expect_json=False,
                retries=3,
                backoff=1.0,
                allow_redirects=True,
            )
            if html:
                self._enrich_from_html(html, comprehensive_data)
        except Exception as exc:
            logger.debug(
                "Website scraping failed for '%s': %s", group_name, exc
            )

        return comprehensive_data

    def _enrich_from_html(self, html: str, data: Dict[str, Any]) -> None:
        """Parse the group page HTML and enrich *data* in-place.

        Extracts victim statistics, metadata counts, IoCs, victim domains,
        and detailed section data (locations, ransom notes, TTPs, CVEs).
        """
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            logger.warning(
                "beautifulsoup4 is not installed — HTML enrichment skipped. "
                "Install it with: pip install beautifulsoup4"
            )
            return

        soup = BeautifulSoup(html, "html.parser")

        # ------------------------------------------------------------------
        # 2A — Statistics boxes  (border-start divs with h6 label + h3/h4 value)
        # ------------------------------------------------------------------
        victims_count = 0
        first_date = "Unknown"
        last_date = "Unknown"
        inactive_days = 0
        avg_delay: Any = "N/A"
        infostealer_pct = 0.0

        for container in soup.find_all("div", class_="border-start"):
            label_tag = container.find("h6")
            value_tag = container.find("h3") or container.find("h4")
            if not (label_tag and value_tag):
                continue
            label_text = label_tag.get_text(strip=True).lower()
            value_text = value_tag.get_text(strip=True)

            if "victims" in label_text:
                try:
                    victims_count = int(value_text)
                except ValueError:
                    pass
            elif "first discovered" in label_text:
                first_date = value_text or "Unknown"
            elif "last discovered" in label_text:
                last_date = value_text or "Unknown"
            elif "inactive" in label_text:
                try:
                    inactive_days = int(value_text)
                except ValueError:
                    pass
            elif "avg delay" in label_text:
                avg_delay = value_text
            elif "infostealer" in label_text:
                m = re.search(r"(\d+\.?\d*)", value_text)
                if m:
                    try:
                        infostealer_pct = float(m.group(1))
                    except ValueError:
                        pass

        stats = data.setdefault("statistics", {})
        stats.update(
            {
                "total_victims": victims_count,
                "first_victim_date": first_date,
                "last_victim_date": last_date,
                "inactive_days": inactive_days,
                "avg_delay_days": avg_delay,
                "infostealer_percentage": infostealer_pct,
            }
        )
        data["total_victims"] = victims_count

        # ------------------------------------------------------------------
        # 2B — Metadata counts from span tags
        # ------------------------------------------------------------------
        meta = data.setdefault("metadata", {})
        locations_count = meta.get("known_locations", 0)
        ransom_notes_count = meta.get("ransom_notes", 0)
        tools_count = meta.get("tools_used", 0)
        vulnerabilities_count = meta.get("vulnerabilities_exploited", 0)
        ttps_count = meta.get("ttps_matrix", 0)
        chats_count = meta.get("negotiation_chats", 0)
        yara_count = meta.get("yara_rules", 0)
        iocs_count = meta.get("iocs_count", 0)

        for span in soup.find_all("span"):
            text = span.get_text(strip=True)
            m = re.search(r"\((\d+)\)", text)
            count = int(m.group(1)) if m else None

            if "Known Locations" in text and count is not None:
                locations_count = count
            elif "Ransom Notes" in text and count is not None:
                ransom_notes_count = count
            elif "Tools Used" in text:
                if "Available" in text:
                    tools_count = tools_count or 1
                elif count is not None:
                    tools_count = count
            elif "Vulnerabilities" in text and count is not None:
                vulnerabilities_count = count
            elif "TTPs" in text and count is not None:
                ttps_count = count
            elif "Negotiation Chats" in text and count is not None:
                chats_count = count
            elif "YARA" in text and count is not None:
                yara_count = count
            elif (
                "Indicators of Compromise" in text or "IoCs" in text
            ) and count is not None:
                iocs_count = count

        meta.update(
            {
                "known_locations": locations_count,
                "ransom_notes": ransom_notes_count,
                "tools_used": tools_count,
                "vulnerabilities_exploited": vulnerabilities_count,
                "ttps_matrix": ttps_count,
                "negotiation_chats": chats_count,
                "yara_rules": yara_count,
                "iocs_count": iocs_count,
            }
        )

        # ------------------------------------------------------------------
        # 2C — IoC extraction from #iocs-section
        # ------------------------------------------------------------------
        iocs_list: List[str] = list(meta.get("iocs_list", []))
        if iocs_count > 0:
            iocs_section = soup.find(id="iocs-section")
            if iocs_section:
                for item in iocs_section.find_all(["li", "tr", "div"]):
                    text = item.get_text(strip=True)
                    if text and len(text) > 3:
                        iocs_list.append(text)
        iocs_list = list(dict.fromkeys(iocs_list))
        meta["iocs_list"] = iocs_list
        data["iocs_list"] = iocs_list

        # ------------------------------------------------------------------
        # 2D — Victim domains from /id/ links
        # ------------------------------------------------------------------
        victim_domains: List[str] = []
        for link in soup.find_all("a", href=True):
            href = link.get("href", "")
            if "/id/" in href and "#infostealer" not in href:
                victim_text = link.get_text(strip=True)
                if victim_text:
                    victim_domains.append(victim_text)
        data["victim_domains"] = list(dict.fromkeys(victim_domains))

        # ------------------------------------------------------------------
        # 2E — Detailed section extraction by HTML id
        # ------------------------------------------------------------------

        # Known Locations
        locations_list: List[str] = list(meta.get("known_locations_list", []))
        locations_section = soup.find("div", id="locations-section")
        if locations_section:
            for row in locations_section.find_all("tr")[1:]:  # skip header row
                cols = row.find_all("td")
                if cols:
                    fqdn = cols[0].get_text(strip=True)
                    if fqdn:
                        locations_list.append(fqdn)
        meta["known_locations_list"] = list(dict.fromkeys(locations_list))
        meta["known_locations"] = len(meta["known_locations_list"])

        # Ransom Notes
        notes_list: List[str] = list(meta.get("ransom_notes_list", []))
        notes_section = (
            soup.find("div", id="ransom-notes-section")
            or soup.find("div", id="ransomNotes")
        )
        if notes_section:
            for item in notes_section.find_all(["li", "a", "p"]):
                text = item.get_text(strip=True)
                if text and len(text) > 3:
                    notes_list.append(text)
        meta["ransom_notes_list"] = list(dict.fromkeys(notes_list))
        meta["ransom_notes"] = len(meta["ransom_notes_list"])

        # TTPs
        ttps_list: List[str] = list(meta.get("ttps_list", []))
        ttps_section = (
            soup.find("div", id="ttps-section") or soup.find("div", id="ttps")
        )
        if ttps_section:
            for item in ttps_section.find_all(["li", "td", "span"]):
                text = item.get_text(strip=True)
                if text and len(text) > 2:
                    ttps_list.append(text)
        meta["ttps_list"] = list(dict.fromkeys(ttps_list))
        meta["ttps_matrix"] = len(meta["ttps_list"])

        # CVEs / Vulnerabilities
        vulnerabilities_list: List[str] = list(meta.get("vulnerabilities_list", []))
        cves_section = (
            soup.find("div", id="cves-section")
            or soup.find("div", id="vulnerabilities")
        )
        if cves_section:
            for item in cves_section.find_all(["li", "td", "span", "a"]):
                text = item.get_text(strip=True)
                if re.match(r"CVE-\d{4}-\d+", text):
                    vulnerabilities_list.append(text)
        # Also pick up inline CVE references anywhere on the page
        for tag in soup.find_all(string=re.compile(r"CVE-\d{4}-\d+")):
            for cve in re.findall(r"CVE-\d{4}-\d+", str(tag)):
                vulnerabilities_list.append(cve)
        meta["vulnerabilities_list"] = list(dict.fromkeys(vulnerabilities_list))
        meta["vulnerabilities_exploited"] = len(meta["vulnerabilities_list"])
        data["cves"] = meta["vulnerabilities_list"]
