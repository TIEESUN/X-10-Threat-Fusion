"""
Intelligence Aggregator - Main Streamlit Application
Integrates multiple threat intelligence sources into one place
"""

# CRITICAL: Load environment FIRST before any other imports
import os
from dotenv import load_dotenv
load_dotenv(override=True)  # Force reload

import streamlit as st
import pandas as pd
from typing import Dict, Any, List
import logging
from datetime import datetime
import time
import re
import json

# Configure Streamlit page
st.set_page_config(
    page_title="🔍 X-10 ThreatFusion",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add this CSS for better tab styling and scrolling
CUSTOM_TAB_CSS = """
<style>
/* Better tab styling for horizontal scrolling */
.stTabs [data-baseweb="tab-list"] {
    gap: 0;
    background-color: #1a1a1a;
    padding: 0;
    overflow-x: auto;
    overflow-y: hidden;
    white-space: nowrap;
    display: flex;
    flex-wrap: nowrap;
    max-width: 100%;
    scrollbar-width: thin;
    scrollbar-color: #ff4444 #1a1a1a;
}

.stTabs [data-baseweb="tab-list"]::-webkit-scrollbar {
    height: 6px;
}

.stTabs [data-baseweb="tab-list"]::-webkit-scrollbar-track {
    background: #1a1a1a;
}

.stTabs [data-baseweb="tab-list"]::-webkit-scrollbar-thumb {
    background: #ff4444;
    border-radius: 3px;
}

.stTabs [data-baseweb="tab"] {
    flex-shrink: 0;
    min-width: 120px;
    max-width: 150px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    padding: 10px 15px;
    margin: 0;
    border-radius: 0;
    border-bottom: 3px solid transparent;
    color: #ff4444;
    font-weight: 500;
    font-size: 13px;
}

.stTabs [aria-selected="true"] {
    color: #ff4444 !important;
    border-bottom-color: #ff4444 !important;
    background-color: #252525 !important;
}

.stTabs [data-baseweb="tab"]:hover {
    background-color: #252525 !important;
    color: #ffffff !important;
}

.stTabs [data-baseweb="tab-panel"] {
    padding-top: 20px;
}
</style>
"""

# Add this to your main() function or after the CSS definitions:
st.markdown(CUSTOM_TAB_CSS, unsafe_allow_html=True)

# Apply dark theme CSS with red/black/white color scheme
dark_theme_css = """
<style>
    /* Dark theme background - Red, Black, White theme */
    :root {
        --bg-primary: #0a0a0a;
        --bg-secondary: #1a1a1a;
        --bg-tertiary: #252525;
        --text-primary: #ffffff;
        --text-secondary: #ff4444;
        --accent-red: #e63946;
        --accent-orange: #ff6b35;
        --accent-yellow: #ffd60a;
        --accent-green: #2ecc71;
        --accent-blue: #ff4444;
        --accent-cyan: #ff6b6b;
        --accent-purple: #9b59b6;
        --border-color: #3a0000;
    }
    
    /* Translucent Akatsuki clouds background */
    body::before {
        content: '';
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-image: 
            radial-gradient(ellipse 800px 400px at 20% 30%, rgba(230, 57, 70, 0.08) 0%, transparent 50%),
            radial-gradient(ellipse 900px 450px at 80% 70%, rgba(230, 57, 70, 0.06) 0%, transparent 50%),
            radial-gradient(ellipse 700px 350px at 50% 80%, rgba(230, 57, 70, 0.07) 0%, transparent 50%);
        background-attachment: fixed;
        pointer-events: none;
        z-index: -1;
    }
    
    /* SVG cloud patterns - Akatsuki style */
    .cloud-bg {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        pointer-events: none;
        z-index: -1;
        opacity: 0.12;
    }
    
    /* Disable image expand button */
    img {
        pointer-events: none !important;
    }
    
    button[title="View fullscreen"] {
        display: none !important;
    }
    
    [data-testid="stImage"] button {
        display: none !important;
    }
    
    /* Hide Streamlit header bar */
    [data-testid="stHeader"] {
        display: none !important;
    }
    
    header {
        display: none !important;
    }
    
    /* Remove ALL top padding and margins */
    [data-testid="stMainBlockContainer"] {
        padding-top: 0 !important;
        margin-top: 0 !important;
        padding: 0 !important;
    }
    
    .stApp {
        padding-top: 0 !important;
        margin-top: 0 !important;
        padding: 0 !important;
        top: 0 !important;
    }
    
    /* Remove gap before content */
    [data-testid="stVerticalBlock"] > div:first-child {
        margin-top: 0 !important;
        padding-top: 0 !important;
    }
    
    /* Target root elements */
    div[class*="stVerticalBlock"] {
        margin-top: 0 !important;
        padding-top: 0 !important;
    }
    
    /* Remove toolbar space */
    .main .block-container {
        padding-top: 0 !important;
        margin-top: 0 !important;
    }
    
    * {
        scrollbar-color: var(--accent-blue) var(--bg-secondary);
        scrollbar-width: thin;
    }
    
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: var(--bg-secondary);
    }
    
    ::-webkit-scrollbar-thumb {
        background: var(--accent-blue);
        border-radius: 4px;
    }
    
    body {
        background-color: var(--bg-primary) !important;
        color: var(--text-primary) !important;
    }
    
    .stApp {
        background-color: var(--bg-primary) !important;
    }
    
    [data-testid="stSidebar"] {
        background-color: var(--bg-secondary) !important;
        border-right: 2px solid var(--border-color) !important;
    }
    
    [data-testid="stMainBlockContainer"] {
        background-color: var(--bg-primary) !important;
        color: var(--text-primary) !important;
    }
    
    .stTabs [data-baseweb="tab-list"] {
        background-color: var(--bg-tertiary) !important;
        gap: 0;
        border-bottom: 2px solid var(--border-color) !important;
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: 0 !important;
        border-bottom: 3px solid transparent !important;
        color: var(--text-secondary) !important;
        padding: 10px 20px !important;
        font-weight: 500 !important;
    }
    
    .stTabs [aria-selected="true"] [data-baseweb="tab"] {
        color: var(--accent-blue) !important;
        border-bottom-color: var(--accent-blue) !important;
        background-color: var(--bg-secondary) !important;
    }
    
    .stExpander {
        background-color: var(--bg-tertiary) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
    }
    
    .stExpander > div > div:first-child {
        color: var(--text-primary) !important;
    }
    
    .stExpander > div > div:nth-child(2) {
        color: var(--text-primary) !important;
    }
    
    .stMetricLabel {
        color: var(--text-secondary) !important;
        font-size: 12px !important;
        font-weight: bold !important;
    }
    
    .stMetricValue {
        color: var(--accent-yellow) !important;
        font-size: 28px !important;
        font-weight: bold !important;
    }
    
    /* Card-like styling */
    .metric-card {
        background-color: var(--bg-tertiary) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 8px !important;
        padding: 16px !important;
        margin: 12px 0 !important;
    }
    
    .card-header {
        color: var(--accent-blue) !important;
        font-size: 18px !important;
        font-weight: bold !important;
        margin-bottom: 12px !important;
        border-bottom: 2px solid var(--border-color) !important;
        padding-bottom: 8px !important;
    }
    
    .threat-critical {
        color: var(--accent-red) !important;
        font-weight: bold !important;
    }
    
    .threat-high {
        color: var(--accent-orange) !important;
        font-weight: bold !important;
    }
    
    .threat-medium {
        color: var(--accent-yellow) !important;
        font-weight: bold !important;
    }
    
    .threat-low {
        color: var(--accent-green) !important;
        font-weight: bold !important;
    }
    
    /* Headers */
    h1, h2, h3, h4, h5, h6 {
        color: var(--text-primary) !important;
    }
    
    h1 {
        color: var(--accent-yellow) !important;
    }
    
    h2 {
        border-bottom: 2px solid var(--border-color) !important;
        padding-bottom: 8px !important;
        color: var(--accent-yellow) !important;
    }
    
    h3, h4, h5, h6 {
        color: var(--text-secondary) !important;
    }
    
    /* General text */
    p, label, span, div {
        color: var(--text-primary) !important;
    }
    
    /* Input fields */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > select {
        background-color: var(--bg-tertiary) !important;
        color: var(--text-primary) !important;
        border-color: var(--border-color) !important;
    }
    
    /* Buttons */
    .stButton > button {
        background-color: var(--accent-blue) !important;
        color: #ffffff !important;
        border: 2px solid var(--accent-blue) !important;
        border-radius: 6px !important;
        font-weight: bold !important;
        font-size: 14px !important;
        transition: all 0.3s ease !important;
        padding: 10px 20px !important;
    }
    
    .stButton > button:hover {
        background-color: var(--accent-purple) !important;
        border-color: var(--accent-purple) !important;
        box-shadow: 0 4px 12px rgba(155, 89, 182, 0.5) !important;
        transform: translateY(-2px) !important;
    }
    
    /* Download buttons styling */
    .stDownloadButton > button {
        background: linear-gradient(135deg, var(--accent-blue) 0%, var(--accent-cyan) 100%) !important;
        color: #ffffff !important;
        border: 2px solid var(--accent-blue) !important;
        border-radius: 6px !important;
        font-weight: bold !important;
        font-size: 14px !important;
        transition: all 0.3s ease !important;
        padding: 10px 20px !important;
    }
    
    .stDownloadButton > button:hover {
        background: linear-gradient(135deg, var(--accent-cyan) 0%, var(--accent-blue) 100%) !important;
        border-color: var(--accent-cyan) !important;
        box-shadow: 0 4px 12px rgba(0, 188, 212, 0.5) !important;
    }
    
    /* Alert boxes */
    .stAlert {
        border-radius: 8px !important;
        border: 2px solid !important;
        background-color: rgba(10, 14, 39, 0.8) !important;
    }
    
    .stSuccess {
        background-color: rgba(46, 204, 113, 0.15) !important;
        border-color: var(--accent-green) !important;
    }
    
    .stError {
        background-color: rgba(255, 71, 87, 0.15) !important;
        border-color: var(--accent-red) !important;
    }
    
    .stWarning {
        background-color: rgba(255, 165, 2, 0.15) !important;
        border-color: var(--accent-orange) !important;
    }
    
    .stInfo {
        background-color: rgba(52, 152, 219, 0.15) !important;
        border-color: var(--accent-blue) !important;
    }
    
    /* Data display */
    .dataframe {
        background-color: var(--bg-tertiary) !important;
    }

    /* Make summary/report areas horizontally scrollable */
    .report-wrapper {
        overflow-x: auto;
        width: 100%;
    }

    table {
        border-collapse: collapse;
        width: 100%;
    }
    
    th {
        background-color: var(--bg-secondary) !important;
        color: var(--accent-blue) !important;
        border-bottom: 2px solid var(--accent-blue) !important;
        padding: 12px !important;
        text-align: left;
        font-weight: bold;
    }
    
    td {
        padding: 10px !important;
        border-bottom: 1px solid var(--border-color) !important;
        color: var(--text-primary) !important;
    }
    
    /* Markdown elements */
    code {
        background-color: var(--bg-tertiary) !important;
        color: var(--accent-yellow) !important;
        padding: 2px 6px !important;
        border-radius: 4px !important;
    }
    
    pre {
        background-color: var(--bg-secondary) !important;
        border: 1px solid var(--border-color) !important;
        border-radius: 6px !important;
        padding: 12px !important;
        color: var(--accent-green) !important;
    }
    
    /* Checkbox and Radio */
    .stCheckbox > label,
    .stRadio > label {
        color: var(--text-primary) !important;
    }
    
    /* Divider */
    hr {
        border-color: var(--border-color) !important;
    }
</style>
"""

st.markdown(dark_theme_css, unsafe_allow_html=True)

# Import our modules
from apis import (
    VirusTotalAPI,
    ShodanAPI,
    OTXAlienVaultAPI,
    IPInfoAPI,
    AbuseIPDBAPI,
    URLHausAPI,
    URLscanAPI,
    IPDetectiveAPI,
    GetIPIntelAPI,
    RansomwareLiveAPI,
    HunterAPI,
    MalwareBazaarAPI,
    ThreatFoxAPI,
    YARAifyAPI,
    SSLBLAPI,
    FeodoTrackerAPI,
)

from utils import (
    Config,
    classify_observable,
    get_threat_level,
    extract_key_findings,
    create_summary_report,
    get_analytics_data,
    format_results_for_export,
    parse_indicators_from_file,
    validate_batch_indicators,
    export_batch_results_json,
    export_batch_results_txt,
    create_individual_batch_reports,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# CSS already applied above with dark theme


def initialize_session_state():
    """Initialize session state variables"""
    if "results" not in st.session_state:
        st.session_state.results = {}
    if "observable" not in st.session_state:
        st.session_state.observable = ""
    if "last_query" not in st.session_state:
        st.session_state.last_query = None
    if "batch_results" not in st.session_state:
        st.session_state.batch_results = {}
    if "batch_mode" not in st.session_state:
        st.session_state.batch_mode = False


def run_analysis(observable: str, selected_sources: list) -> Dict[str, Any]:
    """
    Run analysis across selected sources with bidirectional correlation
    Handles IP:port format by passing full format to ThreatFox, IP-only to other sources
    """
    from utils.helpers import parse_ip_port
    
    results = {}
    clients = get_api_clients()
    identified_groups = set()
    
    # Parse IP:port format if present
    base_observable, port_number, has_port = parse_ip_port(observable)
    
    # Track if we're missing port for ThreatFox
    missing_port_for_threatfox = False
    if not has_port and re.match(r"^(\d{1,3}\.){3}\d{1,3}$", base_observable):
        ip_parts = base_observable.split(".")
        if all(0 <= int(part) <= 255 for part in ip_parts):
            missing_port_for_threatfox = True
    
    # Phase 1: Initial analysis across all sources
    for source_name, client in clients.items():
        if source_name not in selected_sources:
            continue
        
        try:
            # ThreatFox needs full IP:port format, others need just the base observable
            if source_name == "ThreatFox":
                if missing_port_for_threatfox:
                    # Skip ThreatFox if we have just an IP
                    results[source_name] = {
                        "query_status": "skipped",
                        "message": "⚠️ ThreatFox requires IP:port format (e.g., 139.180.203.104:443). Please include the port number for ThreatFox results.",
                        "source": "ThreatFox"
                    }
                    continue
                else:
                    # Pass full observable (with port) to ThreatFox
                    result = client.analyze(observable)
            else:
                # Pass base observable (without port) to other sources
                result = client.analyze(base_observable)
            
            results[source_name] = result
            
            # Extract group names if identified by this source
            if isinstance(result, dict):
                # Check for group field (common in ransomware APIs)
                if "group" in result and result["group"] and result["group"] != "Unknown":
                    identified_groups.add(result["group"])
                
                # Check in associated_groups field
                if "associated_groups" in result:
                    groups = result.get("associated_groups", {})
                    if isinstance(groups, dict) and "matched_groups" in groups:
                        for g in groups.get("matched_groups", []):
                            if isinstance(g, dict) and "name" in g:
                                identified_groups.add(g["name"])
                
                # Check in victims list for group names
                if "victims" in result and isinstance(result["victims"], list):
                    for victim in result["victims"]:
                        if isinstance(victim, dict) and "group" in victim:
                            group = victim.get("group", "").strip()
                            if group and group != "Unknown":
                                identified_groups.add(group)
                
        except Exception as e:
            logger.error(f"Error querying {source_name}: {e}")
            results[source_name] = {"error": str(e)}
    
    # Phase 2: Bidirectional correlation - if groups identified, query Ransomware.live
    if identified_groups and "Ransomware.live" in selected_sources:
        try:
            ransomware_client = clients.get("Ransomware.live")
            if ransomware_client:
                for group_name in identified_groups:
                    # Get group-specific intelligence
                    group_result = ransomware_client.analyze_group(group_name)
                    
                    # Add to existing Ransomware.live results or create new entry
                    if "Ransomware.live" in results:
                        if "identified_groups" not in results["Ransomware.live"]:
                            results["Ransomware.live"]["identified_groups"] = {}
                        results["Ransomware.live"]["identified_groups"][group_name] = group_result
                    else:
                        results["Ransomware.live"] = {
                            "identified_groups": {group_name: group_result}
                        }
        except Exception as e:
            logger.error(f"Error in bidirectional correlation: {e}")
    
    return results


def run_batch_analysis(indicators: list, selected_sources: list) -> Dict[str, Dict[str, Any]]:
    """
    Run analysis for multiple indicators
    Returns dict with indicator as key and results as value
    """
    batch_results = {}
    clients = get_api_clients()
    
    total_indicators = len(indicators)
    total_sources = len(selected_sources)
    total_operations = total_indicators * total_sources
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    current_operation = 0
    
    for idx, indicator_data in enumerate(indicators, 1):
        indicator = indicator_data["indicator"]
        status_text.text(f"Processing {idx}/{total_indicators}: {indicator}")
        
        indicator_results = {}
        
        for source_name, client in clients.items():
            if source_name not in selected_sources:
                continue
            
            try:
                result = client.analyze(indicator)
                indicator_results[source_name] = result
                time.sleep(0.1)  # Small delay to avoid rate limiting
            except Exception as e:
                logger.error(f"Error querying {source_name} for {indicator}: {e}")
                indicator_results[source_name] = {"error": str(e)}
            
            current_operation += 1
            progress = int((current_operation / total_operations) * 100)
            progress_bar.progress(progress)
        
        batch_results[indicator] = indicator_results
    
    progress_bar.empty()
    status_text.empty()
    
    return batch_results


def run_threat_group_analysis(threat_group: str, selected_sources: list) -> Dict[str, Any]:
    """
    Run analysis for a threat group with TWO-PHASE approach:
    Phase 1: Get threat group data from Ransomware.live (always first)
    Phase 2: Query victim domains against ALL selected sources
    """
    results = {}
    clients = get_api_clients()
    victim_domains = []
    
    # ===== PHASE 1: Get threat group info from Ransomware.live =====
    ransomware_client = clients.get("Ransomware.live")
    if ransomware_client:
        try:
            result = ransomware_client.analyze_group(threat_group)
            results["Ransomware.live"] = result
            
            # Extract victim domains and other indicators for Phase 2
            if "victim_domains" in result:
                victim_domains = result.get("victim_domains", [])
            
            # Extract ONLY IoCs for Phase 2 (from iocs-section, not victim links)
            phase2_indicators = result.get("phase2_indicators", {})
                    
        except Exception as e:
            logger.error(f"Error querying Ransomware.live for group {threat_group}: {e}")
            results["Ransomware.live"] = {"error": str(e)}
    
    # ===== PHASE 2: Query ONLY IoCs (domains, IPs, hashes) against ALL selected sources =====
    if phase2_indicators and (phase2_indicators.get("all_iocs") or phase2_indicators.get("domains")):
        # Query ONLY IoCs against all selected sources
        all_domain_results = {}
        
        # Get IoCs by type
        domains_to_query = phase2_indicators.get("domains", [])[:5]  # Query top 5 domains
        ips_to_query = phase2_indicators.get("ips", [])[:5]  # Query top 5 IPs
        hashes_to_query = phase2_indicators.get("hashes", [])[:5]  # Query top 5 hashes
        
        # Combine all IoCs to query
        all_iocs = domains_to_query + ips_to_query + hashes_to_query
        
        if all_iocs and len(all_iocs) > 0:
            st.write("")  # Spacing
            progress_text = st.empty()
            progress_bar = st.progress(0)
            
            total_queries = len(all_iocs) * len(selected_sources)
            current_query = 0
            
            for ioc_idx, ioc in enumerate(all_iocs):
                ioc_results = {}
                
                for source_name, client in clients.items():
                    if source_name == "Ransomware.live" or source_name not in selected_sources:
                        continue
                    
                    current_query += 1
                    progress_text.text(f"Querying IoC {ioc} on {source_name}... ({current_query}/{total_queries})")
                    
                    try:
                        result = client.analyze(ioc)
                        ioc_results[source_name] = result
                        time.sleep(0.15)  # Avoid rate limiting
                    except Exception as e:
                        logger.debug(f"Error querying {source_name} for IoC {ioc}: {e}")
                        ioc_results[source_name] = {"error": str(e)}
                    
                    progress_bar.progress(current_query / total_queries)
                
                all_domain_results[ioc] = ioc_results
            
            progress_bar.empty()
            progress_text.empty()
            
            # Store correlation results
            if all_domain_results:
                results["victim_domain_correlation"] = all_domain_results
    
    return results


def extract_iocs_from_group(ransomware_results: Dict[str, Any]) -> List[str]:
    """
    Extract IOCs from Ransomware.live group analysis results
    
    Args:
        ransomware_results: Results from Ransomware.live analyze_group()
        
    Returns:
        List of IOCs (IPs, domains, etc.)
    """
    iocs = []
    
    if not isinstance(ransomware_results, dict):
        return iocs
    
    # Extract from group_iocs field
    if "group_iocs" in ransomware_results and isinstance(ransomware_results["group_iocs"], list):
        for ioc in ransomware_results["group_iocs"]:
            if isinstance(ioc, dict):
                # IOC might be {'type': 'domain', 'value': 'example.com'} or similar
                if "value" in ioc:
                    iocs.append(ioc["value"])
                elif "ioc" in ioc:
                    iocs.append(ioc["ioc"])
                elif "indicator" in ioc:
                    iocs.append(ioc["indicator"])
            elif isinstance(ioc, str):
                iocs.append(ioc)
    
    # Extract from group_info if it has IOCs
    if "group_info" in ransomware_results and isinstance(ransomware_results["group_info"], dict):
        group_info = ransomware_results["group_info"]
        
        # Check for common IOC fields
        for field in ["iocs", "indicators", "domains", "ips", "c2_servers"]:
            if field in group_info:
                field_data = group_info[field]
                if isinstance(field_data, list):
                    iocs.extend([str(x) for x in field_data])
                elif isinstance(field_data, str):
                    iocs.append(field_data)
    
    # Remove duplicates and limit to 10 most relevant
    iocs = list(set(iocs))[:10]
    return iocs


def display_threat_group_results(results: Dict[str, Any], threat_group: str):
    """
    Display comprehensive threat group analysis results with all Ransomware.live intelligence
    """
    if not results:
        st.error("No results found")
        return
    
    # ===== SECTION 1: COMPREHENSIVE GROUP INTELLIGENCE =====
    ransomware_result = results.get("Ransomware.live", {})
    
    if isinstance(ransomware_result, dict) and "error" not in ransomware_result:
        st.markdown("---")
        
        # ===== Header with Group Name and Status =====
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            st.markdown(f"### 🎯 **{threat_group}**")
        with col2:
            status = ransomware_result.get("status", "Unknown").upper()
            if "ACTIVE" in status:
                st.markdown(f"<p style='color: #ff4757; font-weight: bold; font-size: 16px;'>🔴 {status}</p>", unsafe_allow_html=True)
            else:
                st.markdown(f"<p style='color: #95a5a6; font-weight: bold; font-size: 16px;'>⚫ {status}</p>", unsafe_allow_html=True)
        with col3:
            threat_level = ransomware_result.get("threat_level", "unknown").upper()
            if threat_level == "CRITICAL":
                st.markdown(f"<p style='color: #ff4757; font-weight: bold; font-size: 16px;'>⚠️ {threat_level}</p>", unsafe_allow_html=True)
            else:
                st.markdown(f"<p style='color: #ffa502; font-weight: bold; font-size: 16px;'>📊 {threat_level}</p>", unsafe_allow_html=True)
        
        # ===== Description and History =====
        if ransomware_result.get("description"):
            with st.expander("📖 **Group Description & History**", expanded=True):
                st.markdown(f"**Description:** {ransomware_result.get('description', 'N/A')}")
                if ransomware_result.get("history"):
                    st.markdown(f"\n**History:** {ransomware_result.get('history', 'N/A')}")
        
        # ===== Key Statistics =====
        st.markdown("#### 📊 **Group Statistics**")
        stats = ransomware_result.get("statistics", {})
        
        stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
        with stat_col1:
            st.metric("Total Victims", stats.get("total_victims", 0), delta=None)
        with stat_col2:
            avg_delay = stats.get('avg_delay_days', 0)
            if isinstance(avg_delay, str):
                st.metric("Avg Delay", avg_delay, delta=None)
            else:
                st.metric("Avg Delay (days)", f"{avg_delay:.1f}" if avg_delay else "N/A", delta=None)
        with stat_col3:
            st.metric("Inactive Since (days)", stats.get("inactive_days", 0), delta=None)
        with stat_col4:
            infostealer = stats.get('infostealer_percentage', 0)
            if isinstance(infostealer, str):
                st.metric("Infostealer %", infostealer, delta=None)
            else:
                st.metric("Infostealer %", f"{infostealer:.1f}%" if infostealer else "0%", delta=None)
        
        # Date range
        date_col1, date_col2 = st.columns(2)
        with date_col1:
            st.info(f"🔵 **First Victim Discovered:** {stats.get('first_victim_date', 'Unknown')}")
        with date_col2:
            st.info(f"🔴 **Last Victim Discovered:** {stats.get('last_victim_date', 'Unknown')}")
        
        st.markdown("---")
        
        # ===== KNOWN LOCATIONS =====
        known_locations_list = ransomware_result.get("metadata", {}).get("known_locations_list", [])
        locations_count = ransomware_result.get("metadata", {}).get("known_locations", 0)
        if known_locations_list or locations_count > 0:
            st.markdown(f"#### 🌐 **Known Locations ({locations_count})**")
            if known_locations_list:
                with st.expander("View Locations", expanded=True):
                    for i, location in enumerate(known_locations_list[:20], 1):
                        st.text(f"{i}. {location}")
                    if len(known_locations_list) > 20:
                        st.caption(f"Showing 20 of {len(known_locations_list)} locations")
            else:
                st.info(f"✓ {locations_count} location(s) available")
        
        st.markdown("---")
        
        # ===== Intelligence Metadata =====
        st.markdown("#### 🔍 **Intelligence Metadata Summary**")
        metadata = ransomware_result.get("metadata", {})
        
        # Row 1: Main metadata counts
        meta_col1, meta_col2, meta_col3, meta_col4 = st.columns(4)
        with meta_col1:
            ransom_notes = metadata.get("ransom_notes", 0)
            st.metric("📄 Ransom Notes", ransom_notes)
        with meta_col2:
            tools = metadata.get("tools_used", 0)
            st.metric("🛠️ Tools Used", tools)
        with meta_col3:
            cves = metadata.get("vulnerabilities_exploited", 0)
            st.metric("🔴 CVEs Exploited", cves)
        with meta_col4:
            ttps = metadata.get("ttps_matrix", 0)
            st.metric("📊 TTPs Matrix", ttps)
        
        # Row 2: Intelligence counts
        meta_col5, meta_col6, meta_col7, meta_col8 = st.columns(4)
        with meta_col5:
            chats = metadata.get("negotiation_chats", 0)
            st.metric("💬 Negotiation Chats", chats)
        with meta_col6:
            yara = metadata.get("yara_rules", 0)
            st.metric("🔐 YARA Rules", yara)
        with meta_col7:
            iocs = metadata.get("iocs_count", 0)
            st.metric("🎯 IoCs Available", iocs)
        
        st.markdown("---")
        
        # ===== TARGET INFORMATION (Top Sectors & Countries) =====
        targets = ransomware_result.get("targets", {})
        top_sectors = targets.get("top_sectors", [])
        top_countries = targets.get("top_countries", [])
        
        if top_sectors or top_countries:
            st.markdown("#### 🎯 **Target Information**")
            
            if top_sectors:
                st.markdown("**Top 5 Activity Sectors:**")
                sector_col1, sector_col2 = st.columns(2)
                for i, sector_data in enumerate(top_sectors[:5], 1):
                    if isinstance(sector_data, dict):
                        sector_name = sector_data.get("name", "Unknown")
                        count = sector_data.get("count", 0)
                        with sector_col1 if i % 2 == 1 else sector_col2:
                            st.markdown(f"{i}. {sector_name} - **{count}** victims")
                    else:
                        with sector_col1 if i % 2 == 1 else sector_col2:
                            st.markdown(f"{i}. {sector_data}")
            
            if top_countries:
                st.markdown("**Top 5 Target Countries:**")
                country_col1, country_col2 = st.columns(2)
                for i, country_data in enumerate(top_countries[:5], 1):
                    if isinstance(country_data, dict):
                        country_name = country_data.get("name", "Unknown")
                        count = country_data.get("count", 0)
                        with country_col1 if i % 2 == 1 else country_col2:
                            st.markdown(f"{i}. {country_name} - **{count}** victims")
                    else:
                        with country_col1 if i % 2 == 1 else country_col2:
                            st.markdown(f"{i}. {country_data}")
        
        st.markdown("---")
        
        # ===== DETAILED RANSOM NOTES =====
        ransom_notes_list = metadata.get("ransom_notes_list", [])
        if ransom_notes_list:
            with st.expander(f"📄 **Ransom Notes ({len(ransom_notes_list)})**", expanded=False):
                for i, note in enumerate(ransom_notes_list[:50], 1):
                    if isinstance(note, dict):
                        note_name = note.get("name", "Unknown")
                        note_url = note.get("url", "")
                        st.markdown(f"**{i}. {note_name}**")
                        if note_url:
                            st.markdown(f"[View Note]({note_url})")
                    else:
                        st.markdown(f"{i}. {note}")
                if len(ransom_notes_list) > 50:
                    st.caption(f"Showing 50 of {len(ransom_notes_list)} ransom notes")
        
        st.markdown("---")
        
        # ===== DETAILED TOOLS USED (Classified by Tactic) =====
        tools_list = metadata.get("tools_used_list", [])
        if tools_list:
            if isinstance(tools_list, dict) and len(tools_list) > 0:
                total_tools = sum(len(tools) if isinstance(tools, list) else 0 for tools in tools_list.values())
                st.markdown(f"#### 🛠️ **Tools Used by Group ({total_tools} tools, {len(tools_list)} tactics)**")
                with st.expander("View Tools by Tactic", expanded=True):
                    for tactic, tools in sorted(tools_list.items()):
                        if isinstance(tools, list) and len(tools) > 0:
                            # Filter out placeholders
                            valid_tools = [t for t in tools if t and 'placeholder' not in t.lower()]
                            if valid_tools:
                                st.markdown(f"**{tactic}** ({len(valid_tools)} tools)")
                                for tool in valid_tools:
                                    st.markdown(f"  • {tool}")
                                st.divider()
            else:
                # Fallback for old list format
                st.markdown(f"#### 🛠️ **Tools Used by Group ({len(tools_list) if isinstance(tools_list, list) else 0})**")
                with st.expander(f"View Tools", expanded=False):
                    cols = st.columns(2)
                    for i, tool in enumerate(tools_list[:50] if isinstance(tools_list, list) else []):
                        with cols[i % 2]:
                            st.markdown(f"• {tool}")
        
        st.markdown("---")
        
        # ===== DETAILED VULNERABILITIES/CVEs =====
        vuln_list = metadata.get("vulnerabilities_list", [])
        if vuln_list:
            st.markdown(f"#### 🔴 **Vulnerabilities Exploited ({len(vuln_list)})**")
            with st.expander(f"View {len(vuln_list)} CVEs", expanded=False):
                cols = st.columns(2)
                for i, cve in enumerate(vuln_list[:50]):
                    with cols[i % 2]:
                        st.markdown(f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})")
                if len(vuln_list) > 50:
                    st.caption(f"Showing 50 of {len(vuln_list)} CVEs")
        
        st.markdown("---")
        
        # ===== DETAILED TTPs/TACTICS =====
        ttps_list = metadata.get("ttps_list", [])
        if ttps_list:
            st.markdown(f"#### 📊 **TTPs (Tactics, Techniques & Procedures) ({len(ttps_list)})**")
            with st.expander(f"View {len(ttps_list)} TTPs", expanded=False):
                cols = st.columns(2)
                for i, ttp in enumerate(ttps_list[:50]):
                    with cols[i % 2]:
                        st.markdown(f"• {ttp}")
                if len(ttps_list) > 50:
                    st.caption(f"Showing 50 of {len(ttps_list)} TTPs")
        
        st.markdown("---")
        
        # ===== DETAILED NEGOTIATION CHATS =====
        chats_list = metadata.get("negotiation_chats_list", [])
        if chats_list:
            st.markdown(f"#### 💬 **Negotiation Chats ({len(chats_list)})**")
            with st.expander(f"View {len(chats_list)} Negotiation Chats", expanded=False):
                for i, chat in enumerate(chats_list[:50], 1):
                    if isinstance(chat, dict):
                        chat_title = chat.get("title", "Unknown")
                        chat_url = chat.get("url", "")
                        st.markdown(f"**{i}. {chat_title}**")
                        if chat_url:
                            st.caption(f"URL: {chat_url}")
                    else:
                        st.markdown(f"{i}. {chat}")
                if len(chats_list) > 50:
                    st.caption(f"Showing 50 of {len(chats_list)} chats")
        
        st.markdown("---")
        
        # ===== DETAILED YARA RULES =====
        yara_list = metadata.get("yara_rules_list", [])
        if yara_list:
            st.markdown(f"#### 🔐 **YARA Rules ({len(yara_list)})**")
            with st.expander(f"View {len(yara_list)} YARA Rules", expanded=False):
                for i, rule in enumerate(yara_list[:50], 1):
                    if isinstance(rule, dict):
                        rule_name = rule.get("name", "Unknown")
                        rule_url = rule.get("url", "")
                        st.markdown(f"**{i}. {rule_name}**")
                        if rule_url:
                            st.caption(f"URL: {rule_url}")
                    else:
                        st.markdown(f"{i}. {rule}")
                if len(yara_list) > 50:
                    st.caption(f"Showing 50 of {len(yara_list)} YARA rules")
        
        st.markdown("---")
        
        # ===== Tactical Information =====
        if ransomware_result.get("initial_access_vectors"):
            with st.expander("🚀 **Initial Access Vectors**", expanded=False):
                vectors = ransomware_result.get("initial_access_vectors", [])
                for i, vector in enumerate(vectors, 1):
                    st.markdown(f"{i}. {vector}")
        
        # ===== CVEs Exploited (API) =====
        if ransomware_result.get("cves"):
            with st.expander("🔴 **CVEs from API Data**", expanded=False):
                cves = ransomware_result.get("cves", [])
                for cve in cves:
                    st.markdown(f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})")
        
        # ===== Active Regions =====
        if ransomware_result.get("active_regions"):
            with st.expander("🌍 **Active Regions**", expanded=False):
                regions = ransomware_result.get("active_regions", [])
                st.markdown(", ".join(regions))
        
        # ===== Related Groups =====
        if ransomware_result.get("related_groups"):
            with st.expander("🔗 **Related Groups**", expanded=False):
                related = ransomware_result.get("related_groups", [])
                for group in related:
                    st.markdown(f"• {group}")
        
        st.markdown("---")
        
        # ===== Display Victim Domains =====
        total_victims = ransomware_result.get("statistics", {}).get("total_victims", 0)
        victim_domains = ransomware_result.get("victim_domains", [])
        
        st.markdown(f"#### 👥 **Victims ({total_victims} in database)**")
        st.info(f"🔗 **{len(victim_domains)} victim domains extracted for Phase 2 analysis across all intelligence sources**")
        
        if victim_domains:
            with st.expander(f"View {len(victim_domains)} Extracted Victim Domains", expanded=False):
                # Create victims table
                victims_data = []
                for i, domain in enumerate(victim_domains[:100], 1):  # Show top 100
                    victims_data.append({
                        "#": i,
                        "Victim Domain": domain
                    })
                
                if victims_data:
                    df_victims = pd.DataFrame(victims_data)
                    st.dataframe(
                        df_victims,
                        use_container_width=True,
                        hide_index=True,
                        column_config={
                            "#": st.column_config.NumberColumn("#", width="small"),
                            "Victim Domain": st.column_config.TextColumn("Victim Domain", width="large"),
                        }
                    )
                    
                    if len(victim_domains) > 100:
                        st.caption(f"Showing 100 of {len(victim_domains)} victims")
        
        st.markdown("---")
        
        # ===== Display IoCs =====
        iocs_count = ransomware_result.get("metadata", {}).get("iocs_count", 0)
        iocs_list = ransomware_result.get("iocs_list", [])
        
        if iocs_count > 0 or iocs_list:
            st.markdown(f"#### 🎯 **Indicators of Compromise (IoCs) ({iocs_count} available)**")
            
            if iocs_list:
                with st.expander(f"View {len(iocs_list)} Extracted IoCs", expanded=False):
                    for i, ioc in enumerate(iocs_list[:100], 1):  # Show top 100
                        st.code(ioc, language="text")
                    
                    if len(iocs_list) > 100:
                        st.caption(f"Showing 100 of {len(iocs_list)} IoCs")
            else:
                st.info(f"✓ {iocs_count} IoC(s) available on ransomware.live website")
        
        st.markdown("---")

    
    # ===== SECTION 2: VICTIM DOMAIN INTELLIGENCE (PHASE 2) =====
    if "victim_domain_correlation" in results and results["victim_domain_correlation"]:
        st.markdown("### 🔗 **Victim Domain Intelligence (Phase 2 Analysis)**")
        st.markdown("Analyzing extracted victim domains across all intelligence sources")
        
        correlation_data = results["victim_domain_correlation"]
        
        # Show list of domains being analyzed
        domain_list = list(correlation_data.keys())
        source_count = len([s for s in results.keys() if s not in ['Ransomware.live', 'victim_domain_correlation']])
        
        info_col1, info_col2 = st.columns(2)
        with info_col1:
            st.info(f"🌐 **Domains Analyzed:** {len(domain_list)}")
        with info_col2:
            st.info(f"📡 **Intelligence Sources:** {source_count}")
        
        # Create tabs for each domain
        domain_tabs = st.tabs([f"🌐 {d}" for d in domain_list])
        
        for domain, domain_tab in zip(domain_list, domain_tabs):
            with domain_tab:
                domain_results = correlation_data[domain]
                
                # Show domain header
                st.markdown(f"#### **{domain}** - Multi-Source Analysis")
                
                # Create columns for sources
                source_names = list(domain_results.keys())
                
                if source_names:
                    # Create sub-tabs for each source querying this domain
                    source_tabs = st.tabs([s for s in source_names])
                    
                    for source_name, source_tab in zip(source_names, source_tabs):
                        with source_tab:
                            source_result = domain_results[source_name]
                            
                            if isinstance(source_result, dict):
                                if "error" in source_result:
                                    st.error(f"Could not retrieve data from {source_name}")
                                elif not source_result or len(source_result) == 0:
                                    st.info(f"No threats found on {source_name}")
                                else:
                                    # Display using appropriate renderer
                                    try:
                                        if source_name == "VirusTotal":
                                            display_virustotal_results(source_result)
                                        elif source_name == "Shodan":
                                            display_shodan_results(source_result)
                                        elif source_name == "AlienVault OTX":
                                            display_otx_results(source_result)
                                        elif source_name == "IPInfo":
                                            display_ipinfo_results(source_result)
                                        elif source_name == "AbuseIPDB":
                                            display_abuseipdb_results(source_result)
                                        elif source_name == "URLscan":
                                            display_urlscan_results(source_result)
                                        elif source_name == "URLhaus":
                                            display_urlhaus_results(source_result)
                                        else:
                                            st.json(source_result)
                                    except Exception as e:
                                        st.error(f"Error displaying results: {str(e)}")
                            else:
                                st.info(f"No data from {source_name}")
    
    st.markdown("---")


def display_header():
    """Display application header with CTI professional branding"""
    # Display logo as main header - full width, enlarged, no expand button
    st.image(".streamlit/x10_logo.jpeg", use_column_width=True, output_format="JPEG")
    
    st.markdown("---")
    
    # Stats columns below logo
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        st.markdown("""
        ### <span style='color: #ff4444; font-weight: bold;'>Intelligence Command Platform</span>
        """, unsafe_allow_html=True)
        total_supported = len(Config.SUPPORTED_INTELLIGENCE_SOURCES)
        st.markdown(f"""
        **Real-time threat intelligence aggregation across {total_supported} premium intelligence sources**
        
        🎯 **Designed for:** Security Operations Centers (SOCs) | Threat Analysts | Incident Response Teams
        """)


def display_threat_group_results(results: Dict[str, Any], threat_group: str):
    """
    Display comprehensive threat group analysis results with all Ransomware.live intelligence
    """
    if not results:
        st.error("No results found")
        return
    
    # ===== SECTION 1: COMPREHENSIVE GROUP INTELLIGENCE =====
    ransomware_result = results.get("Ransomware.live", {})
    
    if isinstance(ransomware_result, dict) and "error" not in ransomware_result:
        st.markdown("---")
        
        # ===== Header with Group Name and Status =====
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            st.markdown(f"### 🎯 **{threat_group}**")
        with col2:
            status = ransomware_result.get("status", "Unknown").upper()
            if "ACTIVE" in status:
                st.markdown(f"<p style='color: #ff4757; font-weight: bold; font-size: 16px;'>🔴 {status}</p>", unsafe_allow_html=True)
            else:
                st.markdown(f"<p style='color: #95a5a6; font-weight: bold; font-size: 16px;'>⚫ {status}</p>", unsafe_allow_html=True)
        with col3:
            threat_level = ransomware_result.get("threat_level", "unknown").upper()
            if threat_level == "CRITICAL":
                st.markdown(f"<p style='color: #ff4757; font-weight: bold; font-size: 16px;'>⚠️ {threat_level}</p>", unsafe_allow_html=True)
            else:
                st.markdown(f"<p style='color: #ffa502; font-weight: bold; font-size: 16px;'>📊 {threat_level}</p>", unsafe_allow_html=True)
        
        # ===== Description and History =====
        if ransomware_result.get("description"):
            with st.expander("📖 **Group Description & History**", expanded=True):
                st.markdown(f"**Description:** {ransomware_result.get('description', 'N/A')}")
                if ransomware_result.get("history"):
                    st.markdown(f"\n**History:** {ransomware_result.get('history', 'N/A')}")
        
        # ===== Key Statistics =====
        st.markdown("#### 📊 **Group Statistics**")
        stats = ransomware_result.get("statistics", {})
        
        stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
        with stat_col1:
            st.metric("Total Victims", stats.get("total_victims", 0), delta=None)
        with stat_col2:
            avg_delay = stats.get('avg_delay_days', 0)
            if isinstance(avg_delay, str):
                st.metric("Avg Delay", avg_delay, delta=None)
            else:
                st.metric("Avg Delay (days)", f"{avg_delay:.1f}" if avg_delay else "N/A", delta=None)
        with stat_col3:
            st.metric("Inactive Since (days)", stats.get("inactive_days", 0), delta=None)
        with stat_col4:
            infostealer = stats.get('infostealer_percentage', 0)
            if isinstance(infostealer, str):
                st.metric("Infostealer %", infostealer, delta=None)
            else:
                st.metric("Infostealer %", f"{infostealer:.1f}%" if infostealer else "0%", delta=None)
        
        # Date range
        date_col1, date_col2 = st.columns(2)
        with date_col1:
            st.info(f"🔵 **First Victim Discovered:** {stats.get('first_victim_date', 'Unknown')}")
        with date_col2:
            st.info(f"🔴 **Last Victim Discovered:** {stats.get('last_victim_date', 'Unknown')}")
        
        st.markdown("---")
        
        # ===== KNOWN LOCATIONS =====
        known_locations_list = ransomware_result.get("metadata", {}).get("known_locations_list", [])
        locations_count = ransomware_result.get("metadata", {}).get("known_locations", 0)
        if known_locations_list or locations_count > 0:
            st.markdown(f"#### 🌐 **Known Locations ({locations_count})**")
            if known_locations_list:
                with st.expander("View Locations", expanded=True):
                    for i, location in enumerate(known_locations_list[:20], 1):
                        st.text(f"{i}. {location}")
                    if len(known_locations_list) > 20:
                        st.caption(f"Showing 20 of {len(known_locations_list)} locations")
            else:
                st.info(f"✓ {locations_count} location(s) available")
        
        st.markdown("---")
        
        # ===== Intelligence Metadata =====
        st.markdown("#### 🔍 **Intelligence Metadata Summary**")
        metadata = ransomware_result.get("metadata", {})
        
        # Row 1: Main metadata counts
        meta_col1, meta_col2, meta_col3, meta_col4 = st.columns(4)
        with meta_col1:
            ransom_notes = metadata.get("ransom_notes", 0)
            st.metric("📄 Ransom Notes", ransom_notes)
        with meta_col2:
            tools = metadata.get("tools_used", 0)
            st.metric("🛠️ Tools Used", tools)
        with meta_col3:
            cves = metadata.get("vulnerabilities_exploited", 0)
            st.metric("🔴 CVEs Exploited", cves)
        with meta_col4:
            ttps = metadata.get("ttps_matrix", 0)
            st.metric("📊 TTPs Matrix", ttps)
        
        # Row 2: Intelligence counts
        meta_col5, meta_col6, meta_col7, meta_col8 = st.columns(4)
        with meta_col5:
            chats = metadata.get("negotiation_chats", 0)
            st.metric("💬 Negotiation Chats", chats)
        with meta_col6:
            yara = metadata.get("yara_rules", 0)
            st.metric("🔐 YARA Rules", yara)
        with meta_col7:
            iocs = metadata.get("iocs_count", 0)
            st.metric("🎯 IoCs Available", iocs)
        
        st.markdown("---")
        
        # ===== TARGET INFORMATION (Top Sectors & Countries) =====
        targets = ransomware_result.get("targets", {})
        top_sectors = targets.get("top_sectors", [])
        top_countries = targets.get("top_countries", [])
        
        if top_sectors or top_countries:
            st.markdown("#### 🎯 **Target Information**")
            
            if top_sectors:
                st.markdown("**Top 5 Activity Sectors:**")
                sector_col1, sector_col2 = st.columns(2)
                for i, sector_data in enumerate(top_sectors[:5], 1):
                    if isinstance(sector_data, dict):
                        sector_name = sector_data.get("name", "Unknown")
                        count = sector_data.get("count", 0)
                        with sector_col1 if i % 2 == 1 else sector_col2:
                            st.markdown(f"{i}. {sector_name} - **{count}** victims")
                    else:
                        with sector_col1 if i % 2 == 1 else sector_col2:
                            st.markdown(f"{i}. {sector_data}")
            
            if top_countries:
                st.markdown("**Top 5 Target Countries:**")
                country_col1, country_col2 = st.columns(2)
                for i, country_data in enumerate(top_countries[:5], 1):
                    if isinstance(country_data, dict):
                        country_name = country_data.get("name", "Unknown")
                        count = country_data.get("count", 0)
                        with country_col1 if i % 2 == 1 else country_col2:
                            st.markdown(f"{i}. {country_name} - **{count}** victims")
                    else:
                        with country_col1 if i % 2 == 1 else country_col2:
                            st.markdown(f"{i}. {country_data}")
        
        st.markdown("---")
        
        # ===== DETAILED RANSOM NOTES =====
        ransom_notes_list = metadata.get("ransom_notes_list", [])
        if ransom_notes_list:
            st.markdown(f"#### 📄 **Ransom Notes ({len(ransom_notes_list)})**")
            with st.expander(f"View {len(ransom_notes_list)} Ransom Notes", expanded=False):
                for i, note in enumerate(ransom_notes_list[:50], 1):
                    if isinstance(note, dict):
                        note_name = note.get("name", "Unknown")
                        note_url = note.get("url", "")
                        st.markdown(f"**{i}. {note_name}**")
                        if note_url:
                            st.markdown(f"[View Note]({note_url})")
                    else:
                        st.markdown(f"{i}. {note}")
                if len(ransom_notes_list) > 50:
                    st.caption(f"Showing 50 of {len(ransom_notes_list)} ransom notes")
        
        st.markdown("---")
        
        # ===== DETAILED TOOLS USED (Classified by Tactic) =====
        tools_list = metadata.get("tools_used_list", [])
        if tools_list:
            if isinstance(tools_list, dict) and len(tools_list) > 0:
                total_tools = sum(len(tools) if isinstance(tools, list) else 0 for tools in tools_list.values())
                st.markdown(f"#### 🛠️ **Tools Used by Group ({total_tools} tools, {len(tools_list)} tactics)**")
                with st.expander("View Tools by Tactic", expanded=True):
                    for tactic, tools in sorted(tools_list.items()):
                        if isinstance(tools, list) and len(tools) > 0:
                            # Filter out placeholders
                            valid_tools = [t for t in tools if t and 'placeholder' not in t.lower()]
                            if valid_tools:
                                st.markdown(f"**{tactic}** ({len(valid_tools)} tools)")
                                for tool in valid_tools:
                                    st.markdown(f"  • {tool}")
                                st.divider()
            else:
                # Fallback for old list format
                st.markdown(f"#### 🛠️ **Tools Used by Group ({len(tools_list) if isinstance(tools_list, list) else 0})**")
                with st.expander(f"View Tools", expanded=False):
                    cols = st.columns(2)
                    for i, tool in enumerate(tools_list[:50] if isinstance(tools_list, list) else []):
                        with cols[i % 2]:
                            st.markdown(f"• {tool}")
        
        st.markdown("---")
        
        # ===== DETAILED VULNERABILITIES/CVEs =====
        vuln_list = metadata.get("vulnerabilities_list", [])
        if vuln_list:
            st.markdown(f"#### 🔴 **Vulnerabilities Exploited ({len(vuln_list)})**")
            with st.expander(f"View {len(vuln_list)} CVEs", expanded=False):
                cols = st.columns(2)
                for i, cve in enumerate(vuln_list[:50]):
                    with cols[i % 2]:
                        st.markdown(f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})")
                if len(vuln_list) > 50:
                    st.caption(f"Showing 50 of {len(vuln_list)} CVEs")
        
        st.markdown("---")
        
        # ===== DETAILED TTPs/TACTICS =====
        ttps_list = metadata.get("ttps_list", [])
        if ttps_list:
            st.markdown(f"#### 📊 **TTPs (Tactics, Techniques & Procedures) ({len(ttps_list)})**")
            with st.expander(f"View {len(ttps_list)} TTPs", expanded=False):
                cols = st.columns(2)
                for i, ttp in enumerate(ttps_list[:50]):
                    with cols[i % 2]:
                        st.markdown(f"• {ttp}")
                if len(ttps_list) > 50:
                    st.caption(f"Showing 50 of {len(ttps_list)} TTPs")
        
        st.markdown("---")
        
        # ===== DETAILED NEGOTIATION CHATS =====
        chats_list = metadata.get("negotiation_chats_list", [])
        if chats_list:
            st.markdown(f"#### 💬 **Negotiation Chats ({len(chats_list)})**")
            with st.expander(f"View {len(chats_list)} Negotiation Chats", expanded=False):
                for i, chat in enumerate(chats_list[:50], 1):
                    if isinstance(chat, dict):
                        chat_title = chat.get("title", "Unknown")
                        chat_url = chat.get("url", "")
                        st.markdown(f"**{i}. {chat_title}**")
                        if chat_url:
                            st.caption(f"URL: {chat_url}")
                    else:
                        st.markdown(f"{i}. {chat}")
                if len(chats_list) > 50:
                    st.caption(f"Showing 50 of {len(chats_list)} chats")
        
        st.markdown("---")
        
        # ===== DETAILED YARA RULES =====
        yara_list = metadata.get("yara_rules_list", [])
        if yara_list:
            st.markdown(f"#### 🔐 **YARA Rules ({len(yara_list)})**")
            with st.expander(f"View {len(yara_list)} YARA Rules", expanded=False):
                for i, rule in enumerate(yara_list[:50], 1):
                    if isinstance(rule, dict):
                        rule_name = rule.get("name", "Unknown")
                        rule_url = rule.get("url", "")
                        st.markdown(f"**{i}. {rule_name}**")
                        if rule_url:
                            st.caption(f"URL: {rule_url}")
                    else:
                        st.markdown(f"{i}. {rule}")
                if len(yara_list) > 50:
                    st.caption(f"Showing 50 of {len(yara_list)} YARA rules")
        
        st.markdown("---")
        
        # ===== Tactical Information =====
        if ransomware_result.get("initial_access_vectors"):
            with st.expander("🚀 **Initial Access Vectors**", expanded=False):
                vectors = ransomware_result.get("initial_access_vectors", [])
                for i, vector in enumerate(vectors, 1):
                    st.markdown(f"{i}. {vector}")
        
        # ===== CVEs Exploited (API) =====
        if ransomware_result.get("cves"):
            with st.expander("🔴 **CVEs from API Data**", expanded=False):
                cves = ransomware_result.get("cves", [])
                for cve in cves:
                    st.markdown(f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})")
        
        # ===== Active Regions =====
        if ransomware_result.get("active_regions"):
            with st.expander("🌍 **Active Regions**", expanded=False):
                regions = ransomware_result.get("active_regions", [])
                st.markdown(", ".join(regions))
        
        # ===== Related Groups =====
        if ransomware_result.get("related_groups"):
            with st.expander("🔗 **Related Groups**", expanded=False):
                related = ransomware_result.get("related_groups", [])
                for group in related:
                    st.markdown(f"• {group}")
        
        st.markdown("---")
        
        # ===== Display Victim Domains =====
        total_victims = ransomware_result.get("statistics", {}).get("total_victims", 0)
        victim_domains = ransomware_result.get("victim_domains", [])
        
        st.markdown(f"#### 👥 **Victims ({total_victims} in database)**")
        st.info(f"🔗 **{len(victim_domains)} victim domains extracted for Phase 2 analysis across all intelligence sources**")
        
        if victim_domains:
            with st.expander(f"View {len(victim_domains)} Extracted Victim Domains", expanded=False):
                # Create victims table
                victims_data = []
                for i, domain in enumerate(victim_domains[:100], 1):  # Show top 100
                    victims_data.append({
                        "#": i,
                        "Victim Domain": domain
                    })
                
                if victims_data:
                    df_victims = pd.DataFrame(victims_data)
                    st.dataframe(
                        df_victims,
                        use_container_width=True,
                        hide_index=True,
                        column_config={
                            "#": st.column_config.NumberColumn("#", width="small"),
                            "Victim Domain": st.column_config.TextColumn("Victim Domain", width="large"),
                        }
                    )
                    
                    if len(victim_domains) > 100:
                        st.caption(f"Showing 100 of {len(victim_domains)} victims")
        
        st.markdown("---")
        
        # ===== Display IoCs =====
        iocs_count = ransomware_result.get("metadata", {}).get("iocs_count", 0)
        iocs_list = ransomware_result.get("iocs_list", [])
        
        if iocs_count > 0 or iocs_list:
            st.markdown(f"#### 🎯 **Indicators of Compromise (IoCs) ({iocs_count} available)**")
            
            if iocs_list:
                with st.expander(f"View {len(iocs_list)} Extracted IoCs", expanded=False):
                    for i, ioc in enumerate(iocs_list[:100], 1):  # Show top 100
                        st.code(ioc, language="text")
                    
                    if len(iocs_list) > 100:
                        st.caption(f"Showing 100 of {len(iocs_list)} IoCs")
            else:
                st.info(f"✓ {iocs_count} IoC(s) available on ransomware.live website")
        
        st.markdown("---")

    
    # ===== SECTION 2: VICTIM DOMAIN INTELLIGENCE (PHASE 2) =====
    if "victim_domain_correlation" in results and results["victim_domain_correlation"]:
        st.markdown("### 🔗 **Victim Domain Intelligence (Phase 2 Analysis)**")
        st.markdown("Analyzing extracted victim domains across all intelligence sources")
        
        correlation_data = results["victim_domain_correlation"]
        
        # Show list of domains being analyzed
        domain_list = list(correlation_data.keys())
        source_count = len([s for s in results.keys() if s not in ['Ransomware.live', 'victim_domain_correlation']])
        
        info_col1, info_col2 = st.columns(2)
        with info_col1:
            st.info(f"🌐 **Domains Analyzed:** {len(domain_list)}")
        with info_col2:
            st.info(f"📡 **Intelligence Sources:** {source_count}")
        
        # Create tabs for each domain
        domain_tabs = st.tabs([f"🌐 {d}" for d in domain_list])
        
        for domain, domain_tab in zip(domain_list, domain_tabs):
            with domain_tab:
                domain_results = correlation_data[domain]
                
                # Show domain header
                st.markdown(f"#### **{domain}** - Multi-Source Analysis")
                
                # Create columns for sources
                source_names = list(domain_results.keys())
                
                if source_names:
                    # Create sub-tabs for each source querying this domain
                    source_tabs = st.tabs([s for s in source_names])
                    
                    for source_name, source_tab in zip(source_names, source_tabs):
                        with source_tab:
                            source_result = domain_results[source_name]
                            
                            if isinstance(source_result, dict):
                                if "error" in source_result:
                                    st.error(f"Could not retrieve data from {source_name}")
                                elif not source_result or len(source_result) == 0:
                                    st.info(f"No threats found on {source_name}")
                                else:
                                    # Display using appropriate renderer
                                    try:
                                        if source_name == "VirusTotal":
                                            display_virustotal_results(source_result)
                                        elif source_name == "Shodan":
                                            display_shodan_results(source_result)
                                        elif source_name == "AlienVault OTX":
                                            display_otx_results(source_result)
                                        elif source_name == "IPInfo":
                                            display_ipinfo_results(source_result)
                                        elif source_name == "AbuseIPDB":
                                            display_abuseipdb_results(source_result)
                                        elif source_name == "URLscan":
                                            display_urlscan_results(source_result)
                                        elif source_name == "URLhaus":
                                            display_urlhaus_results(source_result)
                                        else:
                                            st.json(source_result)
                                    except Exception as e:
                                        st.error(f"Error displaying results: {str(e)}")
                            else:
                                st.info(f"No data from {source_name}")
    
    st.markdown("---")


def display_header():
    """Display application header with CTI professional branding"""
    # Display logo as main header - full width, enlarged, no expand button
    st.image(".streamlit/x10_logo.jpeg", use_column_width=True, output_format="JPEG")
    
    st.markdown("---")
    
    # Stats columns below logo
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        st.markdown("""
        ### <span style='color: #ff4444; font-weight: bold;'>Intelligence Command Platform</span>
        """, unsafe_allow_html=True)
        total_supported = len(Config.SUPPORTED_INTELLIGENCE_SOURCES)
        st.markdown(f"""
        **Real-time threat intelligence aggregation across {total_supported} premium intelligence sources**
        
        🎯 **Designed for:** Security Operations Centers (SOCs) | Threat Analysts | Incident Response Teams
        """)

    with col2:
        st.markdown("### 📊 System Status")
        is_valid, message = Config.validate_config()
        if is_valid:
            st.success("✅ All Systems Operational")
        else:
            st.error("⚠️ Configuration Issue")
    
    with col3:
        active_apis = Config.get_active_apis()
        st.metric("Intelligence Sources", f"{len(active_apis)}/{len(Config.SUPPORTED_INTELLIGENCE_SOURCES)}", delta=None)
        st.metric("Status", "🟢 LIVE", delta=None)
    
    st.markdown("---")


def display_single_input():
    """Display single indicator input with CTI terminology"""
    
    # Input type selector
    input_type = st.radio(
        "📌 Indicator Type:",
        ["Observable (IP/Domain/Hash)", "Threat Group"],
        horizontal=True,
        help="Observable: Query indicators | Threat Group: Query APT/ransomware groups"
    )
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        if input_type == "Observable (IP/Domain/Hash)":
            observable = st.text_input(
                "🔎 Enter Indicator (Observable):",
                placeholder="e.g., 8.8.8.8 or malware.com or 139.180.203.104:443",
                help="IPv4 address | Domain | URL | File hash (MD5/SHA1/SHA256) | IP:port (e.g., 192.168.1.1:443 for ThreatFox)",
            )
            threat_group = None
        else:
            observable = None
            threat_group = st.text_input(
                "🚨 Enter Threat Actor/Group Name:",
                placeholder="e.g., LockBit, Lazarus, APT28",
                help="Ransomware group or APT threat actor"
            )
    
    with col2:
        st.markdown("")  # Spacing
        st.markdown("")
        analyze_button = st.button("⚡ ANALYZE", use_container_width=True)
    
    # Source selection
    selected_sources = display_source_selection()
    
    return observable, threat_group, analyze_button, selected_sources, "single", None


def display_batch_input():
    """Display batch input"""
    st.markdown("**Upload Indicator File:**")
    
    uploaded_file = st.file_uploader(
        "Choose a file (TXT or CSV)",
        type=["txt", "csv"],
        help="Upload a file containing indicators (one per line or CSV format)"
    )
    
    analyze_button = st.button("🚀 Analyze Batch", use_container_width=True)
    
    # Source selection
    selected_sources = display_source_selection()
    
    return None, None, analyze_button, selected_sources, "batch", uploaded_file


def display_input_section():
    """Display input and configuration section"""
    st.subheader("� Indicator Analysis Configuration")
    
    # Mode selection
    mode = st.radio(
        "🎯 Select Analysis Mode:",
        ["Single Indicator", "Batch Analysis"],
        horizontal=True,
        help="Single: Analyze one indicator | Batch: Upload multiple indicators for analysis"
    )
    
    st.markdown("---")
    
    if mode == "Single Indicator":
        return display_single_input()
    else:
        return display_batch_input()


def display_source_selection():
    """Display source selection checkboxes"""
    st.markdown("**🔗 Select Intelligence Sources to Query:**")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    
    with col1:
        vt = st.checkbox("VirusTotal", value=bool(Config.VIRUSTOTAL_API_KEY), disabled=not Config.VIRUSTOTAL_API_KEY)
        shodan = st.checkbox("Shodan", value=bool(Config.SHODAN_API_KEY), disabled=not Config.SHODAN_API_KEY)
        otx = st.checkbox("AlienVault OTX", value=bool(Config.OTX_API_KEY), disabled=not Config.OTX_API_KEY)
    
    with col2:
        ipinfo = st.checkbox("IPInfo", value=bool(Config.IPINFO_API_KEY), disabled=not Config.IPINFO_API_KEY)
        abuseipdb = st.checkbox("AbuseIPDB", value=bool(Config.ABUSEIPDB_API_KEY), disabled=not Config.ABUSEIPDB_API_KEY)
        urlscan = st.checkbox("URLscan", value=bool(Config.URLSCAN_API_KEY), disabled=not Config.URLSCAN_API_KEY)
    
    with col3:
        urlhaus = st.checkbox("URLhaus", value=bool(Config.URLHAUS_API_KEY), disabled=not Config.URLHAUS_API_KEY)
        ipdetective = st.checkbox("IP Detective", value=bool(Config.IPDETECTIVE_API_KEY), disabled=not Config.IPDETECTIVE_API_KEY)
        hunter = st.checkbox("Hunter.io", value=bool(Config.HUNTER_API_KEY), disabled=not Config.HUNTER_API_KEY)
    
    with col4:
        getipintel = st.checkbox("GetIPIntel", value=bool(Config.GETIPINTEL_CONTACT), disabled=not Config.GETIPINTEL_CONTACT)
        ransomware_live = st.checkbox("Ransomware.live", value=True)  # Public API — no key required
        malware_bazaar = st.checkbox("Malware Bazaar", value=bool(Config.MALWARE_BAZAAR_API_KEY), disabled=not Config.MALWARE_BAZAAR_API_KEY)
    
    with col5:
        threatfox = st.checkbox("ThreatFox", value=bool(Config.THREATFOX_API_KEY), disabled=not Config.THREATFOX_API_KEY)
        yaraify = st.checkbox("YARAify", value=bool(Config.YARAIFY_API_KEY), disabled=not Config.YARAIFY_API_KEY)
        # Local/CSV based integrations that don't require API keys
        sslbl = st.checkbox("SSLBL", value=True)
        feodo = st.checkbox("Feodo Tracker", value=True)
    selected_sources = []
    if vt:
        selected_sources.append("VirusTotal")
    if shodan:
        selected_sources.append("Shodan")
    if otx:
        selected_sources.append("AlienVault OTX")
    if ipinfo:
        selected_sources.append("IPInfo")
    if abuseipdb:
        selected_sources.append("AbuseIPDB")
    if urlscan:
        selected_sources.append("URLscan")
    if urlhaus:
        selected_sources.append("URLhaus")
    if ipdetective:
        selected_sources.append("IP Detective")
    if hunter:
        selected_sources.append("Hunter.io")
    if getipintel:
        selected_sources.append("GetIPIntel")
    if ransomware_live:
        selected_sources.append("Ransomware.live")
    if malware_bazaar:
        selected_sources.append("Malware Bazaar")
    if threatfox:
        selected_sources.append("ThreatFox")
    if yaraify:
        selected_sources.append("YARAify")
    if sslbl:
        selected_sources.append("SSLBL")
    if feodo:
        selected_sources.append("Feodo Tracker")
    
    return selected_sources


def display_results_overview(results: Dict[str, Any], observable: str):
    """Display results overview section"""
    st.subheader("📊 Analysis Overview")
    
    analytics = get_analytics_data(results)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Threat Level",
            analytics["threat_level"],
            delta=None,
        )
    
    with col2:
        st.metric(
            "Malicious Detections",
            analytics["malicious_detections"],
            delta=None,
        )
    
    with col3:
        st.metric(
            "Suspicious Detections",
            analytics["suspicious_detections"],
            delta=None,
        )
    
    with col4:
        st.metric(
            "Sources Queried",
            analytics["sources_queried"],
            f"{analytics['sources_failed']} failed",
        )
    
    # Key findings
    st.markdown("**Key Findings:**")
    findings = extract_key_findings(results)
    for finding in findings:
        st.write(f"• {finding}")


def display_ipdetective_results(data: Dict[str, Any]):
    """Display IP Detective results (Bot/VPN/Proxy detection)"""
    st.subheader("🤖 IP Detective Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    # Bot, VPN, Proxy detection
    col1, col2, col3 = st.columns(3)
    
    with col1:
        is_bot = data.get("is_bot", False)
        bot_status = "🤖 BOT" if is_bot else "✅ CLEAN"
        bot_color = "🔴" if is_bot else "🟢"
        st.metric("Bot Status", f"{bot_color} {bot_status}")
    
    with col2:
        ip_type = data.get("ip_type", "unknown")
        type_emoji = {
            "bot": "🤖",
            "vpn": "🔐",
            "proxy": "🔀",
            "datacenter": "🏢",
            "unknown": "❓"
        }.get(ip_type, "❓")
        st.metric("IP Type", f"{type_emoji} {ip_type.upper()}")
    
    with col3:
        threat_level = data.get("threat_level", "unknown")
        threat_emoji = {
            "high": "🔴",
            "medium": "🟠",
            "low": "🟡",
            "unknown": "⚪"
        }.get(threat_level, "⚪")
        st.metric("Threat Level", f"{threat_emoji} {threat_level.upper()}")
    
    # Geo and ASN information
    col1, col2 = st.columns(2)
    
    with col1:
        if data.get("country_name"):
            st.write(f"**Country:** {data.get('country_name')}")
        if data.get("country_code"):
            st.write(f"**Country Code:** {data.get('country_code')}")
    
    with col2:
        if data.get("asn"):
            st.write(f"**ASN:** {data.get('asn')}")
        if data.get("asn_description"):
            st.write(f"**ASN Description:** {data.get('asn_description')}")
    
    # Threat summary
    if data.get("is_suspicious"):
        st.warning("⚠️ This IP shows suspicious characteristics (VPN, Proxy, or Datacenter)")


def display_getipintel_results(data: Dict[str, Any]):
    """Display GetIPIntel results (Proxy/VPN/Bad IP detection)"""
    st.subheader("🕵️ GetIPIntel Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    # Score and threat classification
    score = data.get("score", 0)
    threat_level = data.get("threat_level", "unknown")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        threat_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "unknown": "⚪"
        }.get(threat_level, "⚪")
        st.metric("Threat Level", f"{threat_emoji} {threat_level.upper()}", f"{score:.2%}")
    
    with col2:
        is_proxy_vpn = data.get("is_proxy_vpn", False)
        proxy_status = "🚫 PROXY/VPN" if is_proxy_vpn else "✅ CLEAN"
        proxy_color = "🔴" if is_proxy_vpn else "🟢"
        st.metric("Proxy/VPN Status", f"{proxy_color} {proxy_status}")
    
    with col3:
        is_suspicious = data.get("is_suspicious", False)
        suspicious_status = "⚠️ SUSPICIOUS" if is_suspicious else "✅ OK"
        suspicious_color = "🟠" if is_suspicious else "🟢"
        st.metric("Suspicious", f"{suspicious_color} {suspicious_status}")
    
    # Score interpretation
    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**Raw Score:** {score:.4f}")
        st.caption("Score Range: 0.0 (Clean) → 1.0 (Proxy/VPN)")
    
    with col2:
        if data.get("asn"):
            st.write(f"**ASN:** {data.get('asn')}")
    
    # Detailed interpretation
    if score >= 0.99:
        st.error("🔴 CRITICAL: Almost certainly a proxy/VPN")
    elif score >= 0.95:
        st.warning("🟠 HIGH: Very likely a proxy/VPN")
    elif score >= 0.75:
        st.warning("🟡 MEDIUM: Likely a proxy/VPN")
    elif score >= 0.50:
        st.info("🔵 LOW: Possible proxy/VPN")
    elif score > 0:
        st.success("🟢 Very unlikely to be a proxy/VPN")
    
    # Flags used
    flags = data.get("flags_used", "b")
    st.caption(f"Detection method: flags={flags}")


def display_ransomware_live_results(data: Dict[str, Any]):
    """Display Ransomware.live results"""
    st.subheader("🚨 Ransomware.live Results")

    if "error" in data:
        st.error(f"Error: {data['error']}")
        return

    victims = data.get("victims", [])
    # v2 API returns "total_victims_found" (not "victims_found")
    victims_found = data.get("total_victims_found", data.get("victims_found", len(victims)))
    threat_level = data.get("threat_level", "unknown").lower()
    is_malicious = data.get("is_malicious", False)

    # Summary metrics
    col1, col2, col3 = st.columns(3)

    with col1:
        threat_emoji = {
            "critical": "🔴",
            "high": "🔴",
            "medium": "🟠",
            "low": "🟡",
            "none": "🟢",
            "unknown": "⚪",
        }.get(threat_level, "⚪")
        st.metric("Threat Level", f"{threat_emoji} {threat_level.upper()}")

    with col2:
        status_color = "🔴" if is_malicious else "🟢"
        status_text = "ASSOCIATED" if is_malicious else "NOT FOUND"
        st.metric("Ransomware Status", f"{status_color} {status_text}")

    with col3:
        st.metric("Victims Found", victims_found)

    # Display victims if found
    if victims_found > 0:
        st.warning(f"⚠️ Found {victims_found} associated ransomware victim(s)")

        with st.expander(f"📋 Victim Details ({victims_found} total)", expanded=True):
            for idx, victim in enumerate(victims, 1):
                col1, col2 = st.columns([2, 1])

                with col1:
                    # v2 API: organisation name is "victim", date is "attackdate"
                    org_name = victim.get("victim", victim.get("name", "Unknown"))
                    attack_date = victim.get("attackdate", victim.get("discovery_date", "N/A"))
                    country = victim.get("country", "")
                    website = victim.get("website", "")

                    st.write(f"**{idx}. {org_name}**")
                    st.write(f"  - **Group:** {victim.get('group', 'Unknown')}")
                    st.write(f"  - **Date:** {attack_date}")
                    if country:
                        st.write(f"  - **Country:** {country}")
                    if website:
                        st.write(f"  - **Website:** {website}")

                with col2:
                    st.write("")  # Spacing

                if idx < len(victims):
                    st.markdown("---")
    else:
        st.info("✅ No ransomware victim associations found")

    # Display associated groups if identified via bidirectional correlation
    associated_groups = data.get("associated_groups", [])
    if associated_groups:
        with st.expander(f"👥 Associated Ransomware Groups ({len(associated_groups)} found)", expanded=False):
            for group in associated_groups[:10]:
                if isinstance(group, dict):
                    group_name = group.get("name", group.get("groupname", "Unknown"))
                    st.write(f"• **{group_name}**")
                else:
                    st.write(f"• {group}")


def display_virustotal_results(data: Dict[str, Any]):
    """Display VirusTotal results"""
    st.subheader("🦠 VirusTotal Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    # Threat statistics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Malicious", data.get("malicious", 0))
    with col2:
        st.metric("Suspicious", data.get("suspicious", 0))
    with col3:
        st.metric("Undetected", data.get("undetected", 0))
    
    # Additional details
    if data.get("type") == "ip":
        st.write(f"**Country:** {data.get('country')}")
        st.write(f"**ASN:** {data.get('asn')}")
        st.write(f"**AS Owner:** {data.get('as_owner')}")
    
    elif data.get("type") == "domain":
        if data.get("categories"):
            st.write(f"**Categories:** {', '.join(data.get('categories', {}).values())}")
    
    elif data.get("type") == "file":
        st.write(f"**File Size:** {data.get('file_size')} bytes")
        st.write(f"**File Type:** {data.get('file_type')}")
        if data.get("tags"):
            st.write(f"**Tags:** {', '.join(data.get('tags', []))}")


def display_shodan_results(data: Dict[str, Any]):
    """Display Shodan results"""
    st.subheader("🔌 Shodan Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write(f"**Country:** {data.get('country_name')}")
        st.write(f"**City:** {data.get('city')}")
        st.write(f"**ISP:** {data.get('isp')}")
        st.write(f"**Organization:** {data.get('organization')}")
    
    with col2:
        st.write(f"**Latitude:** {data.get('latitude')}")
        st.write(f"**Longitude:** {data.get('longitude')}")
        st.write(f"**OS:** {data.get('os')}")
    
    # Open ports
    if data.get("ports"):
        st.write(f"**Open Ports:** {', '.join(map(str, data.get('ports', [])))}")
    
    # Hostnames
    if data.get("hostnames"):
        st.write(f"**Hostnames:** {', '.join(data.get('hostnames', []))}")


# def display_otx_results(data: Dict[str, Any]):
#     """Display AlienVault OTX results"""
#     st.subheader("🚨 AlienVault OTX Results")
    
#     if "error" in data:
#         st.error(f"Error: {data['error']}")
#         return
    
#     # Basic info
#     col1, col2 = st.columns(2)
    
#     with col1:
#         st.write(f"**Reputation:** {data.get('reputation')}")
#         st.write(f"**Type:** {data.get('type_title')}")
    
#     with col2:
#         st.write(f"**Validity:** {data.get('validity')}")
    
#     # Pulses
#     pulses = data.get("pulses", [])
#     if pulses:
#         st.write(f"**Found in {len(pulses)} Threat Pulses:**")
        
#         for pulse in pulses[:5]:  # Show top 5
#             with st.expander(f"🔴 {pulse.get('name')}"):
#                 st.write(f"**Author:** {pulse.get('author')}")
#                 st.write(f"**Created:** {pulse.get('created')}")
#                 st.write(f"**Description:** {pulse.get('description')}")
                
#                 # Handle None values and convert dicts/objects to strings
#                 malware_families = pulse.get("malware_families") or []
#                 if malware_families and isinstance(malware_families, list):
#                     family_names = [str(item) if not isinstance(item, dict) else item.get('name', str(item)) for item in malware_families]
#                     st.write(f"**Malware Families:** {', '.join(family_names)}")
                
#                 attack_ids = pulse.get("attack_ids") or []
#                 if attack_ids and isinstance(attack_ids, list):
#                     attack_id_strs = [str(item) if not isinstance(item, dict) else item.get('id', str(item)) for item in attack_ids]
#                     st.write(f"**Attack IDs:** {', '.join(attack_id_strs)}")
                
#                 industries = pulse.get("industries") or []
#                 if industries and isinstance(industries, list):
#                     industry_names = [str(item) if not isinstance(item, dict) else item.get('name', str(item)) for item in industries]
#                     st.write(f"**Industries:** {', '.join(industry_names)}")
                
#                 if pulse.get("adversary"):
#                     st.write(f"**Adversary:** {pulse.get('adversary')}")
                
#                 st.markdown(f"[View on OTX]({pulse.get('url')})")
#     else:
#         st.info("No threat pulses found for this observable")


def display_otx_results(data: Dict[str, Any]):
    """Display AlienVault OTX results - COMPREHENSIVE VERSION with error handling"""
    st.subheader("🚨 AlienVault OTX Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    # Basic info
    col1, col2, col3 = st.columns(3)
    
    with col1:
        reputation = data.get('reputation', 0)
        st.write(f"**Reputation:** {reputation}")
        st.write(f"**Type:** {data.get('type_title', 'N/A')}")
    
    with col2:
        st.write(f"**Validity:** {data.get('validity', 'N/A')}")
        pulse_count = data.get('pulse_count', 0)
        st.write(f"**Threat Pulses:** {pulse_count}")
    
    with col3:
        # Use country_name only to avoid duplication
        country = data.get("country_name")
        if country:
            st.write(f"**Country:** {country}")
        asn = data.get("asn")
        if asn:
            st.write(f"**ASN:** {asn}")
    
    # WHOIS Information (for domains)
    whois_data = data.get("whois")
    if whois_data and isinstance(whois_data, str) and len(whois_data) > 10:
        with st.expander("📋 WHOIS Information", expanded=True):
            # Display in a scrollable text area with better formatting
            st.text_area("WHOIS Data", whois_data, height=300, label_visibility="collapsed")
    
    # Related Domains - Removed as endpoint returns 404
    
    # Passive DNS Records
    passive_dns = data.get("passive_dns_records", [])
    if passive_dns and len(passive_dns) > 0:
        with st.expander(f"🌐 Passive DNS Records ({len(passive_dns)} found)"):
            for idx, record in enumerate(passive_dns, 1):
                hostname = record.get('hostname', 'N/A')
                address = record.get('address', 'N/A')
                record_type = record.get('record_type', 'N/A')
                first_seen = record.get('first', 'N/A')
                last_seen = record.get('last', 'N/A')
                
                st.write(f"**{idx}. {hostname}** → {address} ({record_type})")
                st.caption(f"First seen: {first_seen} | Last seen: {last_seen}")
                
                if idx < len(passive_dns):
                    st.markdown("---")
    
    # Associated URLs
    associated_urls = data.get("associated_urls", [])
    if associated_urls and len(associated_urls) > 0:
        with st.expander(f"🔗 Associated URLs ({len(associated_urls)} found)"):
            for idx, url_entry in enumerate(associated_urls, 1):
                url = url_entry.get('url', 'N/A')
                domain = url_entry.get('domain', 'N/A')
                hostname = url_entry.get('hostname', 'N/A')
                date = url_entry.get('date', 'N/A')
                
                st.write(f"**{idx}. {url}**")
                st.caption(f"Domain: {domain} | Hostname: {hostname} | Date: {date}")
                
                if idx < len(associated_urls):
                    st.markdown("---")
    
    # HTTP Scans
    http_scans = data.get("http_scans", [])
    if http_scans and len(http_scans) > 0:
        with st.expander(f"🔍 HTTP Scans ({len(http_scans)} fields found)", expanded=True):
            st.markdown("**Port 443 (HTTPS) Scan Results:**")
            for idx, scan in enumerate(http_scans, 1):
                field = scan.get('field', 'N/A')
                value = scan.get('value', 'N/A')
                st.write(f"**{field}:** {value}")
            st.info("These are the HTTP/HTTPS scan results showing domains, titles, and other web server information.")
    
    # Malware Samples
    malware_samples = data.get("malware_samples", [])
    if malware_samples and len(malware_samples) > 0:
        with st.expander(f"🦠 Malware Samples ({len(malware_samples)} found)", expanded=True):
            st.warning("⚠️ This indicator is associated with known malware!")
            for idx, sample in enumerate(malware_samples[:10], 1):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.code(sample.get('hash', 'N/A'))
                with col2:
                    st.metric("Detections", sample.get('detections', 0))
                st.caption(f"Date: {sample.get('date', 'N/A')}")
                if idx < len(malware_samples[:10]):
                    st.markdown("---")
    
    # Pulses (Threat Intelligence)
    pulses = data.get("pulses", [])
    if pulses and len(pulses) > 0:
        st.write(f"**Found in {len(pulses)} Threat Pulses:**")
        
        for pulse in pulses[:5]:
            with st.expander(f"🔴 {pulse.get('name', 'Unknown')}"):
                st.write(f"**Author:** {pulse.get('author', 'N/A')}")
                st.write(f"**Created:** {pulse.get('created', 'N/A')}")
                
                description = pulse.get('description', '')
                if description:
                    st.write(f"**Description:** {description}")
                
                malware_families = pulse.get("malware_families") or []
                if malware_families and isinstance(malware_families, list) and len(malware_families) > 0:
                    family_names = [str(item) if not isinstance(item, dict) else item.get('name', str(item)) for item in malware_families]
                    if family_names:
                        st.write(f"**Malware Families:** {', '.join(family_names)}")
                
                attack_ids = pulse.get("attack_ids") or []
                if attack_ids and isinstance(attack_ids, list) and len(attack_ids) > 0:
                    attack_id_strs = [str(item) if not isinstance(item, dict) else item.get('id', str(item)) for item in attack_ids]
                    if attack_id_strs:
                        st.write(f"**Attack IDs:** {', '.join(attack_id_strs)}")
                
                industries = pulse.get("industries") or []
                if industries and isinstance(industries, list) and len(industries) > 0:
                    industry_names = [str(item) if not isinstance(item, dict) else item.get('name', str(item)) for item in industries]
                    if industry_names:
                        st.write(f"**Industries:** {', '.join(industry_names)}")
                
                adversary = pulse.get("adversary")
                if adversary:
                    st.write(f"**Adversary:** {adversary}")
                
                pulse_url = pulse.get('url')
                if pulse_url:
                    st.markdown(f"[View on OTX]({pulse_url})")
    else:
        # Check if we have ANY other data
        has_other_data = any([
            passive_dns,
            associated_urls,
            http_scans,
            malware_samples,
            whois_data and isinstance(whois_data, str) and len(whois_data) > 10
        ])
        
        if has_other_data:
            st.info("ℹ️ No threat pulses found, but other intelligence data is available above")
        else:
            st.info("✅ No threat intelligence found for this observable in OTX database")


def display_abuseipdb_results(data: Dict[str, Any]):
    """Display AbuseIPDB results"""
    st.subheader("🚫 AbuseIPDB Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    # Abuse score
    score = data.get("abuse_confidence_score", 0)
    
    # Color code based on score
    if score > 75:
        score_color = "🔴"
    elif score > 25:
        score_color = "🟠"
    else:
        score_color = "🟢"
    
    st.metric("Abuse Confidence Score", f"{score_color} {score}%")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write(f"**Country:** {data.get('country_name')}")
        st.write(f"**ISP:** {data.get('isp')}")
        st.write(f"**Usage Type:** {data.get('usage_type')}")
    
    with col2:
        st.write(f"**Whitelisted:** {data.get('is_whitelisted')}")
        st.write(f"**Total Reports:** {data.get('total_reports')}")
        st.write(f"**Last Reported:** {data.get('last_reported_at')}")


def display_ipinfo_results(data: Dict[str, Any]):
    """Display IPInfo results"""
    st.subheader("ℹ️ IPInfo Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write(f"**Hostname:** {data.get('hostname')}")
        st.write(f"**Organization:** {data.get('org')}")
        st.write(f"**City:** {data.get('city')}")
        st.write(f"**Region:** {data.get('region')}")
    
    with col2:
        st.write(f"**Country:** {data.get('country')}")
        st.write(f"**Timezone:** {data.get('timezone')}")
        st.write(f"**Location:** {data.get('loc')}")
    
    # Privacy info
    if data.get("privacy"):
        privacy = data.get("privacy", {})
        if privacy.get("vpn") or privacy.get("proxy") or privacy.get("tor"):
            st.warning("⚠️ Privacy/Proxy Usage Detected")
            st.write(f"- VPN: {privacy.get('vpn')}")
            st.write(f"- Proxy: {privacy.get('proxy')}")
            st.write(f"- Tor: {privacy.get('tor')}")


def display_urlhaus_results(data: Dict[str, Any]):
    """Display URLhaus results"""
    st.subheader("🌐 URLhaus Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    if data.get("status") == "not_found":
        st.info("No malicious URLs found in URLhaus")
        return
    
    if data.get("type") == "url":
        st.write(f"**Status:** {data.get('status')}")
        st.write(f"**Threat:** {data.get('threat')}")
        
        if data.get("tags"):
            st.write(f"**Tags:** {', '.join(data.get('tags', []))}")
    
    elif data.get("type") == "domain":
        st.write(f"**URLs Found:** {data.get('url_count')}")
        
        if data.get("urls"):
            st.write("**Recent URLs:**")
            for url in data.get("urls", []):
                col1, col2 = st.columns([4, 1])
                with col1:
                    st.write(url.get("url"))
                with col2:
                    st.caption(url.get("threat", ""))


def display_urlscan_results(data: Dict[str, Any]):
    """Display URLscan results"""
    st.subheader("🔍 URLscan Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    if data.get("status") == "not_found":
        st.info("No scan results found for this observable")
        return
    
    if data.get("status") == "submitted":
        st.info(f"✅ URL submitted for scanning!")
        st.write(f"**Scan ID:** {data.get('scan_id')}")
        st.markdown(f"[View Full Scan]({data.get('scan_url')})")
        return
    
    # Display scan results
    scan_count = data.get("scan_count", 0)
    if scan_count > 0:
        st.write(f"**Detections:** {scan_count}")
        
        # Display threats
        threats = data.get("threats", [])
        if threats:
            with st.expander("View Threats", expanded=False):
                for threat in threats:
                    st.warning(f"**{threat.get('engine')}**: {threat.get('result')}")
        
        # Display verdicts
        verdicts = data.get("verdicts", {})
        if verdicts:
            st.write("**Verdicts:**")
            for engine, verdict in verdicts.items():
                st.write(f"- {engine}: {verdict}")


def display_hunter_results(data: Dict[str, Any]):
    """Display Hunter.io results (email and domain intelligence)"""
    st.subheader("🎯 Hunter.io Results")

    if not data:
        st.info("ℹ️ No Hunter.io data available")
        return

    if "error" in data:
        st.error(f"Error: {data['error']}")
        return

    # Domain search results
    if data.get("type") == "domain":
        st.write(f"**Domain:** {data.get('observable')}")

        # Company information
        company_info = data.get("company_info", {})
        if company_info and "error" not in str(company_info):
            with st.expander("Company Information", expanded=True):
                col1, col2 = st.columns(2)
                with col1:
                    if "name" in company_info:
                        st.write(f"**Name:** {company_info.get('name')}")
                    if "description" in company_info:
                        st.write(f"**Description:** {company_info.get('description')}")
                    if "industry" in company_info:
                        st.write(f"**Industry:** {company_info.get('industry')}")
                    if "size" in company_info:
                        st.write(f"**Size:** {company_info.get('size')}")
                with col2:
                    if "location" in company_info:
                        st.write(f"**Location:** {company_info.get('location')}")
                    if "founded" in company_info:
                        st.write(f"**Founded:** {company_info.get('founded')}")
                    if "logo" in company_info:
                        st.image(company_info.get('logo'), width=150)

        # Email count summary
        email_count = data.get("email_count", {})
        if email_count and "error" not in str(email_count):
            with st.expander("Email Count Summary", expanded=True):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Emails", email_count.get("total", 0))
                with col2:
                    st.metric("Personal", email_count.get("personal", 0))
                with col3:
                    st.metric("Generic", email_count.get("generic", 0))

        # Discovered emails
        emails = data.get("emails", [])
        if emails:
            st.info(f"✉️ {len(emails)} emails discovered")
            with st.expander("View Emails", expanded=False):
                email_df = pd.DataFrame([
                    {
                        "Email": e.get("value") if isinstance(e, dict) else e,
                        "First Name": e.get("first_name", "") if isinstance(e, dict) else "",
                        "Last Name": e.get("last_name", "") if isinstance(e, dict) else "",
                        "Title": e.get("position", "") if isinstance(e, dict) else "",
                        "Confidence": f"{e.get('confidence', 0)}%" if isinstance(e, dict) else ""
                    }
                    for e in emails[:200]
                ])
                st.dataframe(email_df, use_container_width=True)

    # Email verification/enrichment results
    elif data.get("type") == "email":
        st.write(f"**Email:** {data.get('observable')}")

        # Email verification status
        verification = data.get("verification", {})
        if verification and "error" not in str(verification):
            status = verification.get("status", "unknown")
            color = "🟢" if status == "valid" else "🔴" if status == "invalid" else "🟡"
            st.write(f"{color} **Verification Status:** {status}")
            if "score" in verification:
                st.write(f"**Confidence Score:** {verification.get('score')}/100")

        # Person information
        person_info = data.get("person", {})
        if person_info and "error" not in str(person_info):
            with st.expander("Person Information", expanded=True):
                col1, col2 = st.columns(2)
                with col1:
                    if "first_name" in person_info:
                        st.write(f"**First Name:** {person_info.get('first_name')}")
                    if "last_name" in person_info:
                        st.write(f"**Last Name:** {person_info.get('last_name')}")
                    if "title" in person_info:
                        st.write(f"**Title:** {person_info.get('title')}")
                with col2:
                    if "company" in person_info:
                        st.write(f"**Company:** {person_info.get('company')}")
                    if "location" in person_info:
                        st.write(f"**Location:** {person_info.get('location')}")
                    if "linkedin_url" in person_info:
                        st.markdown(f"**LinkedIn:** [{person_info.get('linkedin_url')}]({person_info.get('linkedin_url')})")

        # Company information from person
        company_info = data.get("company", {})
        if company_info and "error" not in str(company_info):
            with st.expander("Company Information", expanded=False):
                if "name" in company_info:
                    st.write(f"**Name:** {company_info.get('name')}")
                if "industry" in company_info:
                    st.write(f"**Industry:** {company_info.get('industry')}")
                if "size" in company_info:
                    st.write(f"**Size:** {company_info.get('size')}")

    # Raw data viewer - filtered to show only useful data
    if data.get("raw_data"):
        raw_data = data.get("raw_data", {})
        # Filter out empty objects and errors
        filtered_raw = {}
        for key, value in raw_data.items():
            if value and isinstance(value, dict):
                # Remove null/empty values from each section
                clean_value = {k: v for k, v in value.items() if v}
                if clean_value:
                    filtered_raw[key] = clean_value
            elif value:
                filtered_raw[key] = value
        
        if filtered_raw:
            with st.expander("Raw Data (Hunter.io)", expanded=False):
                st.code(str(filtered_raw), language="json")
        else:
            with st.expander("Raw Data (Hunter.io)", expanded=False):
                st.info("No additional data available from Hunter.io")
    else:
        with st.expander("Raw Data (Hunter.io)", expanded=False):
            st.info("No data returned from Hunter.io API")


def display_malware_bazaar_results(data: Dict[str, Any]):
    """Display Malware Bazaar results (malware analysis and threat intelligence)"""
    st.subheader("🦠 Malware Bazaar Results")

    if not data:
        st.info("ℹ️ No Malware Bazaar data available")
        return

    if "error" in data:
        st.error(f"Error: {data['error']}")
        return

    # Hash query results
    if data.get("type") == "hash":
        query_status = data.get("query_status", "")
        
        if query_status == "ok":
            st.success("✅ Malware sample found in Malware Bazaar!")
            
            # Basic file information
            with st.expander("File Information", expanded=True):
                col1, col2 = st.columns(2)
                with col1:
                    if data.get("file_name"):
                        st.write(f"**File Name:** {data.get('file_name')}")
                    if data.get("file_size"):
                        st.write(f"**File Size:** {data.get('file_size')} bytes")
                    if data.get("file_type"):
                        st.write(f"**File Type:** {data.get('file_type')}")
                    if data.get("file_format"):
                        st.write(f"**File Format:** {data.get('file_format')}")
                with col2:
                    if data.get("file_arch"):
                        st.write(f"**Architecture:** {data.get('file_arch')}")
                    if data.get("file_type_mime"):
                        st.write(f"**MIME Type:** {data.get('file_type_mime')}")
                    if data.get("magika"):
                        st.write(f"**Magika (AI Detection):** {data.get('magika')}")

            # Hashes
            with st.expander("File Hashes", expanded=False):
                col1, col2 = st.columns(2)
                with col1:
                    if data.get("sha256"):
                        st.code(data.get("sha256"), language="text")
                    if data.get("md5"):
                        st.code(data.get("md5"), language="text")
                with col2:
                    if data.get("sha1"):
                        st.code(data.get("sha1"), language="text")
                    if data.get("sha3_384"):
                        st.code(data.get("sha3_384"), language="text")

            # Malware family and signatures
            if data.get("signature"):
                st.warning(f"🔴 **Malware Family:** {data.get('signature')}")
            
            if data.get("tags"):
                tags = data.get("tags", [])
                st.info(f"📋 **Tags:** {', '.join(tags) if isinstance(tags, list) else tags}")

            # Temporal information
            with st.expander("Temporal Information", expanded=False):
                col1, col2 = st.columns(2)
                with col1:
                    if data.get("first_seen"):
                        st.write(f"**First Seen:** {data.get('first_seen')}")
                with col2:
                    if data.get("last_seen"):
                        st.write(f"**Last Seen:** {data.get('last_seen')}")

            # Submission info
            with st.expander("Submission Information", expanded=False):
                if data.get("reporter"):
                    st.write(f"**Reported By:** {data.get('reporter')}")
                if data.get("delivery_method"):
                    st.write(f"**Delivery Method:** {data.get('delivery_method')}")

            # Hash signatures (SSDEEP, TLSH, etc)
            with st.expander("Similarity Hashes", expanded=False):
                if data.get("imphash"):
                    st.write(f"**Import Hash (imphash):** `{data.get('imphash')}`")
                if data.get("tlsh"):
                    st.write(f"**TLSH Hash:** `{data.get('tlsh')}`")
                if data.get("telfhash"):
                    st.write(f"**Telfhash:** `{data.get('telfhash')}`")
                if data.get("gimphash"):
                    st.write(f"**Gimphash:** `{data.get('gimphash')}`")
                if data.get("ssdeep"):
                    st.write(f"**SSDEEP:** `{data.get('ssdeep')}`")
                if data.get("dhash_icon"):
                    st.write(f"**Icon DHash:** `{data.get('dhash_icon')}`")
                if data.get("trid"):
                    st.write(f"**TrID:** {data.get('trid')}")

            # Intelligence data
            intelligence = data.get("intelligence", {})
            if intelligence and isinstance(intelligence, dict):
                with st.expander("Threat Intelligence", expanded=True):
                    if intelligence.get("clamav"):
                        st.write(f"**ClamAV Detection:** {intelligence.get('clamav')}")
                    if intelligence.get("downloads"):
                        st.metric("Downloads from MalwareBazaar", intelligence.get("downloads"))
                    if intelligence.get("uploads"):
                        st.metric("Uploads to MalwareBazaar", intelligence.get("uploads"))
                    if intelligence.get("mail"):
                        st.write(f"**Mail Intelligence:** {intelligence.get('mail')}")

            # Code signing information
            if data.get("code_sign"):
                with st.expander("Code Signing Information", expanded=False):
                    cert = data.get("code_sign", {})
                    if isinstance(cert, dict):
                        if cert.get("subject_cn"):
                            st.write(f"**Subject CN:** {cert.get('subject_cn')}")
                        if cert.get("issuer_cn"):
                            st.write(f"**Issuer CN:** {cert.get('issuer_cn')}")
                        if cert.get("valid_from"):
                            st.write(f"**Valid From:** {cert.get('valid_from')}")
                        if cert.get("valid_to"):
                            st.write(f"**Valid To:** {cert.get('valid_to')}")

            # YARA rules
            yara_rules = data.get("yara_rules", [])
            if yara_rules and isinstance(yara_rules, list):
                with st.expander(f"YARA Rules ({len(yara_rules)})", expanded=False):
                    for rule in yara_rules[:50]:
                        if isinstance(rule, dict):
                            st.write(f"**{rule.get('rule_name')}** - {rule.get('author')}")
                            st.write(f"__{rule.get('description')}__")
                        else:
                            st.write(rule)

            # Comments
            comments = data.get("comments", [])
            if comments and isinstance(comments, list):
                with st.expander(f"Community Comments ({len(comments)})", expanded=False):
                    for comment in comments[:20]:
                        if isinstance(comment, dict):
                            st.write(f"**{comment.get('display_name')}** ({comment.get('date_added')})")
                            st.write(f"_{comment.get('comment')}_")
                        else:
                            st.write(comment)
        else:
            st.warning(f"⚠️ Query Status: {query_status}")

    # Tag or Signature query results
    elif data.get("type") in ["tag_query", "signature_query"]:
        query_type = "Tag" if data.get("type") == "tag_query" else "Signature"
        
        sample_count = data.get("sample_count", 0)
        st.info(f"🔍 Found {sample_count} malware samples for {query_type.lower()}: **{data.get('observable')}**")
        
        if data.get("samples") and isinstance(data.get("samples"), list):
            with st.expander(f"View Samples (showing first 100)", expanded=False):
                samples_df = pd.DataFrame([
                    {
                        "File Name": s.get("file_name", ""),
                        "MD5": s.get("md5_hash", "")[:16] + "...",
                        "File Type": s.get("file_type", ""),
                        "Signature": s.get("signature", ""),
                        "First Seen": s.get("first_seen", ""),
                    }
                    for s in data.get("samples", [])[:100]
                ])
                st.dataframe(samples_df, use_container_width=True)

    # Raw data viewer
    if data.get("raw_data"):
        raw_data = data.get("raw_data", {})
        filtered_raw = {}
        for key, value in raw_data.items():
            if value and isinstance(value, dict):
                clean_value = {k: v for k, v in value.items() if v}
                if clean_value:
                    filtered_raw[key] = clean_value
            elif value:
                filtered_raw[key] = value
        
        if filtered_raw:
            with st.expander("Raw Data (Malware Bazaar)", expanded=False):
                st.code(str(filtered_raw), language="json")
        else:
            with st.expander("Raw Data (Malware Bazaar)", expanded=False):
                st.info("No additional data available from Malware Bazaar")
    else:
        with st.expander("Raw Data (Malware Bazaar)", expanded=False):
            st.info("No data returned from Malware Bazaar API")

#############################
def display_threatfox_results(data: Dict[str, Any]):
    """Display ThreatFox results (IOC threat intelligence) - CLEAN VERSION"""
    st.subheader("🔍 ThreatFox Results")

    if not data:
        st.info("ℹ️ No ThreatFox data available")
        return

    # Handle skipped status
    if data.get("query_status") == "skipped":
        st.warning(f"⚠️ {data.get('message', 'ThreatFox query was skipped')}")
        st.info("💡 **Tip:** For IP addresses, try adding a port number (e.g., '192.168.1.1:443')")
        return

    if "error" in data and data.get("query_status") == "error":
        st.error(f"❌ Error: {data['error']}")
        return

    query_status = data.get("query_status", "")
    ioc_count = data.get("ioc_count", 0)

    if query_status == "ok":
        if ioc_count == 0:
            st.info("ℹ️ No IOCs found in ThreatFox database")
            return

        st.success(f"✅ Found {ioc_count} IOC(s) in ThreatFox!")

        iocs = data.get("iocs", [])
        
        if not isinstance(iocs, list):
            st.error(f"❌ Error: IOCs data is malformed")
            return
        
        if len(iocs) == 0:
            st.info("ℹ️ No IOCs in data list")
            return

        # Display each IOC with comprehensive details
        for idx, ioc in enumerate(iocs, 1):
            try:
                with st.expander(f"📌 IOC {idx}/{len(iocs)}: {ioc.get('ioc', 'N/A')}", expanded=(idx == 1)):
                    
                    # Key metrics in columns
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        confidence = ioc.get('confidence_level', 'N/A')
                        st.metric("Confidence", f"{confidence}%" if confidence != 'N/A' else 'N/A')
                    with col2:
                        threat_type = ioc.get('threat_type_desc', ioc.get('threat_type', 'N/A'))
                        if 'botnet' in threat_type.lower():
                            st.metric("Threat", "🤖 Botnet C&C")
                        elif 'phishing' in threat_type.lower():
                            st.metric("Threat", "🎣 Phishing")
                        elif 'malware' in threat_type.lower():
                            st.metric("Threat", "🦠 Malware")
                        else:
                            st.metric("Threat", threat_type[:15])
                    with col3:
                        reporter = ioc.get('reporter', 'N/A')
                        st.metric("Reporter", reporter[:12] if reporter != 'N/A' else 'N/A')
                    with col4:
                        ioc_id = ioc.get('id', 'N/A')
                        st.metric("ThreatFox ID", str(ioc_id))

                    st.markdown("---")
                    
                    # IOC Details
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"🔹 **IOC:** `{ioc.get('ioc', 'N/A')}`")
                        st.write(f"🔹 **Type:** {ioc.get('ioc_type_desc', ioc.get('ioc_type', 'N/A'))}")
                        st.write(f"🔹 **Threat Type:** {ioc.get('threat_type_desc', ioc.get('threat_type', 'N/A'))}")
                        
                        compromised = ioc.get('is_compromised', False)
                        st.write(f"🔹 **Status:** {'🟢 Active/Compromised' if compromised else '🟡 Inactive'}")
                        
                        first_seen = ioc.get('first_seen', 'N/A')
                        st.write(f"🔹 **First Seen:** {first_seen}")
                        
                        last_seen = ioc.get('last_seen')
                        if last_seen:
                            st.write(f"🔹 **Last Seen:** {last_seen}")
                        else:
                            st.write(f"🔹 **Last Seen:** 🔴 STILL ACTIVE")

                    with col2:
                        st.write(f"🔹 **Confidence Level:** {ioc.get('confidence_level', 'N/A')}%")
                        st.write(f"🔹 **Reporter:** {ioc.get('reporter', 'N/A')}")
                        st.write(f"🔹 **ThreatFox ID:** {ioc.get('id', 'N/A')}")

                    # Malware information
                    if ioc.get("malware") or ioc.get("malware_printable"):
                        st.markdown("---")
                        malware_name = ioc.get('malware_printable', ioc.get('malware', 'Unknown'))
                        st.error(f"🦠 **MALWARE FAMILY DETECTED:** {malware_name.upper()}")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            if ioc.get("malware_alias"):
                                st.write(f"**Aliases:** {ioc.get('malware_alias')}")
                        with col2:
                            if ioc.get("malware_malpedia"):
                                st.markdown(f"[🔗 View on Malpedia]({ioc.get('malware_malpedia')})")

                    # Tags
                    if ioc.get("tags"):
                        st.markdown("---")
                        tags = ioc.get("tags", [])
                        if isinstance(tags, list):
                            tags_str = ", ".join(tags)
                            st.info(f"📋 **Tags:** {tags_str}")
                        else:
                            st.info(f"📋 **Tags:** {tags}")

                    # Reference
                    if ioc.get("reference"):
                        st.markdown("---")
                        st.write("**🔗 Reference:**")
                        st.markdown(f"🔹 [**Reference URL**]({ioc.get('reference')})")

                    # Malware Samples
                    if ioc.get("malware_samples") and len(ioc.get("malware_samples", [])) > 0:
                        st.markdown("---")
                        samples = ioc.get("malware_samples", [])
                        st.write(f"**📦 Associated Malware Samples ({len(samples)}):**")
                        
                        for sample_idx, sample in enumerate(samples, 1):
                            st.write(f"**Sample {sample_idx}:**")
                            col1, col2 = st.columns(2)
                            with col1:
                                if sample.get('md5_hash'):
                                    st.code(sample.get('md5_hash'), language='text')
                                    st.caption("MD5 Hash")
                            with col2:
                                if sample.get('sha256_hash'):
                                    st.code(sample.get('sha256_hash'), language='text')
                                    st.caption("SHA256 Hash")
                            
                            if sample.get("time_stamp"):
                                st.write(f"**Time:** {sample.get('time_stamp')}")
                            if sample.get("malware_bazaar"):
                                st.markdown(f"[🔗 View on Malware Bazaar]({sample.get('malware_bazaar')})")
                            st.write("")

            except Exception as e:
                st.error(f"❌ Error displaying IOC {idx}: {str(e)}")

        # Summary statistics
        st.markdown("---")
        st.subheader("📊 ThreatFox Summary Statistics")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            malware_count = len([ioc for ioc in iocs if ioc.get("malware")])
            st.metric("Malware IOCs", malware_count)
        with col2:
            botnet_count = len([ioc for ioc in iocs if "botnet" in ioc.get("threat_type", "").lower()])
            st.metric("Botnet C&C", botnet_count)
        with col3:
            phishing_count = len([ioc for ioc in iocs if "phishing" in ioc.get("threat_type", "").lower()])
            st.metric("Phishing", phishing_count)
        with col4:
            avg_confidence = sum([ioc.get("confidence_level", 0) for ioc in iocs]) / len(iocs) if iocs else 0
            st.metric("Avg Confidence", f"{avg_confidence:.0f}%")

        # Table view
        st.markdown("---")
        st.write("**📋 All IOCs Summary Table:**")
        
        iocs_table = []
        for ioc in iocs:
            iocs_table.append({
                "IOC": ioc.get("ioc", ""),
                "Type": ioc.get("ioc_type_desc", ioc.get("ioc_type", "")),
                "Threat": ioc.get("threat_type_desc", ioc.get("threat_type", "")),
                "Malware": ioc.get("malware_printable", ioc.get("malware", "")),
                "Confidence": f"{ioc.get('confidence_level', '')}%",
                "First Seen": ioc.get("first_seen", ""),
                "Reporter": ioc.get("reporter", ""),
                "Status": "Active" if ioc.get("is_compromised") else "Inactive"
            })
        
        if iocs_table:
            import pandas as pd
            df_iocs = pd.DataFrame(iocs_table)
            st.dataframe(df_iocs, use_container_width=True, hide_index=True)
    else:
        st.warning(f"⚠️ Query Status: {query_status}")


# Add this function after the other display functions

def display_yaraify_results(data: Dict[str, Any]):
    """Display YARAify results (YARA rule detection and malware analysis)"""
    st.subheader("🔍 YARAify Results")

    if not data:
        st.info("ℹ️ No YARAify data available")
        return

    if "error" in data:
        st.error(f"Error: {data['error']}")
        return

    # Handle hash not found
    if data.get("query_status") == "hash_not_found":
        st.info("ℹ️ Hash not found in YARAify database")
        return

    query_status = data.get("query_status", "")
    
    if query_status == "ok":
        st.success("✅ Malware sample found in YARAify!")
        
        # File information - NO nested expanders
        st.markdown("---")
        st.write("**📄 File Information:**")
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"🔹 **File Name:** {data.get('file_name') or 'N/A'}")
            st.write(f"🔹 **File Size:** {data.get('file_size') or 'N/A'} bytes")
            st.write(f"🔹 **File Type:** {data.get('file_type') or 'N/A'}")
            st.write(f"🔹 **MIME Type:** {data.get('mime_type') or 'N/A'}")
        with col2:
            st.write(f"🔹 **MD5:** `{data.get('md5_hash') or 'N/A'}`")
            st.write(f"🔹 **SHA1:** `{data.get('sha1_hash') or 'N/A'}`")
            st.write(f"🔹 **SHA256:** `{data.get('sha256_hash') or 'N/A'}`")

        # Additional hashes and similarity metrics - always show these
        st.write(f"🔹 **SHA3-384:** {data.get('sha3_384') or 'N/A'}")
        st.write(f"🔹 **Imphash:** {data.get('imphash') or 'N/A'}")
        st.write(f"🔹 **ssdeep:** {data.get('ssdeep') or 'N/A'}")
        st.write(f"🔹 **TLSH:** {data.get('tlsh') or 'N/A'}")
        st.write(f"🔹 **Telfhash:** {data.get('telfhash') or 'N/A'}")
        st.write(f"🔹 **Gimphash:** {data.get('gimphash') or 'N/A'}")
        st.write(f"🔹 **Icon DHash:** {data.get('dhash_icon') or 'N/A'}")

        # Sightings and file download link
        st.write(f"🔹 **Sightings:** {data.get('sightings') or 'N/A'}")
        if data.get('file_download'):
            st.markdown(f"🔹 **File Download:** [Download Sample]({data.get('file_download')})")

        # Malware detection
        st.markdown("---")
        st.write("**🔍 Detection Analysis:**")
        
        if data.get("signature"):
            st.error(f"🔴 **MALWARE SIGNATURE DETECTED:** {data.get('signature')}")
        else:
            st.success("✅ **No malware signature detected**")
        
        if data.get("malware_family"):
            st.warning(f"🦠 **Malware Family:** {data.get('malware_family')}")

        # YARA rules
        yara_count = data.get("yara_rules", 0)
        if yara_count > 0:
            st.success(f"⚠️ **YARA Rules Matched:** {yara_count}")
            
            yara_rules_list = data.get("yara_rules_list", [])
            if yara_rules_list:
                st.write("**YARA Rules Details:**")
                for idx, rule in enumerate(yara_rules_list, 1):
                    if isinstance(rule, dict):
                        rule_name = rule.get("rule_name", "Unknown")
                        author = rule.get("author", "Unknown")
                        description = rule.get("description", "")
                        
                        st.write(f"**{idx}. {rule_name}**")
                        st.write(f"   🔹 Author: {author}")
                        if description:
                            st.write(f"   🔹 Description: {description}")
                        st.write("")
        else:
            st.info("ℹ️ No YARA rules matched")
        
        # ClamAV signature
        if data.get("clamav_signature"):
            st.info(f"🛡️ **ClamAV Signature:** {data.get('clamav_signature')}")

        # Temporal information - NO nested expanders
        st.markdown("---")
        st.write("**📅 Temporal & Additional Information:**")
        col1, col2 = st.columns(2)
        with col1:
            if data.get("first_seen"):
                st.write(f"🔹 **First Seen:** {data.get('first_seen')}")
            else:
                st.write(f"🔹 **First Seen:** N/A")
        with col2:
            if data.get("last_seen"):
                st.write(f"🔹 **Last Seen:** {data.get('last_seen')}")
            else:
                st.write(f"🔹 **Last Seen:** N/A")
        
        # Reporter information
        if data.get("reporter"):
            st.write(f"🔹 **Reporter:** {data.get('reporter')}")
        
        # Tags
        tags = data.get("tags", [])
        if tags:
            st.write(f"🔹 **Tags:** {', '.join(tags)}")
        
        # Comments
        comments = data.get("comments", 0)
        if comments > 0:
            st.write(f"🔹 **Community Comments:** {comments}")
            
            comments_list = data.get("comments_list", [])
            if comments_list:
                st.write("**Recent Comments:**")
                for comment in comments_list:
                    if isinstance(comment, dict):
                        author = comment.get("display_name", "Anonymous")
                        text = comment.get("comment", "")
                        date = comment.get("date_added", "")
                        st.write(f"**{author}** ({date}): _{text}_")
                        st.write("---")
        
        # Raw data as last expandable section (top-level only)
        st.markdown("---")
        with st.expander("🔧 Debug - Raw Response Data", expanded=False):
            if data.get("raw_data"):
                st.json(data.get("raw_data"))
            else:
                st.write("No raw data available")

    else:
        st.warning(f"⚠️ Query Status: {query_status}")


def display_sslbl_results(data: Dict[str, Any]):
    """Display SSLBL results (SSL Certificate Blacklist - Botnet C2 IPs and JA3 fingerprints)"""
    st.subheader("🔒 SSLBL Results")
    
    if not data:
        st.info("ℹ️ No SSLBL data available")
        return
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    if data.get("query_status") == "not_found":
        st.success("✅ Clean - Not found in SSLBL blacklist")
        return
    
    if data.get("query_status") == "found":
        st.error("🚨 ALERT - Found in SSLBL Botnet C2 Blacklist!")
        
        # Display threat info
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Threat Level", data.get("threat_level", "unknown").upper())
        with col2:
            st.metric("Matches Found", data.get("matches_count", 0))
        with col3:
            st.metric("Source", data.get("source", "SSLBL"))
        
        # Display key findings
        if data.get("key_findings"):
            st.markdown("**🔍 Key Findings:**")
            for finding in data["key_findings"]:
                st.write(f"• {finding}")
        
        # Display matches details
        if data.get("matches"):
            st.markdown("---")
            st.markdown("**📋 Match Details:**")
            matches_table = []
            for match in data["matches"][:50]:
                matches_table.append({
                    "IP Address": match.get("ip_address", "N/A"),
                    "Port": match.get("port", "N/A"),
                    "First Seen": match.get("first_seen", "N/A"),
                    "Reason": match.get("listing_reason", "N/A")
                })
            
            if matches_table:
                df_matches = pd.DataFrame(matches_table)
                st.dataframe(df_matches, use_container_width=True, hide_index=True)
        
        # Intelligence summary
        st.markdown("---")
        if data.get("intelligence"):
            intel = data["intelligence"]
            st.markdown("**📊 Intelligence Summary:**")
            st.write(f"🔹 **Type:** {intel.get('type', 'N/A')}")
            st.write(f"🔹 **Confidence:** {intel.get('confidence', 'N/A')}")
            st.write(f"🔹 **Source:** {intel.get('source', 'N/A')}")


def display_feodo_results(data: Dict[str, Any]):
    """Display Feodo Tracker results (Botnet C2 blocklist)"""
    st.subheader("🚨 Feodo Tracker Results")
    
    if not data:
        st.info("ℹ️ No Feodo Tracker data available")
        return
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    if data.get("query_status") == "not_found":
        st.success("✅ Clean - Not found in Feodo Tracker blocklist")
        return
    
    if data.get("query_status") == "found":
        st.error("🚨 ALERT - Found in Feodo Tracker Botnet C2 Blocklist!")
        
        # Display threat info
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Threat Level", data.get("threat_level", "unknown").upper())
        with col2:
            st.metric("Matches Found", data.get("matches_count", 0))
        with col3:
            st.metric("Source", data.get("source", "FeodoTracker"))
        
        # Display key findings
        if data.get("key_findings"):
            st.markdown("**🔍 Key Findings:**")
            for finding in data["key_findings"]:
                st.write(f"• {finding}")
        
        # Display matches details
        if data.get("matches"):
            st.markdown("---")
            st.markdown("**📋 Match Details:**")
            matches_table = []
            for match in data["matches"][:50]:
                matches_table.append({
                    "IOC": match.get("ioc", match.get("ip_address", "N/A")),
                    "Type": match.get("ioc_type", "N/A"),
                    "Malware Family": match.get("malware_family", "N/A"),
                    "First Seen": match.get("first_seen", "N/A"),
                })
            
            if matches_table:
                df_matches = pd.DataFrame(matches_table)
                st.dataframe(df_matches, use_container_width=True, hide_index=True)
        
        # Intelligence summary
        st.markdown("---")
        if data.get("intelligence"):
            intel = data["intelligence"]
            st.markdown("**📊 Intelligence Summary:**")
            st.write(f"🔹 **Type:** {intel.get('type', 'N/A')}")
            st.write(f"🔹 **Confidence:** {intel.get('confidence', 'N/A')}")
            st.write(f"🔹 **Source:** {intel.get('source', 'N/A')}")
            if intel.get("malware_families"):
                st.write(f"🔹 **Malware Families:** {', '.join(intel['malware_families'])}")


def display_results(results: Dict[str, Any], observable: str):
    """Display all results for single indicator - CLEAN VERSION"""
    st.markdown("---")
    
    # Overview section
    display_results_overview(results, observable)
    
    st.markdown("---")
    st.subheader("🔬 Detailed Results by Source")
    
    # Create a summary table of all sources
    sources_summary = []
    
    # Check each source and build summary
    source_checks = [
        ("VirusTotal", results.get("VirusTotal"), display_virustotal_results),
        ("Shodan", results.get("Shodan"), display_shodan_results),
        ("AlienVault OTX", results.get("AlienVault OTX"), display_otx_results),
        ("AbuseIPDB", results.get("AbuseIPDB"), display_abuseipdb_results),
        ("IPInfo", results.get("IPInfo"), display_ipinfo_results),
        ("URLhaus", results.get("URLhaus"), display_urlhaus_results),
        ("URLscan", results.get("URLscan"), display_urlscan_results),
        ("IP Detective", results.get("IP Detective"), display_ipdetective_results),
        ("GetIPIntel", results.get("GetIPIntel"), display_getipintel_results),
        ("Ransomware.live", results.get("Ransomware.live"), display_ransomware_live_results),
        ("Hunter.io", results.get("Hunter.io"), display_hunter_results),
        ("Malware Bazaar", results.get("Malware Bazaar"), display_malware_bazaar_results),
        ("ThreatFox", results.get("ThreatFox"), display_threatfox_results),
        ("YARAify", results.get("YARAify"), display_yaraify_results),
        ("SSLBL", results.get("SSLBL"), display_sslbl_results),
        ("Feodo Tracker", results.get("Feodo Tracker"), display_feodo_results),
    ]
    
    for source_name, source_data, display_func in source_checks:
        if source_data and source_data.get("query_status") == "skipped":
            status = f"⏭️ Skipped"
            sources_summary.append({"Source": source_name, "Status": status})
        elif source_data and "error" not in source_data:
            status = "✅ Data Found"
            sources_summary.append({"Source": source_name, "Status": status})
        elif source_data and "error" in source_data:
            status = f"⚠️ Error"
            sources_summary.append({"Source": source_name, "Status": status})
        else:
            status = "⏭️ No Data"
            sources_summary.append({"Source": source_name, "Status": status})
    
    # Display summary table
    if sources_summary:
        st.markdown("**Query Status Summary:**")
        summary_df = pd.DataFrame(sources_summary)
        st.dataframe(summary_df, use_container_width=True, hide_index=True)
    
    # Display detailed results in tabs - FIXED THREATFOX FILTERING
    st.markdown("---")
    
    # Get list of sources with data - IMPROVED FILTERING
    sources_with_data = [
        ("VirusTotal", results.get("VirusTotal"), display_virustotal_results),
        ("Shodan", results.get("Shodan"), display_shodan_results),
        ("AlienVault OTX", results.get("AlienVault OTX"), display_otx_results),
        ("AbuseIPDB", results.get("AbuseIPDB"), display_abuseipdb_results),
        ("IPInfo", results.get("IPInfo"), display_ipinfo_results),
        ("URLhaus", results.get("URLhaus"), display_urlhaus_results),
        ("URLscan", results.get("URLscan"), display_urlscan_results),
        ("IP Detective", results.get("IP Detective"), display_ipdetective_results),
        ("GetIPIntel", results.get("GetIPIntel"), display_getipintel_results),
        ("Ransomware.live", results.get("Ransomware.live"), display_ransomware_live_results),
        ("Hunter.io", results.get("Hunter.io"), display_hunter_results),
        ("Malware Bazaar", results.get("Malware Bazaar"), display_malware_bazaar_results),
        ("ThreatFox", results.get("ThreatFox"), display_threatfox_results),
        ("YARAify", results.get("YARAify"), display_yaraify_results),
        ("SSLBL", results.get("SSLBL"), display_sslbl_results),
        ("Feodo Tracker", results.get("Feodo Tracker"), display_feodo_results),
    ]
    
    # FIXED FILTERING - Include any source that returned a non-error response
    valid_sources = []
    for name, data, func in sources_with_data:
        if data is not None and isinstance(data, dict):
            has_error = "error" in data
            is_skipped = data.get("query_status") == "skipped"
            is_ok = data.get("query_status") == "ok"
            has_real_data = not has_error and len(data) > 1
            has_iocs = data.get("ioc_count", 0) > 0
            yaraify_feedback = name == "YARAify" and has_error
            # Ransomware.live: always show if no error (even with 0 victims found)
            ransomware_no_error = name == "Ransomware.live" and not has_error

            if has_real_data or has_iocs or is_skipped or is_ok or yaraify_feedback or ransomware_no_error:
                valid_sources.append((name, data, func))
    
    if valid_sources:
        # Create tabs with better styling
        tab_labels = [f"📊 {name}" for name, _, _ in valid_sources]
        
        # CUSTOM TAB STYLING - Horizontal scrollable
        tabs_html = """
        <style>
        .stTabs [data-baseweb="tab-list"] {
            gap: 0;
            background-color: #1a1a1a;
            padding: 0;
            overflow-x: auto;
            overflow-y: hidden;
            white-space: nowrap;
            display: flex;
            flex-wrap: nowrap;
            max-width: 100%;
            scrollbar-width: thin;
            scrollbar-color: #ff4444 #1a1a1a;
        }
        
        .stTabs [data-baseweb="tab-list"]::-webkit-scrollbar {
            height: 6px;
        }
        
        .stTabs [data-baseweb="tab-list"]::-webkit-scrollbar-track {
            background: #1a1a1a;
        }
        
        .stTabs [data-baseweb="tab-list"]::-webkit-scrollbar-thumb {
            background: #ff4444;
            border-radius: 3px;
        }
        
        .stTabs [data-baseweb="tab"] {
            flex-shrink: 0;
            min-width: 120px;
            max-width: 150px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            padding: 10px 15px;
            margin: 0;
            border-radius: 0;
            border-bottom: 3px solid transparent;
            color: #ff4444;
            font-weight: 500;
            font-size: 13px;
        }
        
        .stTabs [aria-selected="true"] {
            color: #ff4444 !important;
            border-bottom-color: #ff4444 !important;
            background-color: #252525 !important;
        }
        
        .stTabs [data-baseweb="tab"]:hover {
            background-color: #252525 !important;
            color: #ffffff !important;
        }
        
        .stTabs [data-baseweb="tab-panel"] {
            padding-top: 20px;
        }
        </style>
        """
        
        st.markdown(tabs_html, unsafe_allow_html=True)
        
        # Create tabs
        tabs = st.tabs(tab_labels)
        
        for tab, (source_name, source_data, display_func) in zip(tabs, valid_sources):
            with tab:
                try:
                    display_func(source_data)
                except Exception as e:
                    st.error(f"Error rendering {source_name}: {str(e)}")
    else:
        st.info("ℹ️ No data available from selected sources.")

def display_batch_results(batch_results: Dict[str, Dict[str, Any]], indicators_metadata: list):
    """Display batch analysis results - individual report for each indicator"""
    st.markdown("---")
    st.subheader("📊 Batch Analysis Results")
    
    st.info(f"Total Indicators Analyzed: {len(batch_results)}")
    
    # Display each indicator's results
    for idx, (indicator, results) in enumerate(batch_results.items(), 1):
        metadata = next((m for m in indicators_metadata if m["indicator"] == indicator), {})
        
        st.markdown("---")
        st.markdown(f"## Indicator {idx}/{len(batch_results)}: `{indicator}`")
        st.caption(f"Type: {metadata.get('type', 'Unknown')}")
        
        # Display full results for this indicator
        display_results(results, indicator)
        
        # Export options for individual indicator
        with st.expander(f"📥 Export Report for {indicator}"):
            col1, col2 = st.columns(2)
            
            with col1:
                json_data = format_results_for_export(results, indicator)
                st.download_button(
                    label="📄 Download as JSON",
                    data=json_data,
                    file_name=f"report_{indicator.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    key=f"json_{idx}"
                )
            
            with col2:
                text_report = create_summary_report(results, indicator)
                st.download_button(
                    label="📝 Download as Text",
                    data=text_report,
                    file_name=f"report_{indicator.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                    key=f"txt_{idx}"
                )


def display_export_section(results: Dict[str, Any], observable: str):
    """Display export options for single indicator"""
    st.markdown("---")
    st.subheader("📥 Export Results")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # Export as JSON
        json_data = format_results_for_export(results, observable)
        st.download_button(
            label="📄 Download as JSON",
            data=json_data,
            file_name=f"report_{observable}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
        )
    
    with col2:
        # Export as Text Report
        text_report = create_summary_report(results, observable)
        st.download_button(
            label="📝 Download as Text Report",
            data=text_report,
            file_name=f"report_{observable}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
        )
    
    with col3:
        st.info("💡 Use 'Copy to clipboard' button above to share results")


def display_batch_export_section(batch_results: Dict[str, Dict[str, Any]], indicators_metadata: list):
    """Display export options for batch results"""
    st.markdown("---")
    st.subheader("📥 Export All Batch Results")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Export complete batch as JSON
        json_data = export_batch_results_json(batch_results, indicators_metadata)
        st.download_button(
            label="📄 Download All as JSON",
            data=json_data,
            file_name=f"batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
        )
    
    with col2:
        # Export complete batch as text
        text_report = export_batch_results_txt(batch_results, indicators_metadata)
        st.download_button(
            label="📝 Download All as Text",
            data=text_report,
            file_name=f"batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
        )
    
    # Individual reports ZIP
    st.markdown("---")
    st.info("💡 Individual reports for each indicator can be downloaded from their respective sections above")


def main():
    """Main application"""
    initialize_session_state()
    
    # Header
    display_header()
    
    st.markdown("---")
    
    # Input section
    observable, threat_group, analyze_button, selected_sources, mode, uploaded_file = display_input_section()
    
    # Handle Single Indicator Analysis
    if mode == "single" and analyze_button and (observable or threat_group) and selected_sources:
        
        # Threat Group Analysis
        if threat_group:
            st.info(f"🚨 Analyzing threat group: **{threat_group}**")
            
            # Run threat group analysis
            with st.spinner("Analyzing threat group..."):
                results = run_threat_group_analysis(threat_group, selected_sources)
            
            # Store in session
            st.session_state.results = results
            st.session_state.threat_group = threat_group
            st.session_state.last_query = datetime.now()
            st.session_state.batch_mode = False
            
            # Display threat group results
            display_threat_group_results(results, threat_group)
            
            # Export section for threat group
            display_export_section(results, threat_group)
            
        # Observable Analysis
        else:
            # Validate observable
            obs_type = classify_observable(observable)
            if obs_type == "Unknown":
                st.error("❌ Invalid observable format. Please enter a valid IP, domain, URL, or hash (or IP:port for ThreatFox).")
            else:
                st.info(f"🔎 Observable type detected: **{obs_type}**")
                
                # Run analysis
                with st.spinner("Analyzing..."):
                    results = run_analysis(observable, selected_sources)
                
                # Store in session
                st.session_state.results = results
                st.session_state.observable = observable
                st.session_state.last_query = datetime.now()
                st.session_state.batch_mode = False
                
                # Display results
                display_results(results, observable)
                
                # Export section
                display_export_section(results, observable)
    
    # Handle Batch Analysis
    elif mode == "batch" and analyze_button and uploaded_file and selected_sources:
        # Read and parse file
        try:
            file_content = uploaded_file.read().decode("utf-8")
            indicators = parse_indicators_from_file(file_content)
            
            if not indicators:
                st.error("❌ No valid indicators found in the uploaded file.")
            else:
                # Validate indicators
                valid_indicators, invalid_indicators, summary = validate_batch_indicators(indicators)
                
                st.info(f"📋 File processed: {summary['total']} total, {summary['valid']} valid, {summary['invalid']} invalid")
                
                if invalid_indicators:
                    with st.expander(f"⚠️ {len(invalid_indicators)} Invalid Indicators"):
                        for invalid in invalid_indicators:
                            st.write(f"- {invalid['indicator']}: {invalid['reason']}")
                
                if valid_indicators:
                    # Store validated indicators in session state
                    st.session_state.valid_indicators = valid_indicators
                    st.session_state.batch_selected_sources = selected_sources
                    st.success(f"✅ Ready to analyze {len(valid_indicators)} indicators")
                
        except Exception as e:
            st.error(f"❌ Error processing file: {str(e)}")
    
    # Batch analysis execution (outside the file upload condition)
    if mode == "batch" and "valid_indicators" in st.session_state and st.session_state.valid_indicators:
        valid_indicators = st.session_state.valid_indicators
        
        if st.button("⚡ Start Batch Analysis", type="primary", use_container_width=True):
            selected_sources = st.session_state.get("batch_selected_sources", [])
            
            with st.spinner(f"Analyzing {len(valid_indicators)} indicators..."):
                batch_results = run_batch_analysis(valid_indicators, selected_sources)
            
            # Store in session
            st.session_state.batch_results = batch_results
            st.session_state.batch_mode = True
            st.session_state.last_query = datetime.now()
            
            st.success("✅ Batch analysis complete!")
            st.rerun()
    
    # Display batch results if they exist
    if mode == "batch" and st.session_state.batch_mode and st.session_state.batch_results:
        batch_results = st.session_state.batch_results
        valid_indicators = st.session_state.valid_indicators
        
        # Display batch results
        display_batch_results(batch_results, valid_indicators)
        
        # Batch export section
        display_batch_export_section(batch_results, valid_indicators)
    
    # Sidebar Navigation & Info
    with st.sidebar:
        # Brand section with CTI professional styling
        st.markdown("### <span style='color: #e63946; font-weight: bold; text-shadow: 0 0 10px #e63946;'>🔐 X-10 ThreatFusion</span>", unsafe_allow_html=True)
        st.markdown("**Intelligence Command Platform**")
        st.markdown("---")
        
        # Quick Stats
        st.markdown("**🎯 SYSTEM STATUS**")
        active_apis = Config.get_active_apis()
        col1, col2 = st.columns(2)
        with col1:
            total_supported = len(Config.SUPPORTED_INTELLIGENCE_SOURCES)
            st.metric("Intelligence Sources", f"{len(active_apis)}/{total_supported}")
        with col2:
            is_valid, _ = Config.validate_config()
            status = "ONLINE" if is_valid else "OFFLINE"
            st.metric("System", status)
        
        st.markdown("---")
        
        # Tools
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔄 Refresh", use_container_width=True):
                st.rerun()
        with col2:
            if st.button("🗑️ Clear", use_container_width=True):
                st.session_state.clear()
                st.rerun()
        
        st.markdown("---")
        
        # About section
        with st.expander("📖 About Platform", expanded=False):
            total = len(Config.SUPPORTED_INTELLIGENCE_SOURCES)
            st.markdown(f"""
            # <span style='color: #e63946; font-weight: bold;'>X-10 ThreatFusion</span>
            
            Unified platform for threat intelligence correlation across {total} premium threat intelligence sources.
            
            **Supported Indicators:**
            - IPv4 addresses & CIDR ranges
            - Domain names & URLs
            - File hashes (MD5, SHA1, SHA256)
            - Ransomware groups & APTs
            
            **Capabilities:**
            - Real-time threat correlation
            - Multi-source intelligence aggregation
            - Bidirectional observable-to-group analysis
            - Batch indicator processing
            - Machine-readable exports (JSON/TXT)
            
            **Use Cases:**
            - Incident Response
            - Threat Hunting
            - IOC Validation
            - APT/Ransomware tracking
            - OSINT investigations
            """, unsafe_allow_html=True)
        
        # Intelligence Sources
        with st.expander("📡 Intelligence Sources", expanded=False):
            st.markdown("**Connected Premium Feeds:**")
            for idx, api_name in enumerate(sorted(active_apis.keys()), 1):
                st.write(f"{idx}. ✅ {api_name}")
        
        # Debug info
        with st.expander("🔧 System Debug", expanded=False):
            debug_info = Config.debug_config()
            for key, status in debug_info.items():
                st.write(f"**{key}:** {status}")
        
        st.markdown("---")
        st.markdown("---")
        st.caption("🛡️ **Enterprise Threat Intelligence Platform** | v2.0 | © CTI Suite")

def get_api_clients() -> Dict[str, Any]:
    """Initialize API clients based on configuration with error handling"""
    clients = {}
    
    if Config.VIRUSTOTAL_API_KEY:
        try:
            clients["VirusTotal"] = VirusTotalAPI(Config.VIRUSTOTAL_API_KEY)
            logger.info("✅ VirusTotal initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize VirusTotal: {e}")
    
    if Config.SHODAN_API_KEY:
        try:
            clients["Shodan"] = ShodanAPI(Config.SHODAN_API_KEY)
            logger.info("✅ Shodan initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize Shodan: {e}")
    
    if Config.OTX_API_KEY:
        try:
            clients["AlienVault OTX"] = OTXAlienVaultAPI(Config.OTX_API_KEY)
            logger.info("✅ AlienVault OTX initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize OTX: {e}")
    
    if Config.IPINFO_API_KEY:
        try:
            clients["IPInfo"] = IPInfoAPI(Config.IPINFO_API_KEY)
            logger.info("✅ IPInfo initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize IPInfo: {e}")
    
    if Config.ABUSEIPDB_API_KEY:
        try:
            clients["AbuseIPDB"] = AbuseIPDBAPI(Config.ABUSEIPDB_API_KEY)
            logger.info("✅ AbuseIPDB initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize AbuseIPDB: {e}")
    
    if Config.URLSCAN_API_KEY:
        try:
            clients["URLscan"] = URLscanAPI(Config.URLSCAN_API_KEY)
            logger.info("✅ URLscan initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize URLscan: {e}")
    
    # URLhaus - Pass API key if available
    if Config.URLHAUS_API_KEY:
        try:
            clients["URLhaus"] = URLHausAPI(Config.URLHAUS_API_KEY)
            logger.info("✅ URLhaus initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize URLhaus: {e}")
    
    # IP Detective - Bot/VPN/Proxy detection
    if Config.IPDETECTIVE_API_KEY:
        try:
            clients["IP Detective"] = IPDetectiveAPI(Config.IPDETECTIVE_API_KEY)
            logger.info("✅ IP Detective initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize IP Detective: {e}")
    
    # GetIPIntel - Proxy/VPN/Bad IP detection (Free API)
    if Config.GETIPINTEL_CONTACT:
        try:
            clients["GetIPIntel"] = GetIPIntelAPI(Config.GETIPINTEL_CONTACT)
            logger.info("✅ GetIPIntel initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize GetIPIntel: {e}")
    
    # Ransomware.live - Public API, no key required
    try:
        clients["Ransomware.live"] = RansomwareLiveAPI()
        logger.info("✅ Ransomware.live initialized")
    except Exception as e:
        logger.error(f"❌ Failed to initialize Ransomware.live: {e}")
    # Hunter.io - Email and domain intelligence
    if Config.HUNTER_API_KEY:
        try:
            clients["Hunter.io"] = HunterAPI(Config.HUNTER_API_KEY)
            logger.info("✅ Hunter.io initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize Hunter.io: {e}")

    
    # Malware Bazaar - Malware threat intelligence
    if Config.MALWARE_BAZAAR_API_KEY:
        try:
            clients["Malware Bazaar"] = MalwareBazaarAPI(Config.MALWARE_BAZAAR_API_KEY)
            logger.info("✅ Malware Bazaar initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize Malware Bazaar: {e}")
    
    # ThreatFox - IOC threat intelligence
    if Config.THREATFOX_API_KEY:
        try:
            clients["ThreatFox"] = ThreatFoxAPI(Config.THREATFOX_API_KEY)
            logger.info("✅ ThreatFox initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize ThreatFox: {e}")
    
    


    # YARAify - YARA rule detection and malware analysis
    if Config.YARAIFY_API_KEY:
        try:
            clients["YARAify"] = YARAifyAPI(Config.YARAIFY_API_KEY)
            logger.info("✅ YARAify initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize YARAify: {e}")
    
    # Feodo Tracker - CSV/JSON based feed (no API key required)
    try:
        clients["Feodo Tracker"] = FeodoTrackerAPI()
        logger.info("✅ Feodo Tracker initialized")
    except Exception as e:
        logger.error(f"❌ Failed to initialize Feodo Tracker: {e}")

    # SSLBL - CSV based SSL/JA3 blacklist (no API key required)
    try:
        clients["SSLBL"] = SSLBLAPI()
        logger.info("✅ SSLBL initialized")
    except Exception as e:
        logger.error(f"❌ Failed to initialize SSLBL: {e}")
        
    logger.info(f"📊 Total active clients: {len(clients)}")
    return clients


if __name__ == "__main__":
    main()
