#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KEV Analyzer - CISA KEV Catalog Analysis Tool

This script queries the CISA KEV catalog, enriches it with CVSS scores
via the NVD API, and allows filtering and exporting the results.

Formind Technical Challenge
Ported to portfolio project by: Antoine Buret
"""

# --- External Libraries ---
import requests

# --- Standard Libraries ---
import json
import os
import argparse
import logging
import sys
import csv
import time
from datetime import datetime, timedelta, date
from collections import Counter
from typing import List, Dict, Any, Optional

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# --- Constants ---
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
# NVD API Key (optional but RECOMMENDED to avoid rate limiting)
# The script will try to read the 'NVD_API_KEY' environment variable
NVD_API_KEY = os.environ.get('NVD_API_KEY')
NVD_REQUEST_DELAY = 6 if NVD_API_KEY else 10  # Seconds between NVD calls (6s with key, 10-12s without)

# Caching
CISA_CACHE_FILE = "cisa_kev_cache.json"
CVSS_CACHE_FILE = "cvss_scores_cache.json"
CACHE_DURATION_HOURS = 4


class KevAnalyzer:
    """
    Main class to manage fetching, analysis,
    and export of KEV data.
    """
    def __init__(self, force_refresh=False):
        self.force_refresh = force_refresh
        self.cisa_cache_duration = CACHE_DURATION_HOURS * 3600
        # CVSS cache is kept longer because scores change infrequently
        self.cvss_cache_duration = (24 * 7) * 3600  # 1 week
        
        self.kev_data = self._load_data(
            url=CISA_KEV_URL,
            cache_file=CISA_CACHE_FILE,
            cache_duration=self.cisa_cache_duration,
            data_key="vulnerabilities"
        )
        
        self.cvss_cache = self._load_data(
            url=None, # No URL, this is a pure cache
            cache_file=CVSS_CACHE_FILE,
            cache_duration=self.cvss_cache_duration,
            data_key=None
        ) or {} # Ensure it is a dict
    
    def _load_data(self, url: Optional[str], cache_file: str, cache_duration: int, data_key: Optional[str]) -> Optional[Any]:
        """
        Generic function for loading/caching.
        If 'url' is None, just loads the cache.
        """
        if os.path.exists(cache_file) and not self.force_refresh:
            try:
                file_mod_time = os.path.getmtime(cache_file)
                cache_age = datetime.now().timestamp() - file_mod_time
                if cache_age < cache_duration:
                    logging.info(f"Loading data from cache: {cache_file}")
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        return json.load(f)
            except Exception as e:
                logging.warning(f"Error reading cache {cache_file}: {e}. Re-downloading...")

        if not url: # If we just wanted to load the cache
            return None if data_key else {}

        logging.info(f"Querying API: {url.split('?')[0]}...")
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            # Extract the relevant part of the data
            data_to_cache = data.get(data_key) if data_key else data
            if data_to_cache is None:
                 logging.error(f"Key '{data_key}' not found in API response.")
                 return None

            logging.info(f"Data successfully retrieved. ({len(data_to_cache)} items)")

            # Update cache
            try:
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(data_to_cache, f, indent=2)
                    logging.info(f"Cache updated: {cache_file}")
            except IOError as e:
                logging.warning(f"Could not write to cache file: {e}")

            return data_to_cache

        except requests.exceptions.RequestException as err:
            logging.error(f"Critical error during data retrieval: {err}")
            return None

    def _get_cvss_score(self, cve_id: str) -> Dict[str, Any]:
        """
        CVSS enrichment for a single CVE.
        Uses its own cache.
        """
        # 1. Check cache first
        if cve_id in self.cvss_cache:
            cache_entry = self.cvss_cache[cve_id]
            cache_age = datetime.now().timestamp() - cache_entry.get('timestamp', 0)
            if cache_age < self.cvss_cache_duration and not self.force_refresh:
                logging.debug(f"CVSS score for {cve_id} found in cache.")
                return cache_entry['data']
        
        # 2. If not in cache or obsolete, query NVD API
        logging.info(f"CVSS enrichment for {cve_id} (NVD API Call...)")
        headers = {'apiKey': NVD_API_KEY} if NVD_API_KEY else {}
        try:
            # Respect the rate limit
            time.sleep(NVD_REQUEST_DELAY) 
            
            response = requests.get(f"{NVD_API_URL}{cve_id}", headers=headers, timeout=10)
            response.raise_for_status()
            nvd_data = response.json()
            
            score_data = {"cvss_score": None, "cvss_severity": None}
            
            if nvd_data.get('vulnerabilities'):
                cve_item = nvd_data['vulnerabilities'][0]['cve']
                # Look for V3.1 score, otherwise V3.0
                metrics = cve_item.get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    metric = metrics['cvssMetricV31'][0]['cvssData']
                    score_data["cvss_score"] = metric.get('baseScore')
                    score_data["cvss_severity"] = metric.get('baseSeverity')
                elif 'cvssMetricV30' in metrics:
                    metric = metrics['cvssMetricV30'][0]['cvssData']
                    score_data["cvss_score"] = metric.get('baseScore')
                    score_data["cvss_severity"] = metric.get('baseSeverity')

            # 3. Update the cache
            self.cvss_cache[cve_id] = {
                "timestamp": datetime.now().timestamp(),
                "data": score_data
            }
            return score_data

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logging.warning(f"NVD does not (yet) have info for {cve_id}.")
                return {"cvss_score": "N/A", "cvss_severity": "N/A"}
            logging.error(f"NVD HTTP error for {cve_id}: {e}")
            return {"cvss_score": "Error", "cvss_severity": "Error"}
        except Exception as e:
            logging.error(f"Unexpected NVD error for {cve_id}: {e}")
            return {"cvss_score": "Error", "cvss_severity": "Error"}

    def _save_cvss_cache(self):
        """Save the CVSS cache at the end of the script."""
        try:
            with open(CVSS_CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.cvss_cache, f, indent=2)
                logging.debug("CVSS cache saved.")
        except IOError as e:
            logging.warning(f"Could not save CVSS cache: {e}")

    def get_filtered_vulnerabilities(self, count: int, days: int, search_vendor: Optional[str], enrich: bool) -> List[Dict[str, Any]]:
        """
        Filters the KEV list and enriches it (if requested).
        """
        if not self.kev_data:
            return []

        date_limit = date.today() - timedelta(days=days)
        
        # 1. Sort and filter
        sorted_vulns = sorted(self.kev_data, key=lambda x: x['dateAdded'], reverse=True)
        
        filtered_list = []
        for vuln in sorted_vulns:
            vuln_date = date.fromisoformat(vuln['dateAdded'])
            
            # Filter by date
            if vuln_date < date_limit:
                continue # Too old
            
            # (NEW) Filter by vendor
            if search_vendor and search_vendor.lower() not in vuln.get('vendorProject', '').lower():
                continue # Doesn't match vendor
                
            filtered_list.append(vuln)
        
        # 2. Apply 'count' AFTER filtering
        final_list = filtered_list[:count]
        
        # 3. (IDEA 1) Enrichment
        if enrich:
            logging.info(f"CVSS enrichment for {len(final_list)} vulnerability(s). (This may take time...)")
            enriched_list = []
            for i, vuln in enumerate(final_list):
                logging.info(f"[{i+1}/{len(final_list)}] Processing {vuln['cveID']}...")
                cvss_data = self._get_cvss_score(vuln['cveID'])
                vuln.update(cvss_data) # Adds 'cvss_score' and 'cvss_severity' keys
                enriched_list.append(vuln)
            
            # Save the CVSS cache after the loop
            self._save_cvss_cache()
            return enriched_list
        else:
            return final_list
            
    def get_vendor_statistics(self, top_n: int) -> List[tuple]:
        """
        Calculate vendor statistics.
        """
        if not self.kev_data:
            return []
            
        try:
            vendor_list = [vuln.get('vendorProject', 'Unknown') for vuln in self.kev_data]
            vendor_counts = Counter(vendor_list)
            return vendor_counts.most_common(top_n)
        except Exception as e:
            logging.error(f"Error during vendor analysis: {e}")
            return []

    def format_output(self, vuln_data: List[Dict], stats_data: List[tuple], output_format: str, output_file: Optional[str]):
        """
        Manages data output (console, JSON, CSV).
        """
        # Prepare data container
        output_data = {
            "vulnerabilities": vuln_data,
            "vendor_statistics": [{"vendor": v, "count": c} for v, c in stats_data]
        }
        
        # Determine destination (stdout or file)
        destination = open(output_file, 'w', encoding='utf-8') if output_file else sys.stdout

        try:
            if output_format == 'json':
                json.dump(output_data, destination, indent=2)
            
            elif output_format == 'csv':
                # For CSV, only output vulnerabilities
                if not vuln_data:
                    logging.info("No vulnerabilities to export to CSV.")
                    return
                
                writer = csv.DictWriter(destination, fieldnames=vuln_data[0].keys())
                writer.writeheader()
                writer.writerows(vuln_data)
            
            else: # 'console' (default)
                self._format_console(destination, output_data)
        
        finally:
            if output_file:
                destination.close()
                logging.info(f"Results saved to: {output_file}")

    def _format_console(self, dest, data):
        """Helper for clean console display."""
        
        # 1. Display vulnerabilities
        vuln_list = data.get('vulnerabilities', [])
        if vuln_list:
            dest.write(f"\n--- 1. Vulnerability Analysis (Total: {len(vuln_list)}) ---\n")
            for vuln in vuln_list:
                dest.write(f"\n  CVE ID:         {vuln.get('cveID')}\n")
                # Display CVSS score if enriched
                if 'cvss_score' in vuln:
                    dest.write(f"  CVSS Score:     {vuln.get('cvss_score')} ({vuln.get('cvss_severity')})\n")
                dest.write(f"  Vendor/Product: {vuln.get('vendorProject')} / {vuln.get('product')}\n")
                dest.write(f"  Date Added:     {vuln.get('dateAdded')}\n")
        else:
             dest.write(f"\n--- 1. Vulnerability Analysis ---\n")
             dest.write("[!] No vulnerabilities match your filter criteria.\n")

        # 2. Display statistics
        stats_list = data.get('vendor_statistics', [])
        dest.write(f"\n--- 2. Vendor Statistics (Top {len(stats_list)}) ---\n")
        if stats_list:
            for item in stats_list:
                dest.write(f"  {item['vendor']:<25} : {item['count']} vulnerability(s)\n")
        else:
            dest.write("[!] No statistics to display.\n")


def main():
    """
    Main function to orchestrate execution
    and handle command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="CISA KEV Catalog analysis tool, enriched with CVSS scores.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # --- Filter Arguments ---
    parser.add_argument(
        "-n", "--number",
        type=int,
        default=5,
        help="Max number of vulnerabilities to display.\nDefault: 5"
    )
    parser.add_argument(
        "-d", "--days",
        type=int,
        default=30,
        help="Filter vulnerabilities added in the last X days.\nDefault: 30"
    )
    parser.add_argument(
        "-s", "--search-vendor",
        type=str,
        help="Filter by vendor name (e.g., 'Microsoft', 'Apple').\nCase-insensitive."
    )
    
    # --- Enrichment Arguments ---
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Enable CVSS enrichment (via NVD API).\nCAN BE VERY SLOW WITHOUT AN API KEY."
    )
    
    # --- Statistics Arguments ---
    parser.add_argument(
        "-vn", "--vendor-number",
        type=int,
        default=10,
        help="Number of vendors to show in stats top list.\nDefault: 10"
    )

    # --- Output Arguments (IDEA 2) ---
    parser.add_argument(
        "-o", "--output-file",
        type=str,
        help="Save the output to a file (e.g., report.json)."
    )
    parser.add_argument(
        "-f", "--output-format",
        choices=['console', 'json', 'csv'],
        default='console',
        help="Output format.\nDefault: console"
    )

    # --- Cache Arguments ---
    parser.add_argument(
        "--force-refresh",
        action="store_true",
        help="Force data refresh, ignoring caches."
    )
    
    args = parser.parse_args()
    
    if not NVD_API_KEY and args.enrich:
        logging.warning("No 'NVD_API_KEY' environment variable found.")
        logging.warning(f"NVD API calls will be VERY slow (1 call / {NVD_REQUEST_DELAY}s).")
        logging.warning("Create a free key on the NVD website to speed up the process.")

    try:
        analyzer = KevAnalyzer(force_refresh=args.force_refresh)
        
        # 1. Get filtered and (optionally) enriched vulnerabilities
        vuln_data = analyzer.get_filtered_vulnerabilities(
            count=args.number,
            days=args.days,
            search_vendor=args.search_vendor,
            enrich=args.enrich
        )
        
        # 2. Get statistics
        stats_data = analyzer.get_vendor_statistics(top_n=args.vendor_number)
        
        # 3. Format and show output
        analyzer.format_output(
            vuln_data=vuln_data,
            stats_data=stats_data,
            output_format=args.output_format,
            output_file=args.output_file
        )

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
