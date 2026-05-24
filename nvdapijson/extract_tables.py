#!/usr/bin/env python3
"""
Script to read NVD JSON files and extract data into normalized tables with schema name "nvd"
"""

import os
import json
import pandas as pd
from datetime import datetime
import sys

def extract_cve_data(json_file_path):
    """Extract CVE data from a single JSON file"""
    try:
        with open(json_file_path, 'r') as f:
            data = json.load(f)

        # Extract CVE items - NVD JSON structure is an array of CVE objects
        cves = []
        for item in data:  # Direct iteration over the array
            cve_id = item.get('cve', {}).get('id', '')
            if not cve_id:
                continue

            # Extract basic CVE information
            cve_info = {
                'cve_id': cve_id,
                'assigner': item.get('cve', {}).get('sourceIdentifier', ''),
                'description': '',
                'published_date': item.get('cve', {}).get('published', ''),
                'last_modified_date': item.get('cve', {}).get('lastModified', ''),
                'cvss_score': 0.0,
                'cvss_vector': '',
                'severity': '',
                'vendor': '',
                'product': '',
                'version': ''
            }

            # Extract description
            descriptions = item.get('cve', {}).get('descriptions', [])
            if descriptions:
                # Get the English description
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        cve_info['description'] = desc.get('value', '')
                        break
                # If no English description, take the first one
                if not cve_info['description'] and descriptions:
                    cve_info['description'] = descriptions[0].get('value', '')

            # Extract CVSS scores and vectors
            metrics = item.get('cve', {}).get('metrics', {})
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
                cve_info['cvss_score'] = cvss_data.get('baseScore', 0.0)
                cve_info['cvss_vector'] = cvss_data.get('vectorString', '')
                cve_info['severity'] = cvss_data.get('baseSeverity', '')
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                cve_info['cvss_score'] = cvss_data.get('baseScore', 0.0)
                cve_info['cvss_vector'] = cvss_data.get('vectorString', '')
                cve_info['severity'] = cvss_data.get('baseSeverity', '')  # This might not exist for V2

            # Extract vendor and product information
            # NVD format has affects section
            affects = item.get('cve', {}).get('affects', {})
            if 'vendor' in affects and affects['vendor']:
                vendor_data = affects['vendor'].get('vendor_data', [])
                if vendor_data:
                    cve_info['vendor'] = vendor_data[0].get('vendor_name', '')

            # Extract product information
            if 'vendor' in affects and affects['vendor']:
                vendor_data = affects['vendor'].get('vendor_data', [])
                if vendor_data:
                    if 'product' in vendor_data[0]:
                        product_data = vendor_data[0]['product'].get('product_data', [])
                        if product_data:
                            cve_info['product'] = product_data[0].get('product_name', '')

            cves.append(cve_info)

        return cves

    except Exception as e:
        print(f"Error processing {json_file_path}: {str(e)}")
        return []

def extract_references(json_file_path):
    """Extract CVE references from a single JSON file"""
    try:
        with open(json_file_path, 'r') as f:
            data = json.load(f)

        references = []
        for item in data:  # Direct iteration over the array
            cve_id = item.get('cve', {}).get('id', '')
            if not cve_id:
                continue

            # Extract references - NVD JSON structure has references directly in the cve object
            references_list = item.get('cve', {}).get('references', [])
            for ref in references_list:
                reference = {
                    'cve_id': cve_id,
                    'source': ref.get('source', ''),
                    'url': ref.get('url', ''),
                    'description': ', '.join(ref.get('tags', []))  # Join tags into a string
                }
                references.append(reference)

        return references

    except Exception as e:
        print(f"Error processing references in {json_file_path}: {str(e)}")
        return []

def process_all_json_files(data_dir):
    """Process all JSON files in the data directory"""
    cve_data = []
    reference_data = []

    # Find all JSON files in the directory
    for root, dirs, files in os.walk(data_dir):
        for filename in files:
            if filename.endswith('.json'):
                file_path = os.path.join(root, filename)
                print(f"Processing {filename}...")

                # Extract CVE data
                cve_items = extract_cve_data(file_path)
                cve_data.extend(cve_items)

                # Extract references
                refs = extract_references(file_path)
                reference_data.extend(refs)

    return cve_data, reference_data

def save_to_csv(data, filename, schema_name="nvd"):
    """Save data to CSV with schema prefix"""
    if not data:
        print(f"No data to save to {filename}")
        return

    # Create DataFrame
    df = pd.DataFrame(data)

    # Add schema name prefix to column names if needed
    if schema_name:
        df.columns = [f"{schema_name}.{col}" for col in df.columns]

    # Save to CSV
    df.to_csv(filename, index=False)
    print(f"Saved {len(data)} records to {filename}")

def main():
    """Main function"""
    # Set data directory - using the actual path where data is stored
    data_dir = "/Users/ben/repos/data/nvd/json"

    # Check if data directory exists
    if not os.path.exists(data_dir):
        print(f"Data directory {data_dir} does not exist")
        sys.exit(1)

    print(f"Processing JSON files in {data_dir}")

    # Process all JSON files
    cve_data, reference_data = process_all_json_files(data_dir)

    # Save data to CSV files
    save_to_csv(cve_data, "cves_nvd.csv", "nvd")
    save_to_csv(reference_data, "cve_references_nvd.csv", "nvd")

    print(f"Processing complete. Extracted {len(cve_data)} CVE records and {len(reference_data)} reference records.")

if __name__ == "__main__":
    main()