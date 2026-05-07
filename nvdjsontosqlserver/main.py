import json
import os
import pyodbc
from pathlib import Path
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database connection configuration
SERVER = os.environ.get('SQL_SERVER', 'localhost')
DATABASE = os.environ.get('SQL_DATABASE', 'cybersecurity')
USERNAME = os.environ.get('SQL_USERNAME', 'sa')
PASSWORD = os.environ.get('SQL_PASSWORD', 'YourStrong@Passw0rd')
DRIVER = os.environ.get('SQL_DRIVER', '{ODBC Driver 17 for SQL Server}')

# Connection string
CONNECTION_STRING = f"DRIVER={DRIVER};SERVER={SERVER};DATABASE={DATABASE};UID={USERNAME};PWD={PASSWORD}"

# Directory containing JSON files
JSON_DIR = os.environ.get('JSON_DIR', '/data/nvd')

def get_connection():
    """Create and return a database connection."""
    try:
        conn = pyodbc.connect(CONNECTION_STRING)
        logger.info("Successfully connected to SQL Server")
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to SQL Server: {e}")
        raise

def create_tables():
    """Create necessary tables in the database."""
    conn = get_connection()
    cursor = conn.cursor()

    # Create CVE table
    create_cve_table = """
    IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='cves' AND xtype='U')
    CREATE TABLE cves (
        id VARCHAR(255) PRIMARY KEY,
        published DATETIME2,
        last_modified DATETIME2,
        vuln_status VARCHAR(50),
        description NVARCHAR(MAX),
        cvss_score FLOAT,
        cvss_vector VARCHAR(100),
        exploitability_score FLOAT,
        impact_score FLOAT,
        cwe_id VARCHAR(50),
        vendor VARCHAR(255),
        product VARCHAR(255),
        version VARCHAR(100),
        created_at DATETIME2 DEFAULT GETDATE()
    )
    """

    # Create CVE references table
    create_refs_table = """
    IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='cve_references' AND xtype='U')
    CREATE TABLE cve_references (
        id INT IDENTITY(1,1) PRIMARY KEY,
        cve_id VARCHAR(255),
        reference_url NVARCHAR(MAX),
        source VARCHAR(100),
        created_at DATETIME2 DEFAULT GETDATE(),
        FOREIGN KEY (cve_id) REFERENCES cves(id)
    )
    """

    try:
        cursor.execute(create_cve_table)
        cursor.execute(create_refs_table)
        conn.commit()
        logger.info("Tables created successfully")
    except Exception as e:
        logger.error(f"Error creating tables: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

def parse_cve_data(cve_data):
    """Parse CVE data from JSON structure."""
    cve_id = cve_data.get('id', '')
    published = cve_data.get('published', '')
    last_modified = cve_data.get('lastModified', '')
    vuln_status = cve_data.get('vulnStatus', '')

    # Parse description
    description = ''
    descriptions = cve_data.get('descriptions', [])
    if descriptions:
        description = descriptions[0].get('value', '') if descriptions[0] else ''

    # Parse CVSS scores
    cvss_score = None
    cvss_vector = None
    exploitability_score = None
    impact_score = None

    metrics = cve_data.get('metrics', {})
    if metrics:
        # Try CVSS v3.x first
        cvss_v3 = metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30')
        if cvss_v3:
            cvss_data = cvss_v3[0].get('cvssData', {})
            cvss_score = cvss_data.get('baseScore')
            cvss_vector = cvss_data.get('vectorString')
            exploitability_score = cvss_data.get('exploitabilityScore')
            impact_score = cvss_data.get('impactScore')

    # Parse CWE
    cwe_id = None
    cwe_data = cve_data.get('weaknesses', [])
    if cwe_data:
        cwe_id = cwe_data[0].get('description', [{}])[0].get('value')

    # Parse vendor and product information
    vendor = ''
    product = ''
    version = ''

    config = cve_data.get('configurations', [])
    if config:
        for node in config:
            for cpe_match in node.get('nodes', []):
                if cpe_match.get('cpe23Uri'):
                    # Extract vendor, product, version from CPE URI
                    cpe_uri = cpe_match['cpe23Uri']
                    parts = cpe_uri.split(':')
                    if len(parts) >= 6:
                        vendor = parts[3]
                        product = parts[4]
                        version = parts[5]

    return {
        'id': cve_id,
        'published': published,
        'last_modified': last_modified,
        'vuln_status': vuln_status,
        'description': description,
        'cvss_score': cvss_score,
        'cvss_vector': cvss_vector,
        'exploitability_score': exploitability_score,
        'impact_score': impact_score,
        'cwe_id': cwe_id,
        'vendor': vendor,
        'product': product,
        'version': version
    }

def insert_cve_data(cve_data):
    """Insert CVE data into the database."""
    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Parse the CVE data
        parsed_data = parse_cve_data(cve_data)

        # Insert CVE data
        insert_sql = """
        INSERT INTO cves (id, published, last_modified, vuln_status, description,
                         cvss_score, cvss_vector, exploitability_score, impact_score,
                         cwe_id, vendor, product, version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        cursor.execute(insert_sql, (
            parsed_data['id'],
            parsed_data['published'],
            parsed_data['last_modified'],
            parsed_data['vuln_status'],
            parsed_data['description'],
            parsed_data['cvss_score'],
            parsed_data['cvss_vector'],
            parsed_data['exploitability_score'],
            parsed_data['impact_score'],
            parsed_data['cwe_id'],
            parsed_data['vendor'],
            parsed_data['product'],
            parsed_data['version']
        ))

        # Insert references
        references = cve_data.get('references', [])
        for ref in references:
            insert_ref_sql = """
            INSERT INTO cve_references (cve_id, reference_url, source)
            VALUES (?, ?, ?)
            """
            cursor.execute(insert_ref_sql, (
                parsed_data['id'],
                ref.get('url', ''),
                ref.get('source', '')
            ))

        conn.commit()
        logger.info(f"Successfully inserted CVE: {parsed_data['id']}")

    except Exception as e:
        logger.error(f"Error inserting CVE {parsed_data['id']}: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

def process_json_files():
    """Process all JSON files in the specified directory."""
    logger.info(f"Starting to process JSON files in {JSON_DIR}")

    # Create tables if they don't exist
    create_tables()

    json_path = Path(JSON_DIR)
    if not json_path.exists():
        logger.error(f"JSON directory {JSON_DIR} does not exist")
        return

    processed_count = 0
    error_count = 0

    # Process all JSON files in the directory
    for json_file in json_path.glob("*.json"):
        try:
            logger.info(f"Processing {json_file.name}")

            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Process the CVE data
            vulnerabilities = data.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                try:
                    insert_cve_data(vuln)
                    processed_count += 1
                except Exception as e:
                    logger.error(f"Error processing CVE {vuln.get('id', 'unknown')}: {e}")
                    error_count += 1

        except Exception as e:
            logger.error(f"Error processing file {json_file.name}: {e}")
            error_count += 1

    logger.info(f"Processing complete. Processed: {processed_count}, Errors: {error_count}")

def main():
    """Main function to run the ingestion process."""
    try:
        process_json_files()
        logger.info("NVD JSON to SQL Server ingestion completed successfully")
    except Exception as e:
        logger.error(f"Error in main process: {e}")
        raise

if __name__ == "__main__":
    main()