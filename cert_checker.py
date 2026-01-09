# cert_checker.py
# version 2.0 - Database Integration

from datetime import datetime, UTC
import socket, ssl, sys, argparse, yaml
import status, formatter
from database import CertDatabase


def clean_hostname(hostname):
    """Clean common hostname input mistakes."""
    
    hostname = hostname.lower()
    hostname = hostname.replace('https://', '').replace('http://', '')
    hostname = hostname.split('/')[0]
    hostname = hostname.split(':')[0]
    
    return hostname


def get_cert(hostname, port, timeout=15):
    """Retrieves SSL certificate and calculates time until expiry."""
    
    port = int(port)
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
  
    return parse_certificate_info(cert)


def parse_certificate_info(cert):
    """Calculates time remaining until certificate expires and extracts data."""
    not_after = cert["notAfter"]

    # Certificate dates are in GMT format: "Dec 31 23:59:59 2024 GMT"
    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    now = datetime.now(UTC)
    delta = expiry.replace(tzinfo=UTC) - now
    
    # Extract issuer information
    issuer = {key: value for ((key, value),) in cert['issuer']}
    issuer_org = issuer.get('organizationName', None)
    issuer_cn = issuer.get('commonName', None)

    # Use org name if available, otherwise fall back to CN
    issuer_name = issuer_org if issuer_org else issuer_cn
    
    return {
        'days_remaining': delta.days,
        'expiry_date': expiry.strftime('%Y-%m-%d'),
        'issuer_name': issuer_name
    }


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='SSL Certificate Expiration Checker with Database Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  %(prog)s --config config.yaml\n'
               '  %(prog)s --config config.yaml --db-path /custom/path/certs.db\n'
    )
    
    parser.add_argument('--config', required=True, help='Path to configuration YAML file')
    parser.add_argument('--timeout', type=int, default=15, help='Socket timeout in seconds (default: 15)')
    parser.add_argument('--db-path', default='certs.db', help='Path to database file (default: certs.db)')
    parser.add_argument('--version', action='version', version='cert_checker 2.0')
    
    return parser.parse_args()


def loadconfig(configfile):
    """Load configuration from a YAML file."""
    try:
        with open(configfile, 'r') as stream:
            config = yaml.safe_load(stream)
    except FileNotFoundError:
        print(f"Error: Configuration file {configfile} not found.")
        sys.exit(1)
    except yaml.YAMLError as exc:
        print(f"Error in configuration file: {exc}")
        sys.exit(1)
    return config


def should_alert(old_status, new_status):
    """
    Determine if status change warrants an alert.
    Only alert if status got WORSE (severity increased).
    """
    status_severity = {
        'OK': 0,
        'WARNING': 1,
        'CRITICAL': 2,
        'EXPIRED': 3,
        'ERROR': 3
    }
    
    old_severity = status_severity.get(old_status, 0)
    new_severity = status_severity.get(new_status, 0)
    
    return new_severity > old_severity


def check_and_store_certificate(hostname, port, timeout, db):
    """
    Check a single certificate and store/update in database.
    
    Args:
        hostname: Domain to check
        port: Port number
        timeout: Socket timeout
        db: CertDatabase instance
    
    Returns:
        dict: Result dictionary with certificate data
    """
    clean_host = clean_hostname(hostname)
    
    try:
        # Check the certificate
        cert_data = get_cert(clean_host, port, timeout)
        days_remaining = cert_data['days_remaining']
        current_status = status.determine_status(days_remaining)
        
        # Read existing certificate
        existing = db.query_one(
            'SELECT * FROM certificates WHERE hostname = ? AND port = ?',
            (clean_host, port)
        )
        
        # Write/update certificate atomically
        db.process_certificate_check(
            clean_host,
            port,
            {
                'days_remaining': days_remaining,
                'status': current_status,
                'issuer_name': cert_data['issuer_name'],
                'expire_date': cert_data['expiry_date'],
                'error_message': None
            },
            existing_cert=existing
        )
        
        # Return display result
        return {
            "hostname": clean_host,
            "port": port,
            "days_remaining": days_remaining,
            "status": current_status,
            "issuer_name": cert_data['issuer_name'],
            "expire_date": cert_data['expiry_date'],
            "error_message": None
        }
    
    except (ssl.SSLError, socket.gaierror, ConnectionRefusedError, TimeoutError, OSError) as e:
        # Error checking certificate
        error_msg = str(e)
        error_status = 'EXPIRED' if 'expired' in error_msg.lower() else 'ERROR'
        
        # Read existing certificate
        existing = db.query_one(
            'SELECT * FROM certificates WHERE hostname = ? AND port = ?',
            (clean_host, port)
        )
        
        # Write error state atomically
        db.process_certificate_check(
            clean_host,
            port,
            {
                'days_remaining': None,
                'status': error_status,
                'issuer_name': None,
                'expire_date': None,
                'error_message': error_msg
            },
            existing_cert=existing
        )
        
        # Return error result
        return {
            "hostname": clean_host,
            "port": port,
            "days_remaining": None,
            "status": error_status,
            "issuer_name": None,
            "expire_date": None,
            "error_message": error_msg
        }


def process_domains(domains_list, default_port, timeout, db):
    """
    Process a list of domains and store results in database.
    
    Args:
        domains_list: List of domain configs (dicts or strings)
        default_port: Default port to use
        timeout: Socket timeout
        db: CertDatabase instance
    
    Returns:
        list: List of result dictionaries
    """
    results = []
    
    for domain_info in domains_list:
        # Handle both dict and string domain configs
        if isinstance(domain_info, dict):
            hostname = domain_info['hostname']
            port = domain_info.get('port', default_port)
        else:
            hostname = domain_info
            port = default_port
        
        result = check_and_store_certificate(hostname, port, timeout, db)
        results.append(result)
    
    return results


if __name__ == "__main__":
    
    args = parse_arguments()
    
    # Initialize database
    db = CertDatabase(args.db_path)
    
    # Load configuration
    config = loadconfig(args.config)
    default_port = config.get('default_port', 443)
    
    # Process all domains
    results = process_domains(
        config['domains'],
        default_port,
        args.timeout,
        db
    )
    
    # Display summary
    print(f"Checked {len(results)} certificates")
    print(f"Database: {args.db_path}")
    
    # Show table output
    print("\nCurrent Status:")
    print(formatter.format_as_table(results))