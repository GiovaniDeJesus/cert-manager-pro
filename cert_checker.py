#version 1.0

from datetime import datetime, UTC
import socket, ssl, sys, argparse, yaml, status, formatter


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
        description='SSL Certificate Expiration Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  %(prog)s google.com 443\n'
               '  %(prog)s --domains google.com,github.com --port 443\n'
               '  %(prog)s --config config.yaml\n'
               '  %(prog)s example.com --timeout 10'
               '  %(prog)s example.com --format json --output results.json'
               
    )
    
    parser.add_argument('--domains', help='Comma-separated list of domains to check')
    parser.add_argument('--port', dest='port_flag', type=int, help='Port for all domains')
    parser.add_argument('--config', help='Path to configuration YAML file')
    parser.add_argument('--timeout', type=int, help='Socket timeout in seconds (default: 15)')
    parser.add_argument('--version', action='version', version='cert_checker 1.0')
    parser.add_argument('--format', choices=['table', 'json', 'csv'], default='table', help='Output format')
    parser.add_argument('--output', help='Output filename (for json/csv formats)')
    return parser.parse_args()

def loadconfig(configfile):
    '''Load configuration from a YAML file'''
    try:
        with open(configfile, 'r') as stream:
            config = yaml.safe_load(stream)
    except FileNotFoundError:
        print(f"Error: Configuration file {configfile} not found.")
        sys.exit(1)
    except (yaml.YAMLError) as exc:
        print ("Error in configuration file:", exc)
        sys.exit(1)
    return config


def process_domains(domains_list, port, timeout):
    """Process a list of domains and return formatted results."""
    
    results = []    
    for domain_info in domains_list:
        # domain_info could be just a hostname string, or a dict with hostname/port
        if isinstance(domain_info, dict):
            hostname = domain_info['hostname']
            domain_port = domain_info.get('port', port)
        else:
            hostname = domain_info
            domain_port = port
        
        clean_host = clean_hostname(hostname)
        
        try:
            cert_data = get_cert(clean_host, domain_port, timeout)
            results.append({
                "hostname": clean_host,
                "port": domain_port,
                "days_remaining": cert_data["days_remaining"],
                "status": status.determine_status(cert_data["days_remaining"]),
                "issuer_name": cert_data["issuer_name"],
                "expire_date": cert_data["expiry_date"],
                "error_message": None
            })
        except (ssl.SSLError, socket.gaierror, ConnectionRefusedError, TimeoutError) as e:
            error_msg = str(e).lower()
            results.append({
                "hostname": clean_host,
                "port": domain_port,
                "days_remaining": None,
                "status": 'EXPIRED' if 'expired' in error_msg else 'ERROR',
                "issuer_name": None,
                "expire_date": None,
                "error_message": str(e)
            })
    
    return results
            

if __name__ == "__main__":
    
    args = parse_arguments()
    
    # Set socket timeout
    timeout = args.timeout if args.timeout else 15
    
    # Determine port to use
    port = args.port_flag or 443
    
    # Validate port
    if not (1 <= port <= 65535):
        print("Error: Port must be between 1 and 65535")
        sys.exit(1)
        

    # Configuration file mode
    if args.config:
        print("Loading domains from config file...")
        config = loadconfig(args.config)
        default_port = config.get('default_port', 443)
        results = process_domains(config['domains'], default_port, timeout)
        
        if args.format == 'json':
            filename = args.output or 'results.json'
            output = formatter.format_as_json(results, filename)
        elif args.format == 'csv':
            filename = args.output or 'results.csv'
            output = formatter.format_as_csv(results, filename)
        else:
            output = formatter.format_as_table(results)
            print(output)
        sys.exit(0)   
    
    # Multiple domains mode
    elif args.domains:
        domains = [d.strip() for d in args.domains.split(',')]
        results = process_domains(domains, port, timeout)
        if args.format == 'json':
            filename = args.output or 'results.json'
            output = formatter.format_as_json(results, filename)
            print(output)
        elif args.format == 'csv':
            filename = args.output or 'results.csv'
            output = formatter.format_as_csv(results, filename)
            print(output)
        else:
            output = formatter.format_as_table(results)
            print(output)
        
        sys.exit(0)
        
    # No valid input provided
    else:
        print("Error: No hostname or domains specified")
        print("Not config file provided")
        print(f"Usage: {sys.argv[0]} --domains <domain1,domain2> [--port <port>] OR --config <configfile> [--format table|json|csv] [--output <filename>]")
        sys.exit(1)
        

            
        