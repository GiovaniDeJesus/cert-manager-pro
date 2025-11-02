#version 1.0

from datetime import datetime, UTC
import socket, ssl, sys, argparse, yaml


def clean_hostname(hostname):
    """Clean common hostname input mistakes."""
    
    hostname = hostname.lower()
    hostname = hostname.replace('https://', '').replace('http://', '')
    hostname = hostname.split('/')[0]
    hostname = hostname.split(':')[0]
    
    return hostname

def get_cert_data(hostname, port, timeout=15):
    """Retrieves SSL certificate and calculates time until expiry."""
    try:
        port = int(port)
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        return cal_date(cert)
    
    except ssl.SSLError as e:
        print(f"Error: SSL error for '{hostname}': {e}")
        return None 
    except socket.gaierror:
        print(f"Error: Could not resolve hostname '{hostname}'")
        return None
    except ConnectionRefusedError:
        print(f"Error: Connection to '{hostname}:{port}' was refused")
        return None    
    except TimeoutError:
        print("Socket operation timed out.")
        return None
    except Exception as e:
        print(f"Error: Unexpected error: {e}")
        return None
     
    

def cal_date(cert):
    """Calculates time remaining until certificate expires."""
    not_after = cert["notAfter"]
    
    # Certificate dates are in GMT format: "Dec 31 23:59:59 2024 GMT"
    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    now = datetime.now(UTC)
    delta = expiry.replace(tzinfo=UTC) - now
    return delta



def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='SSL Certificate Expiration Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  %(prog)s google.com 443\n'
               '  %(prog)s --domains google.com,github.com --port 443\n'
    )
    
    parser.add_argument('hostname', nargs='?', help='Hostname to check')
    parser.add_argument('port', nargs='?', type=int, default=443, help='Port number (default: 443)')
    parser.add_argument('--domains', help='Comma-separated list of domains to check')
    parser.add_argument('--port', dest='port_flag', type=int, help='Port for all domains')
    parser.add_argument('--config', help='Path to configuration YAML file')
    parser.add_argument('--timeout', type=int, help='Socket timeout in seconds (default: 15)')
    parser.add_argument('--version', action='version', version='cert_checker 1.0')
    
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

def result_formatter(config):
     
        config = loadconfig(args.config)
        domains_results = {}
        list_results = []
        for domain in config['domains']:
            hostname = domain['hostname']
            port = domain.get('port', config.get('default_port'))
            timeout = args.timeout if args.timeout else 15
            clean_host = clean_hostname(hostname)
            result = get_cert_data(clean_host, int(port), timeout)
            if result is not None:
                domains_results = {
                    "hostname": hostname,
                    "port": port,
                    "days_until_expiry": result.days,
                    "seconds_until_expiry": result.total_seconds()
                }
                list_results.append(domains_results)
                print(list_results)
                
    

if __name__ == "__main__":
    
    args = parse_arguments()
    
    # If config file is provided, use it
    if args.config:
        result_formatter(args.config)
        sys.exit(0)    
    # Determine port to use
    port = args.port_flag if args.port_flag else args.port
    
    # Validate port
    if not (1 <= port <= 65535):
        print("Error: Port must be between 1 and 65535")
        sys.exit(1)
        
    # Set socket timeout
    timeout = args.timeout 
    # Determine which domains to check
    if args.domains:
        # Multiple domains mode
        domains = [d.strip() for d in args.domains.split(',')]
    elif args.hostname:
        # Single domain mode (backward compatible)
        domains = [args.hostname]
    else:
        print("Error: No hostname or domains specified")
        print(f"Usage: {sys.argv[0]} <hostname> <port> OR --domains <domain1,domain2> --port <port>")
        sys.exit(1)
    
    for domain in domains:
        clean_host = clean_hostname(domain)
        result = get_cert_data(clean_host, int(port), timeout)
        
        if result is not None: #If there is not errors it will print the result
            print(f"{domain}: {result}")

