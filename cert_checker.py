from datetime import datetime, UTC
import socket, ssl, sys, argparse


def clean_hostname(hostname):
    """Clean common hostname input mistakes."""
    
    hostname = hostname.lower()
    hostname = hostname.replace('https://', '').replace('http://', '')
    hostname = hostname.split('/')[0]
    hostname = hostname.split(':')[0]
    
    return hostname

def get_cert_data(hostname, port):
    """Retrieves SSL certificate and calculates time until expiry."""
    try:
        port = int(port)
        context = ssl.create_default_context()   
        with socket.create_connection((hostname, port), timeout=10) as sock:
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
    
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    
    # Determine port to use
    port = args.port_flag if args.port_flag else args.port
    
    # Validate port
    if not (1 <= port <= 65535):
        print("Error: Port must be between 1 and 65535")
        sys.exit(1)
    
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
        result = get_cert_data(clean_host, str(port))
        
        if result is not None:
            print(f"{domain}: {result}")

