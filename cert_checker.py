from datetime import datetime, UTC
import socket, ssl, sys


def clean_hostname(hostname):
    """Clean common hostname input mistakes."""

    hostname = hostname.lower().replace('https://', '').replace('http://', '')
    hostname = hostname.split('/')[0]
    hostname = hostname.lower()
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



if __name__ == "__main__":
    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
            if 1 <= port <= 65535:
                clean_host = clean_hostname(sys.argv[1])
                result = get_cert_data(clean_host, sys.argv[2])
                if result is not None:
                    print(result)
            else:
                print("Error: Port must be between 1 and 65535")
        except ValueError:
            print(f"Error: '{sys.argv[2]}' is not a valid port number")
    else:
        print(f"Usage: {sys.argv[0]} domain_name port_number")
        print(f"Example: {sys.argv[0]} example.com 443")
        