import json
import csv
from tabulate import tabulate

def format_as_json(results, filename):
    """
    Save certificate check results as JSON file.
    
    Args:
        results: List of result dictionaries
        filename: Output filename (default: results.json)
    
    Returns:
        str: Success message
    """
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    
    return f"Results saved to {filename}"


def format_as_csv(results, filename):
    """
    Save certificate check results as CSV file.
    
    Args:
        results: List of result dictionaries
        filename: Output filename (default: results.csv)
    
    Returns:
        str: Success message
    """
    
    fieldnames = ['hostname', 'port', 'status', 'days_remaining', 'expire_date', 'issuer_name', 'error_message']
    
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in results:
            # Handle None values - convert to empty string for CSV
            row = {
                'hostname': result.get('hostname', ''),
                'port': result.get('port', ''),
                'status': result.get('status', ''),
                'days_remaining': result.get('days_remaining', ''),
                'expire_date': result.get('expire_date', ''),
                'issuer_name': result.get('issuer_name', ''),
                'error_message': result.get('error_message', '')
            }
            writer.writerow(row)
    
    return f"Results saved to {filename}"


def format_as_table(results):
    """
    Format certificate check results as a table.
    
    Args:
        results: List of result dictionaries
    
    Returns:
        str: Formatted table string
    """
    table_data = []
    
    for result in results:
        # Decide: show port or not?
        if result['port'] != 443:
            domain_display = f"{result['hostname']}:{result['port']}"
        else:
            domain_display = result['hostname']
        
        # Handle errors
        if result['status'] == 'ERROR' or result['status'] == 'EXPIRED':
            row = [
                domain_display,
                result['status'],
                '-',
                '-',
                '-',
                result['error_message'] or 'Unknown error'
            ]
        else:
            row = [
                domain_display,
                result['status'],
                result['days_remaining'],
                result['expire_date'],
                result['issuer_name'],
                '-'

                '' 
            ]
        
        table_data.append(row)
    
    headers = ['Domain', 'Status', 'Days Left', 'Expires', 'Issuer', 'Error']
    
    return tabulate(table_data, headers=headers, tablefmt='grid', maxcolwidths=[None, None, None, None, None, 30])