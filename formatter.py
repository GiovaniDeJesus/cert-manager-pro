from tabulate import tabulate

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