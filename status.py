

def determine_status(days_remaining):
    """
    Determine certificate status based on days until expiry.
    
    Args:
        days_remaining: int or None if error occurred
    
    Returns:
        str: 'OK', 'WARNING', 'CRITICAL'
    """

    if days_remaining < 7:
        return 'CRITICAL'
    
    if days_remaining < 30:
        return 'WARNING'
    
    return 'OK'