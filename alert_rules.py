
"""
Business rules for certificate alerting.
Shared between database and main script.
"""

def should_alert(old_status, new_status):
    """
    Determine if status change warrants an alert.
    Only alert if status got WORSE (severity increased).
    
    Args:
        old_status: Previous status ('OK', 'WARNING', 'CRITICAL', etc.)
        new_status: Current status
    
    Returns:
        bool: True if should alert, False otherwise
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