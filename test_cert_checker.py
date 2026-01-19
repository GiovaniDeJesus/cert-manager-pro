import pytest
import sqlite3
from datetime import datetime
from cert_checker import (
    clean_hostname,
    parse_certificate_info,
    process_domains,
    check_and_store_certificate,

)
from status import determine_status
from database import CertDatabase
import alert_rules
from alerts import EmailAlerter
import time # Sleep to avoid SMTP rate limits


# ===== Basic Function Tests =====

@pytest.mark.parametrize("hostname,expected", [
    ("google.com", "google.com"),
    ("HTTPS://GITHUB.COM/", "github.com"),
    ("http://example.com", "example.com"),
    ("example.com:443", "example.com"),
    ("SITE.COM/path/to/page", "site.com"),
])
def test_clean_hostname(hostname, expected):
    """Test hostname cleaning with various inputs"""
    assert clean_hostname(hostname) == expected


@pytest.mark.parametrize("days,expected_status", [
    (100, "OK"),
    (31, "OK"),
    (30, "OK"),
    (29, "WARNING"),
    (15, "WARNING"),
    (7, "WARNING"),
    (6, "CRITICAL"),
    (1, "CRITICAL"),
    (0, "CRITICAL"),
])
def test_determine_status(days, expected_status):
    """Test status determination for different day ranges"""
    assert determine_status(days) == expected_status


# ===== Certificate Parsing Tests =====

@pytest.fixture
def mock_certificate():
    """Provide sample SSL certificate data"""
    return {
        'notAfter': 'Feb 23 23:59:59 2025 GMT',
        'issuer': ((('organizationName', "Let's Encrypt"),),)
    }


def test_parse_certificate_info(mock_certificate):
    """Test parsing certificate data"""
    result = parse_certificate_info(mock_certificate)
    
    assert 'days_remaining' in result
    assert 'expiry_date' in result
    assert 'issuer_name' in result
    assert result['issuer_name'] == "Let's Encrypt"
    assert result['expiry_date'] == '2025-02-23'


# ===== Database Fixture =====

@pytest.fixture
def test_database():
    """Create in-memory database for testing"""
    # Use in-memory database for speed
    db = CertDatabase(':memory:')
    
    yield db
    


# ===== Alert Logic Tests =====

@pytest.mark.parametrize("old_status,new_status,should_alert_flag", [
    ('OK', 'OK', False),           # No change
    ('OK', 'WARNING', True),       # Got worse
    ('WARNING', 'CRITICAL', True), # Got worse
    ('WARNING', 'OK', False),      # Got better
    ('CRITICAL', 'WARNING', False),# Got better
    ('ERROR', 'OK', False),        # Recovered
    ('OK', 'ERROR', True),         # New error
])
def test_should_alert(old_status, new_status, should_alert_flag):
    """Test alert logic for status changes"""
    assert alert_rules.should_alert(old_status, new_status) == should_alert_flag


# ===== Database Integration Tests =====

def test_database_initial_insert(test_database):
    """Test storing new certificate in database"""
    hostname = "example.com"
    port = 443
    
    # First check - should insert
    test_database.process_certificate_check(
        hostname,
        port,
        {
            'days_remaining': 45,
            'status': 'OK',
            'issuer_name': "Let's Encrypt",
            'expire_date': '2025-02-23',
            'error_message': None
        },
        existing_cert=None
    )
    
    # Verify it was stored
    result = test_database.query_one(
        'SELECT hostname, days_remaining, status FROM certificates WHERE hostname = ?',
        (hostname,)
    )
    
    assert result is not None
    assert result['hostname'] == hostname
    assert result['days_remaining'] == 45
    assert result['status'] == 'OK'


def test_renewal_detection(test_database):
    """Test that certificate renewals are detected and logged"""
    hostname = "example.com"
    port = 443
    
    # Insert certificate expiring in 10 days
    test_database.process_certificate_check(
        hostname, port,
        {'days_remaining': 10, 'status': 'CRITICAL', 'issuer_name': "Let's Encrypt",
         'expire_date': '2025-01-22', 'error_message': None},
        existing_cert=None
    )
    
    existing = test_database.query_one(
        'SELECT * FROM certificates WHERE hostname = ? AND port = ?',
        (hostname, port)
    )
    
    # Certificate was renewed - now has 90 days
    test_database.process_certificate_check(
        hostname, port,
        {'days_remaining': 90, 'status': 'OK', 'issuer_name': "Let's Encrypt",
         'expire_date': '2025-04-20', 'error_message': None},
        existing_cert=existing
    )
    
    # Check events log with proper JOIN
    changes = test_database.query('''
        SELECT e.*, c.hostname, c.port
        FROM events e
        JOIN certificates c ON e.cert_id = c.id
        WHERE c.hostname = ?
    ''', (hostname,))
    
    assert len(changes) > 0
    
    # Find the renewal event
    renewal_events = [e for e in changes if e['event_type'] == 'RENEWED']
    assert len(renewal_events) > 0
    assert renewal_events[0]['old_value'] == '2025-01-22'
    assert renewal_events[0]['new_value'] == '2025-04-20'


# ===== Process Domains Tests =====

def test_process_domains_single(test_database):
    """Test processing a single domain"""
    domains = ['google.com']
    
    results = process_domains(domains, 443, 10, test_database)
    
    assert len(results) == 1
    assert results[0]['hostname'] == 'google.com'
    assert results[0]['status'] in ['OK', 'WARNING', 'CRITICAL']
    
    # Verify stored in database
    db_result = test_database.query_one(
        'SELECT * FROM certificates WHERE hostname = ?',
        ('google.com',)
    )
    assert db_result is not None


def test_process_domains_multiple(test_database):
    """Test processing multiple domains"""
    domains = [
        {'hostname': 'google.com', 'port': 443},
        {'hostname': 'github.com', 'port': 443}
    ]
    
    results = process_domains(domains, 443, 10, test_database)
    
    assert len(results) == 2
    
    # Verify both stored in database
    db_results = test_database.query('SELECT hostname FROM certificates')
    hostnames = [row['hostname'] for row in db_results]
    
    assert 'google.com' in hostnames
    assert 'github.com' in hostnames


def test_process_domains_with_errors(test_database):
    """Test handling domains that fail"""
    domains = ['nonexistent.invalid.domain.example']
    
    results = process_domains(domains, 443, 5, test_database)
    
    assert len(results) == 1
    assert results[0]['status'] == 'ERROR'
    assert results[0]['error_message'] is not None
    
    # Verify error stored in database
    db_result = test_database.query_one(
        'SELECT status, error_message FROM certificates WHERE hostname = ?',
        ('nonexistent.invalid.domain.example',)
    )
    assert db_result['status'] == 'ERROR'
    assert db_result['error_message'] is not None


# ===== Integration Test with badssl.com =====

def test_expired_certificate(test_database):
    """Test handling expired certificate using badssl.com"""
    domains = ['expired.badssl.com']
    
    results = process_domains(domains, 443, 10, test_database)
    
    assert len(results) == 1
    assert results[0]['status'] == 'EXPIRED'
    assert results[0]['error_message'] is not None
    



# ===== Email Alert Tests =====
alerter = EmailAlerter()

def test_email_alerter_initialization():
    """Test EmailAlerter can be initialized with .env credentials."""
    try:
        assert alerter.smtp_server is not None, "SMTP_HOST not configured"
        assert alerter.username is not None, "SMTP_USER not configured"
        assert alerter.password is not None, "SMTP_PASSWORD not configured"
        assert alerter.sender_email is not None, "SMTP_TO_EMAIL not configured"
        assert alerter.receiver_email is not None, "SMTP_FROM_EMAIL not configured" 
        assert alerter.smtp_port is not None, "SMTP_PORT not configured"
        
    except ValueError as e:
        pytest.fail(f"EmailAlerter initialization failed: {e}")



def test_send_critical_alert():
    time.sleep(10)  # Sleep to avoid SMTP rate limits
    """Test sending CRITICAL alert email."""
    test_cert = {
        'hostname': 'test-critical.example.com',
        'port': 443,
        'days_remaining': 3,
        'status': 'CRITICAL',
        'issuer_name': "Let's Encrypt",
        'expire_date': '2025-01-22',
        'error_message': None
    }
    
    result = alerter.send_alert(test_cert, 'CRITICAL')
    assert result is True, "CRITICAL alert failed to send"


def test_send_warning_alert():
    time.sleep(10)  # Sleep to avoid SMTP rate limits
    """Test sending WARNING alert email."""
    test_cert = {
        'hostname': 'test-warning.example.com',
        'port': 443,
        'days_remaining': 20,
        'status': 'WARNING',
        'issuer_name': 'DigiCert',
        'expire_date': '2025-02-08',
        'error_message': None
    }
    
    result = alerter.send_alert(test_cert, 'WARNING')
    assert result is True, "WARNING alert failed to send"


def test_send_expired_alert():
    """Test sending EXPIRED alert email."""
    time.sleep(10)  # Sleep to avoid SMTP rate limits
    test_cert = {
        'hostname': 'test-expired.example.com',
        'port': 443,
        'days_remaining': None,
        'status': 'EXPIRED',
        'issuer_name': None,
        'expire_date': None,
        'error_message': 'certificate has expired'
    }
    
    result = alerter.send_alert(test_cert, 'EXPIRED')
    assert result is True, "EXPIRED alert failed to send"


def test_send_renewed_alert():
    time.sleep(10)  # Sleep to avoid SMTP rate limits
    """Test sending RENEWED alert email."""
    test_cert = {
        'hostname': 'test-renewed.example.com',
        'port': 443,
        'days_remaining': 90,
        'status': 'OK',
        'issuer_name': "Let's Encrypt",
        'expire_date': '2025-04-20',
        'error_message': None
    }
    
    result = alerter.send_alert(test_cert, 'RENEWED')
    assert result is True, "RENEWED alert failed to send"


def test_alert_with_missing_data():
    time.sleep(10)  # Sleep to avoid SMTP rate limits
    """Test alert handles missing certificate data gracefully."""
    test_cert = {
        'hostname': 'test-incomplete.example.com',
        'port': 443,
        'days_remaining': None,
        'status': 'ERROR',
        'issuer_name': None,
        'expire_date': None,
        'error_message': 'Connection timeout'
    }
    
    # Should not crash, even with missing data
    result = alerter.send_alert(test_cert, 'ERROR')
    assert result is True, "Alert with missing data failed"


def test_multiple_alerts():
    """Test sending multiple alerts in sequence."""
    
    certs = [
        {
            'hostname': f'test-multi-{i}.example.com',
            'port': 443,
            'days_remaining': 5 + i,
            'status': 'CRITICAL',
            'issuer_name': "Let's Encrypt",
            'expire_date': '2025-01-25',
            'error_message': None
        }
        for i in range(3) # Sleep to avoid SMTP rate limits
    ]
    
    results = []
    for cert in certs:
        result = alerter.send_alert(cert, 'CRITICAL')
        time.sleep(10)
        results.append(result)
    
    assert all(results), f"Some alerts failed: {results.count(False)}/{len(results)}"
    assert len(results) == 3, "Expected 3 alerts to be sent"