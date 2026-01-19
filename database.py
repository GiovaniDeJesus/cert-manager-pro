import sqlite3
from datetime import datetime
from alert_rules import should_alert 


class CertDatabase:
    """
    Database layer for certificate monitoring.
    
    Simple approach:
    - Generic query methods for flexibility
    - Atomic batch write for certificate checks
    """
    
    def __init__(self, db_path='certs.db'):
        self.db_path = db_path
        self._persistent_conn = None
        
        # If using in-memory, keep connection alive
        if db_path == ':memory:':
            self._persistent_conn = self._get_connection()
        
        self._init_database()
    
    def _get_connection(self):
        """Get database connection - reuse for in-memory databases."""
        # If we have a persistent connection (in-memory), use it
        if self._persistent_conn is not None:
            return self._persistent_conn
        
        # Otherwise create new connection (file-based)
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        return conn
    
    def close(self):
        """Close persistent connection if exists."""
        if self._persistent_conn is not None:
            self._persistent_conn.close()
            self._persistent_conn = None
            
    def _init_database(self):
        """Create tables and indexes if they don't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Certificates: Current state of all monitored certs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    days_remaining INTEGER,
                    status TEXT,
                    issuer_name TEXT,
                    expire_date TEXT,
                    error_message TEXT,
                    last_checked TIMESTAMP,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(hostname, port)
                )
            ''')
            
            # Events: Log interesting changes only
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cert_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    notes TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cert_id) REFERENCES certificates(id)
                )
            ''')
            
            # Alerts: Track sent notifications
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cert_id INTEGER NOT NULL,
                    alert_type TEXT NOT NULL,
                    message TEXT,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    acknowledged BOOLEAN DEFAULT 0,
                    acknowledged_by TEXT,
                    acknowledged_at TIMESTAMP,
                    FOREIGN KEY (cert_id) REFERENCES certificates(id)
                )
            ''')
            
            # Indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hostname ON certificates(hostname)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_status ON certificates(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_days_remaining ON certificates(days_remaining)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cert_events ON events(cert_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cert_alerts ON alerts(cert_id)')
            
            conn.commit()
    
    # ========================================
    # GENERIC READ METHODS
    # ========================================
    def _row_to_dict(self, row):
        """Convert sqlite3.Row to dictionary."""
        if row is None:
            return None
        return dict(row) 
    
    def query(self, sql, params=()):
        """
        Execute a SELECT query and return all results.
        
        This is a generic read method - use it for any query.
        
        Args:
            sql: SQL SELECT statement
            params: Tuple of parameters for ? placeholders
        
        Returns:
            list: List of Row objects (dict-like)
        
        Examples:
            # Get one certificate
            db.query('SELECT * FROM certificates WHERE hostname = ?', ('google.com',))
            
            # Get all WARNING certificates
            db.query('SELECT * FROM certificates WHERE status = ?', ('WARNING',))
            
            # Get certificates expiring soon
            db.query('SELECT * FROM certificates WHERE days_remaining < ?', (7,))
            
            # Complex JOIN
            db.query('''
                SELECT c.hostname, e.event_type, e.detected_at
                FROM certificates c
                JOIN events e ON c.id = e.cert_id
                WHERE c.status = ?
                ORDER BY e.detected_at DESC
            ''', ('CRITICAL',))
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            return [self._row_to_dict(row) for row in rows]
        

    
    def query_one(self, sql, params=()):
        """
        Execute a SELECT query and return one result.
        
        Args:
            sql: SQL SELECT statement
            params: Tuple of parameters for ? placeholders
        
        Returns:
            Row object (dict-like) or None if no results
        
        Examples:
            # Get specific certificate
            db.query_one(
                'SELECT * FROM certificates WHERE hostname = ? AND port = ?',
                ('google.com', 443)
            )
            
            # Count certificates
            result = db.query_one('SELECT COUNT(*) as count FROM certificates')
            print(result['count'])
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            row = cursor.fetchone()
            return self._row_to_dict(row)
    
    # ========================================
    # ATOMIC WRITE METHOD
    # ========================================
    
    def process_certificate_check(self, hostname, port, cert_data, existing_cert=None):
        """
        Process a complete certificate check in a SINGLE atomic transaction.
        
        This method handles all database operations for checking a certificate:
        - Insert new certificate or update existing
        - Log events for changes (renewal, status change, issuer change)
        - Record alerts when needed
        
        All operations succeed together or fail together (atomic).
        
        Args:
            hostname: Domain name
            port: Port number
            cert_data: Dict with certificate data:
                - days_remaining: int or None
                - status: str ('OK', 'WARNING', 'CRITICAL', 'ERROR', 'EXPIRED')
                - issuer_name: str or None
                - expire_date: str (YYYY-MM-DD) or None
                - error_message: str or None
            existing_cert: Existing certificate Row from database (or None for new)
        
        Returns:
            dict: {
                'cert_id': int,
                'action': str ('inserted' or 'updated'),
                'events_logged': list of event types,
                'alerts_recorded': list of alert types
            }
        
        Raises:
            Exception: If any database operation fails (entire transaction rolls back)
        
        Examples:
            # New certificate
            result = db.process_certificate_check(
                'google.com', 443,
                {'days_remaining': 67, 'status': 'OK', 'issuer_name': 'Google', 
                 'expire_date': '2025-03-15', 'error_message': None},
                existing_cert=None
            )
            
            # Update existing
            existing = db.query_one(
                'SELECT * FROM certificates WHERE hostname = ? AND port = ?',
                ('google.com', 443)
            )
            result = db.process_certificate_check(
                'google.com', 443,
                {'days_remaining': 25, 'status': 'WARNING', ...},
                existing_cert=existing
            )
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            try:
                result = {
                    'cert_id': None,
                    'action': None,
                    'events_logged': [],
                    'alerts_recorded': []
                }
                
                if not existing_cert:
                    # ==========================================
                    # NEW CERTIFICATE
                    # ==========================================
                    
                    # Insert certificate
                    cursor.execute('''
                        INSERT INTO certificates 
                        (hostname, port, days_remaining, status, issuer_name, 
                         expire_date, error_message, last_checked)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        hostname,
                        port,
                        cert_data.get('days_remaining'),
                        cert_data.get('status'),
                        cert_data.get('issuer_name'),
                        cert_data.get('expire_date'),
                        cert_data.get('error_message'),
                        datetime.now().isoformat()
                    ))
                    
                    cert_id = cursor.lastrowid
                    result['cert_id'] = cert_id
                    result['action'] = 'inserted'
                    
                    # Log discovery event (only if not an error)
                    if cert_data.get('status') not in ('ERROR', 'EXPIRED'):
                        cursor.execute('''
                            INSERT INTO events (cert_id, event_type, notes)
                            VALUES (?, ?, ?)
                        ''', (
                            cert_id,
                            'DISCOVERED',
                            f"First seen with {cert_data.get('days_remaining')} days remaining"
                        ))
                        result['events_logged'].append('DISCOVERED')
                    else:
                        # Log error discovery
                        cursor.execute('''
                            INSERT INTO events (cert_id, event_type, notes)
                            VALUES (?, ?, ?)
                        ''', (
                            cert_id,
                            'ERROR',
                            cert_data.get('error_message', 'Certificate check failed')
                        ))
                        result['events_logged'].append('ERROR')
                
                else:
                    # ==========================================
                    # EXISTING CERTIFICATE - CHECK FOR CHANGES
                    # ==========================================
                    
                    cert_id = existing_cert['id']
                    result['cert_id'] = cert_id
                    result['action'] = 'updated'
                    
                    # Check 1: Certificate Renewed?
                    if (existing_cert['expire_date'] and 
                        cert_data.get('expire_date') and 
                        existing_cert['expire_date'] != cert_data.get('expire_date')):
                        
                        # Expire date changed = certificate was renewed
                        cursor.execute('''
                            INSERT INTO events 
                            (cert_id, event_type, old_value, new_value, notes)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (
                            cert_id,
                            'RENEWED',
                            existing_cert['expire_date'],
                            cert_data.get('expire_date'),
                            f"Certificate renewed. Days remaining reset from {existing_cert['days_remaining']} to {cert_data.get('days_remaining')}"
                        ))
                        result['events_logged'].append('RENEWED')
                        
                        # Check if should alert for renewal (not alerted in last week)
                        cursor.execute('''
                            SELECT COUNT(*) FROM alerts
                            WHERE cert_id = ? 
                              AND alert_type = ?
                              AND sent_at > datetime('now', '-168 hours')
                        ''', (cert_id, 'RENEWED'))
                        
                        if cursor.fetchone()[0] == 0:
                            cursor.execute('''
                                INSERT INTO alerts (cert_id, alert_type, message)
                                VALUES (?, ?, ?)
                            ''', (
                                cert_id,
                                'RENEWED',
                                f"Certificate renewed. New expiry: {cert_data.get('expire_date')}"
                            ))
                            result['alerts_recorded'].append('RENEWED')
                    
                    # Check 2: Issuer Changed?
                    if (existing_cert['issuer_name'] and 
                        cert_data.get('issuer_name') and 
                        existing_cert['issuer_name'] != cert_data.get('issuer_name')):
                        
                        cursor.execute('''
                            INSERT INTO events 
                            (cert_id, event_type, old_value, new_value)
                            VALUES (?, ?, ?, ?)
                        ''', (
                            cert_id,
                            'ISSUER_CHANGE',
                            existing_cert['issuer_name'],
                            cert_data.get('issuer_name')
                        ))
                        result['events_logged'].append('ISSUER_CHANGE')
                    
                    # Check 3: Status Changed?
                    if existing_cert['status'] != cert_data.get('status'):
                        cursor.execute('''
                            INSERT INTO events 
                            (cert_id, event_type, old_value, new_value, notes)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (
                            cert_id,
                            'STATUS_CHANGE',
                            existing_cert['status'],
                            cert_data.get('status'),
                            f"Status changed at {cert_data.get('days_remaining')} days remaining"
                        ))
                        result['events_logged'].append('STATUS_CHANGE')
                        
                        # Check if should alert (status got worse + not alerted recently)
                        if should_alert(existing_cert['status'], cert_data.get('status')):
                            cursor.execute('''
                                SELECT COUNT(*) FROM alerts
                                WHERE cert_id = ? 
                                  AND alert_type = ?
                                  AND sent_at > datetime('now', '-24 hours')
                            ''', (cert_id, cert_data.get('status')))
                            
                            if cursor.fetchone()[0] == 0:
                                cursor.execute('''
                                    INSERT INTO alerts (cert_id, alert_type, message)
                                    VALUES (?, ?, ?)
                                ''', (
                                    cert_id,
                                    cert_data.get('status'),
                                    f"Status changed from {existing_cert['status']} to {cert_data.get('status')}"
                                ))
                                result['alerts_recorded'].append(cert_data.get('status'))
                    
                    # Check 4: New Error?
                    if (cert_data.get('error_message') and 
                        cert_data.get('error_message') != existing_cert.get('error_message')):
                        
                        cursor.execute('''
                            INSERT INTO events 
                            (cert_id, event_type, notes)
                            VALUES (?, ?, ?)
                        ''', (
                            cert_id,
                            'ERROR',
                            cert_data.get('error_message')
                        ))
                        result['events_logged'].append('ERROR')
                    
                    # Update certificate with latest data
                    cursor.execute('''
                        UPDATE certificates 
                        SET days_remaining = ?,
                            status = ?,
                            issuer_name = ?,
                            expire_date = ?,
                            error_message = ?,
                            last_checked = ?
                        WHERE id = ?
                    ''', (
                        cert_data.get('days_remaining'),
                        cert_data.get('status'),
                        cert_data.get('issuer_name'),
                        cert_data.get('expire_date'),
                        cert_data.get('error_message'),
                        datetime.now().isoformat(),
                        cert_id
                    ))
                
                # ==========================================
                # COMMIT ALL CHANGES AT ONCE
                # ==========================================
                conn.commit()
                
                return result
                
            except Exception as e:
                # ==========================================
                # ROLLBACK EVERYTHING IF ANY STEP FAILS
                # ==========================================
                conn.rollback()
                raise Exception(f"Database error for {hostname}:{port}: {e}")
    
    # ========================================
    