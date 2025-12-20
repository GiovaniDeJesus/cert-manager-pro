# database.py
import sqlite3
from datetime import datetime

class CertDatabase:
    """Database layer for certificate monitoring."""
    
    def __init__(self, db_path='certs.db'):
        """Initialize database connection and create tables if needed."""
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Create tables and indexes if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cursor = conn.cursor()
            
            # ========================================
            # YOUR SCHEMA GOES HERE
            # ========================================
            
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
    # CRUD METHODS GO HERE
    # ========================================
    
    def get_certificate(self, hostname, port):
        """Get certificate by hostname and port."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row  # Return dict-like rows
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM certificates 
                WHERE hostname = ? AND port = ?
            ''', (hostname, port))
            
            return cursor.fetchone()
    
    def insert_certificate(self, hostname, port, cert_data):
        """Insert new certificate."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
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
            
            conn.commit()
            return cursor.lastrowid  # Return the new certificate's ID
    
    def update_certificate(self, cert_id, cert_data):
        """Update existing certificate."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
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
            
            conn.commit()
    
    def log_event(self, cert_id, event_type, old_value=None, new_value=None, notes=None):
        """Log a certificate event."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO events 
                (cert_id, event_type, old_value, new_value, notes)
                VALUES (?, ?, ?, ?, ?)
            ''', (cert_id, event_type, old_value, new_value, notes))
            
            conn.commit()
    
    def record_alert(self, cert_id, alert_type, message=None):
        """Record that an alert was sent."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts (cert_id, alert_type, message)
                VALUES (?, ?, ?)
            ''', (cert_id, alert_type, message))
            
            conn.commit()
    
    def alert_sent_recently(self, cert_id, alert_type, hours=24):
        """Check if alert was sent recently."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) FROM alerts
                WHERE cert_id = ?
                  AND alert_type = ?
                  AND sent_at > datetime('now', ? || ' hours')
            ''', (cert_id, alert_type, -hours))
            
            count = cursor.fetchone()[0]
            return count > 0
    
    def get_all_certificates(self):
        """Get all certificates."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM certificates 
                ORDER BY days_remaining ASC
            ''')
            
            return cursor.fetchall()

