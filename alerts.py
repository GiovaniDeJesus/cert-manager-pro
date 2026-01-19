import smtplib
from email.message import EmailMessage
import os
from dotenv import load_dotenv

# Load environment variables once at module level
load_dotenv()


class EmailAlerter:
    """Send email alerts for certificate issues."""
    
    def __init__(self):
        """Initialize with SMTP configuration from environment variables."""
        # Load SMTP configuration
        self.smtp_server = os.getenv("SMTP_SERVER")
        self.smtp_port = int(os.getenv("SMTP_PORT", 587))
        self.username = os.getenv("USERNAME")
        self.password = os.getenv("PASSWORD")
        self.sender_email = os.getenv("sender_email")
        self.receiver_email = os.getenv("receiver_email")
        
        # Validate configuration
        if not all([self.smtp_server, self.username, self.password, 
                    self.sender_email, self.receiver_email]):
            raise ValueError(
                "Missing SMTP configuration. Check your .env file.\n"
                "Required: SMTP_SERVER, USERNAME, PASSWORD, sender_email, receiver_email"
            )
    
    def send_alert(self, alert_data, alert_type):
        """
        Send email alert for a certificate issue.
        
        Args:
            alert_data: Dictionary with certificate data
            alert_type: Type of alert ('WARNING', 'CRITICAL', 'EXPIRED', etc.)
        
        Returns:
            bool: True if sent successfully, False otherwise
        """
        try:
            # Extract data
            hostname = alert_data['hostname']
            port = alert_data['port']
            days_remaining = alert_data.get('days_remaining')
            status = alert_data['status']
            issuer_name = alert_data.get('issuer_name')
            expiry_date = alert_data.get('expire_date')
            error = alert_data.get('error_message')
            
            # Create subject and body
            subject = self._create_subject(hostname, port, alert_type)
            body = self._create_body(
                hostname, port, status, days_remaining, 
                expiry_date, issuer_name, error, alert_type
            )
            
            # Create email message
            message = EmailMessage()
            message["Subject"] = subject
            message["From"] = self.sender_email
            message["To"] = self.receiver_email
            message.set_content(body)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()  # Secure connection
                server.ehlo()
                server.login(self.username, self.password)
                server.send_message(message)
            
            print(f"✓ Alert sent: {alert_type} for {hostname}")
            return True
            
        except smtplib.SMTPAuthenticationError:
            print("✗ Error: Authentication failed. Check username/password.")
            return False
        except smtplib.SMTPRecipientsRefused:
            print("✗ Error: The recipient address was rejected.")
            return False
        except smtplib.SMTPException as e:
            print(f"✗ SMTP error occurred: {e}")
            return False
        except OSError as e:
            print(f"✗ Network error: {e}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            return False
    
    def _create_subject(self, hostname, port, alert_type):
        """Create email subject line."""
        if alert_type == 'CRITICAL':
            return f"🚨 CRITICAL: SSL Certificate Alert for {hostname}:{port}"
        elif alert_type == 'WARNING':
            return f"⚠️  WARNING: SSL Certificate Alert for {hostname}:{port}"
        elif alert_type == 'EXPIRED':
            return f"❌ EXPIRED: SSL Certificate Alert for {hostname}:{port}"
        elif alert_type == 'ERROR':
            return f"🔴 ERROR: SSL Certificate Alert for {hostname}:{port}"
        elif alert_type == 'RENEWED':
            return f"✅ RENEWED: SSL Certificate Alert for {hostname}:{port}"
        else:
            return f"📧 SSL Certificate Alert for {hostname}:{port} - {alert_type}"
    
    def _create_body(self, hostname, port, status, days_remaining, 
                     expiry_date, issuer_name, error, alert_type):
        """Create email body text."""
        body = f"SSL Certificate Alert\n"
        body += "=" * 60 + "\n\n"
        
        body += f"Host: {hostname}:{port}\n"
        body += f"Status: {status}\n"
        body += f"Alert Type: {alert_type}\n\n"
        
        if days_remaining is not None:
            body += f"Days Remaining: {days_remaining}\n"
        
        if expiry_date:
            body += f"Expiry Date: {expiry_date}\n"
        
        if issuer_name:
            body += f"Issuer Name: {issuer_name}\n"
        
        if error:
            body += f"\nError Message:\n{error}\n"
        
        body += "\n" + "=" * 60 + "\n"
        body += "This is an automated alert from Cert Monitor Pro\n"
        
        return body