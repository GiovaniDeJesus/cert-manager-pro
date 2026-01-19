import smtplib
from email.mime.text import MIMEText
import ssl
import os
from dotenv import load_dotenv



def smtp_alert(alert_data, alert_type):
    
    load_dotenv()  # Load environment variables from .env file
    hostname = alert_data['hostname']
    port = alert_data['port']
    days_remaining = alert_data['days_remaining']
    status = alert_data['status']
    issuer_name = alert_data['issuer_name']
    expiry_date = alert_data['expire_date']
    error = alert_data['error_message']
    

    # SMTP Configuration
    SMTP_SERVER = os.getenv("SMTP_SERVER")  # Replace with actual SMTP server
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))  # 465 for SSL, 587 for TLS
    USERNAME = os.getenv("USERNAME")
    PASSWORD = os.getenv("PASSWORD")
    context = ssl.create_default_context()


    # Email Details
    sender_email = os.getenv("sender_email")
    receiver_email = os.getenv("receiver_email")
    subject = f"SSL Certificate Alert for {hostname}:{port} - Alert: {alert_type}"
    body = f"SSL Certificate Alert for {hostname}:{port} - Status: {status}\n\nDays Remaining: {days_remaining}\nExpiry Date: {expiry_date}\nIssuer Name: {issuer_name}\nError: {error}"

    # Create the email
    message = MIMEText(body, "plain")
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = receiver_email

    # Send the email
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.ehlo() 
            server.starttls(context=context)  # Secure connection
            server.ehlo()
            server.login(USERNAME, PASSWORD)
            server.sendmail(sender_email, receiver_email, message.as_string())
            
        print("Email sent successfully!")
            

    except smtplib.SMTPAuthenticationError:
        print("Error: Authentication failed. Check username/password.")

    except smtplib.SMTPRecipientsRefused:
        print("Error: The recipient address was rejected.")

    except smtplib.SMTPException as e:
        print(f"SMTP error occurred: {e}")

    except OSError as e:
        print(f"Network error: {e}")
