import smtplib
import os
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger("asdip.email")

def send_otp_email(receiver_email: str, otp: str):
    sender_email = os.environ.get("EMAIL_USER")
    sender_password = os.environ.get("EMAIL_PASS")
    
    if not sender_email or not sender_password:
        logger.error("Email credentials not set in .env")
        return False
        
    try:
        # Create a modern/professional email template
        subject = "ASDIP Secure Verification Code"
        body = f"""
        <html>
        <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 40px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #1e293b; border-radius: 12px; padding: 32px; border: 1px solid #334155; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);">
                <h2 style="color: #38bdf8; margin-top: 0; border-bottom: 2px solid #334155; padding-bottom: 16px;">Authentication Required</h2>
                <p style="font-size: 16px; line-height: 1.6;">A login or signup attempt for <strong>ASDIP</strong> requires verification.</p>
                <div style="background-color: #0f172a; color: #38bdf8; padding: 24px; text-align: center; border-radius: 8px; margin: 32px 0;">
                    <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px;">{otp}</span>
                </div>
                <p style="font-size: 14px; color: #94a3b8;">This code will expire in 5 minutes. If you did not request this code, please ignore this email and change your password.</p>
                <div style="margin-top: 32px; padding-top: 16px; border-top: 1px solid #334155; font-size: 12px; color: #64748b; text-align: center;">
                    ASDIP Security Operations Center &copy; 2026
                </div>
            </div>
        </body>
        </html>
        """
        
        message = MIMEMultipart()
        message["From"] = f"ASDIP Security <{sender_email}>"
        message["To"] = receiver_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "html"))
        
        # Connect to Gmail SMTP (assuming Gmail based on the user's email)
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, message.as_string())
            
        logger.info(f"OTP email sent successfully to {receiver_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {receiver_email}: {e}")
        return False
