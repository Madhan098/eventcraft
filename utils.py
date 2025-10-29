import random
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def send_otp_email(email, otp_code, purpose='verification'):
    """Send OTP via email using Gmail SMTP"""
    
    # Always display OTP in terminal for debugging
    print(f"\n{'='*60}")
    print(f"OTP GENERATED FOR {email.upper()}")
    print(f"{'='*60}")
    print(f"Purpose: {purpose}")
    print(f"OTP Code: {otp_code}")
    print(f"Valid for 10 minutes")
    print(f"Use this OTP to complete your {purpose}")
    print(f"{'='*60}\n")
    
    try:
        # Gmail SMTP configuration from environment variables
        smtp_server = 'smtp.gmail.com'
        smtp_port = 587
        smtp_username = os.environ.get('SMTP_USERNAME', 'jmadhanplacement@gmail.com')
        smtp_password = os.environ.get('SMTP_PASSWORD', 'nuzo pyuk focz kdxx')
        
        # Validate email format
        if not email or '@' not in email:
            print(f"ERROR: Invalid email address: {email}")
            return False
        
        # Determine email content based on purpose
        if purpose == 'password_reset':
            subject = "EventCraft Pro - Password Reset OTP"
            title = "EventCraft Pro - Password Reset"
            message = "Your OTP for EventCraft Pro password reset is:"
            action = "password reset"
        else:
            subject = "EventCraft Pro - Email Verification OTP"
            title = "EventCraft Pro - Email Verification"
            message = "Your OTP for EventCraft Pro email verification is:"
            action = "verification"
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = f"EventCraft Pro <{smtp_username}>"
        msg['To'] = email
        msg['Subject'] = subject
        msg['Reply-To'] = smtp_username
        
        # Email body with both HTML and plain text
        html_body = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .otp-box {{ background: linear-gradient(135deg, #E91E63 0%, #9C27B0 50%, #66BB6A 100%); 
                            padding: 30px; text-align: center; border-radius: 12px; margin: 30px 0; }}
                .otp-code {{ font-size: 42px; font-weight: bold; color: #FFFFFF; 
                            letter-spacing: 8px; margin: 20px 0; font-family: 'Courier New', monospace; }}
                .footer {{ color: #666; font-size: 12px; margin-top: 30px; padding-top: 20px; 
                          border-top: 1px solid #eee; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2 style="color: #E91E63;">{title}</h2>
                <p>Hello,</p>
                <p>{message}</p>
                <div class="otp-box">
                    <div class="otp-code">{otp_code}</div>
                </div>
                <p><strong>This OTP will expire in 10 minutes.</strong></p>
                <p>If you didn't request this {action}, please ignore this email.</p>
                <div class="footer">
                    <p>EventCraft Pro - Digital Event Invitations</p>
                    <p>Create beautiful invitations in minutes</p>
                </div>
            </div>
        </body>
        </html>
        '''
        
        plain_body = f'''
{title}

Hello,

{message} {otp_code}

This OTP will expire in 10 minutes.

If you didn't request this {action}, please ignore this email.

---
EventCraft Pro - Digital Event Invitations
Create beautiful invitations in minutes
        '''
        
        # Attach both plain text and HTML versions
        msg.attach(MIMEText(plain_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        # Send email with detailed logging
        print(f"Attempting to send {purpose} email to: {email}")
        print(f"Using SMTP server: {smtp_server}:{smtp_port}")
        print(f"From: {smtp_username}")
        
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.set_debuglevel(0)  # Set to 1 for verbose logging
        server.ehlo()
        server.starttls()
        server.ehlo()
        print("✓ STARTTLS enabled")
        
        server.login(smtp_username, smtp_password)
        print("✓ SMTP login successful")
        
        text = msg.as_string()
        result = server.sendmail(smtp_username, [email], text)
        server.quit()
        
        print(f"✓ Email sent successfully to {email}")
        print(f"SMTP sendmail result: {result}")
        
        # Empty dict means success
        if not result:
            print(f"✓ OTP email delivered successfully to {email}")
            return True
        else:
            print(f"⚠ Email sent with delivery issues: {result}")
            # Still return True as email was accepted by server
            return True
            
    except smtplib.SMTPAuthenticationError as e:
        print(f"✗ SMTP Authentication Error: {str(e)}")
        print("Please check your SMTP credentials (username and password)")
        
    except smtplib.SMTPRecipientsRefused as e:
        print(f"✗ SMTP Recipients Refused: {str(e)}")
        print(f"Email address {email} was refused by the server")
        
    except smtplib.SMTPSenderRefused as e:
        print(f"✗ SMTP Sender Refused: {str(e)}")
        print("Sender email address was refused by the server")
        
    except smtplib.SMTPDataError as e:
        print(f"✗ SMTP Data Error: {str(e)}")
        print("The server refused the message data")
        
    except smtplib.SMTPConnectError as e:
        print(f"✗ SMTP Connection Error: {str(e)}")
        print("Could not connect to SMTP server")
        
    except smtplib.SMTPException as e:
        print(f"✗ SMTP Error: {str(e)}")
        print(f"Exception type: {type(e).__name__}")
        
    except Exception as e:
        print(f"✗ Unexpected Error: {str(e)}")
        print(f"Exception type: {type(e).__name__}")
    
    # Try fallback approach with simple message
    print("\nAttempting fallback email approach...")
    try:
        simple_msg = MIMEText(f"""
EventCraft Pro - {title}

Hello,

{message} {otp_code}

This OTP will expire in 10 minutes.

If you didn't request this {action}, please ignore this email.

---
EventCraft Pro - Digital Event Invitations
        """)
        
        simple_msg['Subject'] = subject
        simple_msg['From'] = smtp_username
        simple_msg['To'] = email
        
        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(simple_msg)
        server.quit()
        
        print(f"✓ Fallback email sent successfully to {email}")
        return True
        
    except Exception as e2:
        print(f"✗ Fallback email also failed: {str(e2)}")
    
    # Final fallback - always print OTP for manual verification
    print(f"\n{'='*60}")
    print(f"EMAIL SENDING FAILED - OTP FOR MANUAL USE")
    print(f"{'='*60}")
    print(f"Email: {email}")
    print(f"OTP Code: {otp_code}")
    print(f"Purpose: {purpose}")
    print(f"Expires: 10 minutes from now")
    print(f"{'='*60}\n")
    
    print("TROUBLESHOOTING SUGGESTIONS:")
    print("1. Check if Gmail account has 2-factor authentication enabled")
    print("2. Verify the app password is correct and hasn't expired")
    print("3. Check spam/junk folder for the email")
    print("4. Ensure SMTP_USERNAME and SMTP_PASSWORD environment variables are set")
    print("5. For Render deployment, add these as environment variables in Render dashboard")
    print("6. Check firewall/network restrictions")
    print("7. Verify email address format is correct")
    
    return False

def format_date(date_str):
    """Format date string for display"""
    from datetime import datetime
    try:
        date_obj = datetime.strptime(date_str, '%Y-%m-%d')
        return date_obj.strftime('%B %d, %Y')
    except:
        return date_str

def format_time(time_str):
    """Format time string for display"""
    from datetime import datetime
    try:
        time_obj = datetime.strptime(time_str, '%H:%M')
        return time_obj.strftime('%I:%M %p')
    except:
        return time_str
