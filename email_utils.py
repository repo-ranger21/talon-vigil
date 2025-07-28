from flask_mail import Mail, Message

mail = Mail()

def send_email(to_email, subject, html_content, text_content=None):
    """
    Send an email using Flask-Mail.
    
    Args:
        to_email (str): Recipient email address
        subject (str): Email subject
        html_content (str): HTML content of the email
        text_content (str, optional): Plain text content of the email
    """
    try:
        msg = Message(
            subject=subject,
            recipients=[to_email],
            html=html_content,
            body=text_content or html_content.replace('<br>', '\n').replace('</p>', '\n\n')
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        return False
