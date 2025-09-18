import os
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Optional, List, Dict, Any
from datetime import datetime

import core_logging as log
from core_renderer import Jinja2Renderer

from core_api.response import ErrorResponse
from ..constants import *


def _create_ssl_context() -> ssl.SSLContext:
    """Create SSL context based on configuration"""
    context = ssl.create_default_context()

    # Configure SSL verification mode
    verify_mode_map = {
        "none": ssl.CERT_NONE,
        "peer": ssl.CERT_REQUIRED,
        "client_once": ssl.CERT_REQUIRED,
        "fail_if_no_peer_cert": ssl.CERT_REQUIRED,
    }

    context.check_hostname = SMTP_OPENSSL_VERIFY_MODE != "none"
    context.verify_mode = verify_mode_map.get(SMTP_OPENSSL_VERIFY_MODE, ssl.CERT_NONE)

    # Load CA certificates if specified
    if SMTP_CA_FILE and os.path.exists(SMTP_CA_FILE):
        context.load_verify_locations(SMTP_CA_FILE)
    elif SMTP_CA_PATH and os.path.exists(SMTP_CA_PATH):
        context.load_verify_locations(capath=SMTP_CA_PATH)

    return context


def _create_connection() -> smtplib.SMTP:
    """Create and configure SMTP connection"""
    if not SMTP_ENABLE:
        raise Exception("SMTP is disabled in configuration")

    try:
        # Create SMTP connection
        server = smtplib.SMTP(SMTP_ADDRESS, int(SMTP_PORT))
        server.set_debuglevel(0)  # Set to 1 for debug output

        # Enable STARTTLS if configured
        if SMTP_ENABLE_STARTTLS_AUTO:
            server.starttls(context=_create_ssl_context())

        # Authenticate if credentials provided
        if SMTP_USER_NAME and SMTP_PASSWORD:
            log.debug(f"Authenticating as {SMTP_USER_NAME}: {SMTP_PASSWORD}")
            server.login(SMTP_USER_NAME, SMTP_PASSWORD)

        return server

    except Exception as e:
        log.error(f"Failed to create SMTP connection: {str(e)}")
        raise


def _add_attachments(msg: MIMEMultipart, attachments: List[Dict[str, Any]]):
    """Add attachments to email message"""
    for attachment in attachments:
        try:
            filename = attachment.get("filename", "attachment")
            content = attachment.get("content", b"")
            content_type = attachment.get("content_type", "application/octet-stream")

            part = MIMEBase(*content_type.split("/"))
            part.set_payload(content)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename= {filename}")
            msg.attach(part)

        except Exception as e:
            log.warning(f"Failed to add attachment {attachment.get('filename', 'unknown')}: {str(e)}")


def send_email(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: Optional[str] = None,
    cc: Optional[List[str]] = None,
    bcc: Optional[List[str]] = None,
    attachments: Optional[List[Dict[str, Any]]] = None,
    custom_headers: Optional[Dict[str, str]] = None,
) -> bool:
    """
    Send email with HTML and optional text body

    Args:
        to_email: Recipient email address
        subject: Email subject (prefix will be added automatically)
        html_body: HTML content of the email
        text_body: Plain text fallback (optional)
        cc: List of CC recipients (optional)
        bcc: List of BCC recipients (optional)
        attachments: List of attachment dicts (optional)
        custom_headers: Additional email headers (optional)

    Returns:
        bool: True if sent successfully, False otherwise
    """
    try:
        # Create message
        msg = MIMEMultipart("alternative")

        # Set headers
        msg["From"] = f"{SMTP_EMAIL_DISPLAY_NAME} <{SMTP_EMAIL_FROM}>"
        msg["To"] = to_email
        msg["Subject"] = f"{SMTP_EMAIL_SUBJECT_PREFIX} {subject}"
        msg["Reply-To"] = SMTP_EMAIL_REPLY_TO

        # Add CC and BCC if provided
        if cc:
            msg["Cc"] = ", ".join(cc)
        if bcc:
            msg["Bcc"] = ", ".join(bcc)

        # Add custom headers
        if custom_headers:
            for key, value in custom_headers.items():
                msg[key] = value

        # Add text body if provided
        if text_body:
            text_part = MIMEText(text_body, "plain", "utf-8")
            msg.attach(text_part)

        # Add HTML body
        html_part = MIMEText(html_body, "html", "utf-8")
        msg.attach(html_part)

        # Add attachments if provided
        if attachments:
            _add_attachments(msg, attachments)

        # Build recipient list
        recipients = [to_email]
        if cc:
            recipients.extend(cc)
        if bcc:
            recipients.extend(bcc)

        # Send email
        with _create_connection() as server:
            server.send_message(msg, to_addrs=recipients)

        log.debug(f"Email sent successfully to {to_email}")
        return True

    except Exception as e:
        log.debug(f"Failed to send email to {to_email}: {str(e)}")
        return False


def load_email_template(template_name: str, template_type: str = "html", variables: Dict[str, str] = None) -> str:
    """
    Load email template and replace variables

    Args:
        template_name: Name of the template file (without extension)
        template_type: Type of template ('html' or 'txt')
        variables: Dictionary of variables to replace in template

    Returns:
        str: Processed template content
    """
    try:

        # Use the directory where this module is located
        module_dir = os.path.dirname(__file__)
        template_path = os.path.join(module_dir, "templates")
        filename = f"{template_name}.{template_type}"

        renderer = Jinja2Renderer(template_path=template_path)

        # Load and render template content
        template_content = renderer.render_file(filename, variables)

        return template_content

    except Exception as e:
        log.error(f"Failed to load template {template_name}.{template_type}: {str(e)}")
        if template_type == "html":
            return f"<html><body><h1>Error Loading Template</h1><p>{str(e)}</p></body></html>"
        else:
            return f"Error Loading Template: {str(e)}"


def send_auth_code_email(to_email: str, auth_code: str, user_name: str = None) -> bool:
    """
    Send password reset authorization code email

    Args:
        to_email: Recipient email address
        auth_code: 8-digit authorization code
        user_name: User's name (optional)

    Returns:
        bool: True if sent successfully
    """
    try:
        # Prepare template variables
        variables = {
            "auth_code": auth_code,
            "user_name": user_name or to_email.split("@")[0],
            "support_email": SMTP_EMAIL_REPLY_TO,
            "company_name": SMTP_EMAIL_DISPLAY_NAME,
            "reset_url": f"https://{SMTP_DOMAIN}/enter-code",
        }

        # Load HTML and text templates
        html_body = load_email_template("authcode", "html.j2", variables)
        text_body = load_email_template("authcode", "txt.j2", variables)

        # Send email
        return send_email(
            to_email=to_email,
            subject="Password Reset Authorization Code",
            html_body=html_body,
            text_body=text_body,
            custom_headers={"X-Email-Type": "password-reset", "X-Priority": "1"},
        )

    except Exception as e:
        log.debug(f"Failed to send auth code email to {to_email}: {str(e)}")
        return False


def send_welcome_email(to_email: str, user_name: str, temp_password: str = None) -> bool:
    """
    Send welcome email to new users

    Args:
        to_email: Recipient email address
        user_name: User's name
        temp_password: Temporary password (optional)

    Returns:
        bool: True if sent successfully
    """
    try:
        variables = {
            "user_name": user_name,
            "login_url": f"https://{SMTP_DOMAIN}/login",
            "support_email": SMTP_EMAIL_REPLY_TO,
            "company_name": SMTP_EMAIL_DISPLAY_NAME,
            "temp_password": temp_password,
            "features": [
                {"icon": "☁️", "title": "Cloud Deploy", "description": "Deploy across multiple providers"},
                {"icon": "📊", "title": "Monitor & Scale", "description": "Real-time monitoring"},
                {"icon": "🔒", "title": "Secure by Default", "description": "Enterprise security"},
                {"icon": "⚡", "title": "Lightning Fast", "description": "Optimized performance"},
            ],
            "current_year": datetime.now().year,
            "expiry_minutes": 5,
        }

        # Fix: Use .j2 extensions consistently
        html_body = load_email_template("welcome", "html.j2", variables)
        text_body = load_email_template("welcome", "txt.j2", variables)

        return send_email(
            to_email=to_email,
            subject="Welcome to Core Automation",
            html_body=html_body,
            text_body=text_body,
            custom_headers={"X-Email-Type": "welcome"},
        )

    except Exception as e:
        log.error(f"Failed to send welcome email to {to_email}: {str(e)}")
        return False


def send_password_updated_email(to_email: str, user_name: str, ip_address: str = None, user_agent: str = None) -> bool:
    """
    Send password updated notification email

    Args:
        to_email: Recipient email address
        user_name: User's name
        ip_address: IP address from which password was changed (optional)
        user_agent: User agent string (optional)

    Returns:
        bool: True if sent successfully
    """
    try:
        variables = {
            "user_name": user_name,
            "login_url": f"https://{SMTP_DOMAIN}/login",
            "support_email": SMTP_EMAIL_REPLY_TO,
            "company_name": SMTP_EMAIL_DISPLAY_NAME,
            "update_date": datetime.now().strftime("%B %d, %Y"),
            "update_time": datetime.now().strftime("%I:%M %p UTC"),
            "ip_address": ip_address,
            "user_agent": user_agent,
        }

        # Load HTML and text templates
        html_body = load_email_template("passupdated", "html.j2", variables)
        text_body = load_email_template("passupdated", "txt.j2", variables)

        return send_email(
            to_email=to_email,
            subject="SECURITY ALERT: Password Updated",
            html_body=html_body,
            text_body=text_body,
            custom_headers={"X-Email-Type": "security-notification", "X-Priority": "1"},  # High priority
        )

    except Exception as e:
        log.error(f"Failed to send password updated email to {to_email}: {str(e)}")
        return False
