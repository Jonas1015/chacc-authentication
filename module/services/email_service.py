"""
Best-effort SMTP delivery for staff invite emails (Epic C7 follow-up).

Sending failures are logged but never block invite creation - the Invite row
and its token are the source of truth; email is a delivery convenience on
top of that, matching this codebase's existing "optional external service,
degrade gracefully" pattern used for Redis elsewhere in this plugin.
"""

import smtplib
from email.mime.text import MIMEText
from typing import Optional


def _smtp_settings(context) -> Optional[dict]:
    host = context.get_module_config("SMTP_HOST", "authentication", None)
    if not host:
        return None
    return {
        "host": host,
        "port": int(context.get_module_config("SMTP_PORT", "authentication", 587)),
        "username": context.get_module_config("SMTP_USERNAME", "authentication", None),
        "password": context.get_module_config("SMTP_PASSWORD", "authentication", None),
        "from_email": context.get_module_config(
            "SMTP_FROM_EMAIL", "authentication", "no-reply@menuapp.local"
        ),
        "use_tls": str(
            context.get_module_config("SMTP_USE_TLS", "authentication", "true")
        ).lower()
        == "true",
    }


def send_invite_email(context, to_email: str, invite_link: str, role_name: str) -> bool:
    """Send the invite email. Returns True if sent, False if skipped/failed."""
    settings = _smtp_settings(context)
    if not settings:
        context.logger.info(
            "SMTP not configured (AUTHENTICATION_SMTP_HOST unset) - skipping "
            "invite email; token/link is still returned in the API response"
        )
        return False

    message = MIMEText(
        f"You've been invited to join a restaurant's staff as {role_name}.\n\n"
        f"Accept your invite: {invite_link}"
    )
    message["Subject"] = "You're invited to join MenuApp"
    message["From"] = settings["from_email"]
    message["To"] = to_email

    try:
        with smtplib.SMTP(settings["host"], settings["port"], timeout=10) as server:
            if settings["use_tls"]:
                server.starttls()
            if settings["username"] and settings["password"]:
                server.login(settings["username"], settings["password"])
            server.sendmail(settings["from_email"], [to_email], message.as_string())
        return True
    except Exception as exc:
        context.logger.warning(f"Failed to send invite email to {to_email}: {exc}")
        return False
