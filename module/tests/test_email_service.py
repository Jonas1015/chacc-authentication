"""Tests for best-effort SMTP invite delivery (services/email_service.py)."""

from unittest.mock import MagicMock, Mock, patch

from ..services.email_service import send_invite_email


class FakeContext:
    def __init__(self, config: dict):
        self.logger = Mock()
        self._config = config

    def get_module_config(self, key, module, default=None):
        return self._config.get(key, default)


def test_send_invite_email_skips_when_smtp_host_unset():
    context = FakeContext({})
    sent = send_invite_email(context, "new@example.com", "http://x/accept", "MENU_MANAGER")
    assert sent is False
    context.logger.info.assert_called_once()


@patch("smtplib.SMTP")
def test_send_invite_email_sends_when_configured(mock_smtp_cls):
    mock_server = MagicMock()
    mock_smtp_cls.return_value.__enter__.return_value = mock_server

    context = FakeContext(
        {
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": 587,
            "SMTP_USERNAME": "user",
            "SMTP_PASSWORD": "pass",
            "SMTP_FROM_EMAIL": "no-reply@example.com",
            "SMTP_USE_TLS": "true",
        }
    )

    sent = send_invite_email(context, "new@example.com", "http://x/accept", "MENU_MANAGER")

    assert sent is True
    mock_smtp_cls.assert_called_once_with("smtp.example.com", 587, timeout=10)
    mock_server.starttls.assert_called_once()
    mock_server.login.assert_called_once_with("user", "pass")
    mock_server.sendmail.assert_called_once()
    args, _ = mock_server.sendmail.call_args
    assert args[0] == "no-reply@example.com"
    assert args[1] == ["new@example.com"]
    assert "http://x/accept" in args[2]


@patch("smtplib.SMTP")
def test_send_invite_email_returns_false_and_logs_on_failure(mock_smtp_cls):
    mock_smtp_cls.side_effect = OSError("connection refused")

    context = FakeContext({"SMTP_HOST": "smtp.example.com"})
    sent = send_invite_email(context, "new@example.com", "http://x/accept", "MENU_MANAGER")

    assert sent is False
    context.logger.warning.assert_called_once()


def test_send_invite_email_skips_login_when_no_credentials():
    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__.return_value = mock_server

        context = FakeContext({"SMTP_HOST": "smtp.example.com", "SMTP_USE_TLS": "false"})
        sent = send_invite_email(context, "new@example.com", "http://x/accept", "ANALYTICS_VIEWER")

        assert sent is True
        mock_server.starttls.assert_not_called()
        mock_server.login.assert_not_called()
