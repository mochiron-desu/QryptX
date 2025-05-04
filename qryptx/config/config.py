"""Configuration settings for the honeypot"""
import os

# Database settings
DB_FILE = "honeypot.db"

# Logging configuration
LOG_FORMAT = "%(message)s"

# Telegram bot configuration
BOT_TOKEN = "YOUR_BOT_TOKEN"  # Replace with actual token
CHAT_ID = "YOUR_CHAT_ID"      # Replace with actual chat ID

# Valid credentials for honeypot services
VALID_HTTP_USERNAME = "user"
VALID_HTTP_PASSWORD = "password"

VALID_FTP_USERS = {
    "user": "passs"
}

VALID_SSH_USERNAME = "user"
VALID_SSH_PASSWORD = "password123"

VALID_SMTP_USERNAME = "test"
VALID_SMTP_PASSWORD = "password"

# SQL Injection detection patterns
SQLI_PATTERNS = [
    r"\bOR\b",
    r"\bAND\b",
    r"\bUNION\b",
    "--",
    r"' OR '1'='1",
    r"' OR 1=1 --",
    r"DROP TABLE",
    r"SELECT \* FROM",
    r"' OR 'x'='x"
]

# Fake files for FTP/SSH services
FAKE_FILES = [
    "file1.txt",
    "report.pdf",
    "secret.doc"
]

# Service ports (using non-privileged ports for development)
HTTP_PORT = 8080    # Instead of 80
FTP_PORT = 2121    # Instead of 21
SMTP_PORT = 2525   # Instead of 25
SSH_PORT = 2222    # Instead of 22
DASHBOARD_PORT = 8000  # Changed from 8080 to avoid conflict with HTTP

# PQC Key file paths
DILITHIUM_PRIVATE_KEY = os.path.join(os.path.dirname(__file__), "..", "keys", "dilithium_private_key.bin")
DILITHIUM_PUBLIC_KEY = os.path.join(os.path.dirname(__file__), "..", "keys", "dilithium_public_key.bin")