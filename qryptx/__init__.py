"""QryptX - Post-Quantum Cryptography Honeypot"""
from .core.honeypot import HoneypotManager
from .services.http_handler import handle_http
from .services.ftp_handler import handle_ftp
from .services.smtp_handler import handle_smtp
from .services.ssh_handler import handle_ssh
from .dashboard.dashboard_handler import start_dashboard
from .utils.logging import start_telegram_bot
from .database.db_handler import init_database
from .utils.crypto import generate_dilithium_keys
from .config.config import (
    HTTP_PORT,
    FTP_PORT,
    SMTP_PORT,
    SSH_PORT,
    DASHBOARD_PORT,
    LOG_FORMAT
)

def main():
    """Initialize and start the honeypot"""
    import logging
    import threading
    import pyfiglet

    # Print Banner
    banner = pyfiglet.figlet_format("QryptX", font="dos_rebel")
    print(banner)
    print("Post-Quantum Cryptography Honeypot")
    print("Created by: FIYAN MEHFIL AYOOB & MELVINA JOSE")
    print("-" * 50)

    # Initialize logging
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

    try:
        # Initialize PQC keys
        logging.info("[*] Initializing post-quantum cryptographic keys...")
        generate_dilithium_keys()
        logging.info("[+] PQC keys initialized successfully")

        # Initialize database
        init_database()
        logging.info("[+] Database initialized successfully")

        # Create honeypot manager
        manager = HoneypotManager()

        # Register services
        manager.add_service(HTTP_PORT, handle_http)
        manager.add_service(FTP_PORT, handle_ftp)
        manager.add_service(SMTP_PORT, handle_smtp)
        manager.add_service(SSH_PORT, handle_ssh)

        # Start Telegram bot in background
        telegram_thread = threading.Thread(target=start_telegram_bot, daemon=True)
        telegram_thread.start()
        logging.info("[+] Telegram bot started")

        # Start dashboard in background
        dashboard_thread = threading.Thread(target=start_dashboard, args=(DASHBOARD_PORT,), daemon=True)
        dashboard_thread.start()
        logging.info(f"[+] Dashboard started on port {DASHBOARD_PORT}")

        # Start all honeypot services
        logging.info("[*] Starting honeypot services...")
        manager.start_all()
        logging.info("[+] All services started successfully")

    except Exception as e:
        logging.error(f"[ERROR] Failed to start honeypot: {e}")
        raise

if __name__ == "__main__":
    main()