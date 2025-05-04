"""SMTP honeypot service handler"""
import logging
import base64
from ..utils.logging import log_attack

def handle_smtp(client_socket, client_address):
    """Handle SMTP connections and detect attacks"""
    ip = client_address[0]
    client_socket.send(b"220 mail.honeypot.com ESMTP Postfix\n")

    sender = recipient = None
    email_content = []

    while True:
        try:
            data = client_socket.recv(1024).decode(errors="ignore").strip()
            if not data:
                break

            # SMTP handshake
            if "EHLO" in data or "HELO" in data:
                client_socket.send(b"250-mail.honeypot.com Hello\n250-SIZE 52428800\n250 AUTH LOGIN PLAIN\n")

            # Brute force login loop
            elif "AUTH LOGIN" in data:
                while True:
                    client_socket.send(b"334 VXNlcm5hbWU6\n")  # "Username:" in Base64
                    username_b64 = client_socket.recv(1024).decode(errors="ignore").strip()
                    try:
                        username = base64.b64decode(username_b64).decode(errors="ignore")
                    except Exception:
                        username = "[INVALID BASE64]"

                    client_socket.send(b"334 UGFzc3dvcmQ6\n")  # "Password:" in Base64
                    password_b64 = client_socket.recv(1024).decode(errors="ignore").strip()
                    try:
                        password = base64.b64decode(password_b64).decode(errors="ignore")
                    except Exception:
                        password = "[INVALID BASE64]"

                    log_attack(ip, "SMTP", f"Brute Force Attempt: {username}:{password}", "Credential Harvesting")

                    # Simulate successful login for known credentials
                    if username == "test" and password == "password":
                        client_socket.send(b"235 Authentication successful\n")
                        log_attack(ip, "SMTP", f"SMTP AUTH SUCCESS: {username}:{password}", "Honeypot Login")
                        break

                    else:
                        client_socket.send(b"535 Authentication failed\n")

            # Capture MAIL FROM
            elif data.startswith("MAIL FROM:"):
                sender = data.split(":", 1)[1].strip()
                client_socket.send(b"250 OK\n")

            # Capture RCPT TO
            elif data.startswith("RCPT TO:"):
                recipient = data.split(":", 1)[1].strip()
                client_socket.send(b"250 OK\n")

            # Capture Email Content
            elif data.startswith("DATA"):
                client_socket.send(b"354 Start mail input; end with <CRLF>.<CRLF>\n")

                while True:
                    line = client_socket.recv(1024).decode(errors="ignore")
                    if line.strip() == ".":
                        break
                    if line:
                        email_content.append(line)

                full_email = "\n".join(email_content)
                log_attack(ip, "SMTP", f"Email from {sender} to {recipient}\n{full_email}", "Fake Email Sent")
                client_socket.send(b"250 OK: Message accepted\n")

            # VRFY (Verify User)
            elif data.startswith("VRFY"):
                client_socket.send(b"252 Cannot VRFY user but will accept message\n")

            # QUIT (End Connection)
            elif data.startswith("QUIT"):
                client_socket.send(b"221 Bye\n")
                break

            # Unknown Commands
            else:
                client_socket.send(b"500 Command not recognized\n")

        except Exception as e:
            logging.error(f"[SMTP ERROR] {e}")
            break

    client_socket.close()