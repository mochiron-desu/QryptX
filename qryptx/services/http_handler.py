"""HTTP honeypot service handler"""
import logging
import re
from urllib.parse import unquote_plus
from ..utils.logging import log_attack
from ..config.config import (
    VALID_HTTP_USERNAME,
    VALID_HTTP_PASSWORD,
    SQLI_PATTERNS
)
from ..utils.templates import (
    LOGIN_PAGE_TEMPLATE,
    ADMIN_PANEL,
    ACCESS_DENIED
)

def handle_http(client_socket, client_address):
    """Handle HTTP connections and detect attacks"""
    ip = client_address[0]
    
    try:
        request = client_socket.recv(4096).decode("utf-8", errors="ignore")
        if not request:
            return

        if "GET /" in request:
            response = LOGIN_PAGE_TEMPLATE.format(error_message="")

        elif "POST /login" in request:
            try:
                post_data = request.split("\r\n\r\n", 1)[1].strip()
                logging.info(f"[DEBUG] Raw POST Data from {ip}: {post_data}")

                if not post_data:
                    raise ValueError("POST data is empty")

                post_params = {}
                for param in post_data.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        post_params[key] = unquote_plus(value)
                
                username = post_params.get("username", "").strip()
                password = post_params.get("password", "").strip()

                # Check for SQL Injection
                for pattern in SQLI_PATTERNS:
                    if re.search(pattern, username, re.IGNORECASE) or re.search(pattern, password, re.IGNORECASE):
                        log_attack(ip, "HTTP", f"SQL Injection Attempt: {username}:{password}", "SQLi")
                        response = ACCESS_DENIED
                        break
                else:  # Only runs if no SQLi detected
                    if username == VALID_HTTP_USERNAME and password == VALID_HTTP_PASSWORD:
                        log_attack(ip, "HTTP", f"Successful Fake Login: {username}:{password}", "Credential Theft")
                        response = ADMIN_PANEL
                    else:
                        log_attack(ip, "HTTP", f"Failed Login Attempt: {username}:{password}", "Brute Force")
                        response = LOGIN_PAGE_TEMPLATE.format(error_message="incorrect")

            except Exception as e:
                response = ACCESS_DENIED
                logging.error(f"[HTTP ERROR] Login parsing failed: {e}")

        else:
            response = "HTTP/1.1 404 Not Found\n\n<h1>404 Page Not Found</h1>"

        client_socket.send(response.encode())
        client_socket.close()

    except Exception as e:
        logging.error(f"[HTTP ERROR] Unexpected error: {e}")