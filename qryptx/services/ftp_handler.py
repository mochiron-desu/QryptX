"""FTP honeypot service handler"""
import logging
from ..utils.logging import log_attack
from ..config.config import VALID_FTP_USERS, FAKE_FILES

def handle_ftp(client_socket, client_address):
    """Handle FTP connections and detect attacks"""
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