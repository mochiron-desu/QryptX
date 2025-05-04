"""Core honeypot functionality and base classes"""
import logging
import socket
import threading
from typing import Dict, Callable

class HoneypotService:
    def __init__(self, port: int, handler: Callable):
        self.port = port
        self.handler = handler
        
    def start(self):
        """Start the honeypot service on the specified port"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", self.port))
            server.listen(5)
            logging.info(f"[*] {self.handler.__name__.split('_')[1].upper()} listening on port {self.port}")

            while True:
                client_socket, client_address = server.accept()
                logging.info(f"[+] {client_address[0]} connected on port {self.port}")
                threading.Thread(target=self.handler, args=(client_socket, client_address)).start()
        except Exception as e:
            logging.error(f"[ERROR] Port {self.port} failed: {e}")

class HoneypotManager:
    def __init__(self):
        self.services: Dict[int, HoneypotService] = {}
        
    def add_service(self, port: int, handler: Callable):
        """Add a new service to the honeypot"""
        self.services[port] = HoneypotService(port, handler)
        
    def start_all(self):
        """Start all registered honeypot services"""
        for service in self.services.values():
            threading.Thread(target=service.start).start()