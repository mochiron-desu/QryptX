"""Dashboard web interface handler"""
import logging
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from ..database.db_handler import fetch_recent_attacks, get_attack_stats
from ..utils.templates import DASHBOARD_HTML

class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the honeypot dashboard"""

    def do_GET(self):
        """Handle GET requests"""
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        
        if path == "/api/attacks":
            self.handle_api_attacks()
        elif path == "/api/stats":
            self.handle_api_stats()
        elif path == "/" or path == "/dashboard":
            self.serve_dashboard()
        else:
            self.send_error(404, "Not Found")
    
    def serve_dashboard(self):
        """Serve the main dashboard HTML page"""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(DASHBOARD_HTML.encode())
    
    def handle_api_attacks(self):
        """Handle API requests for attack data"""
        try:
            attacks = fetch_recent_attacks(20)  # Get last 20 attacks
            
            # Format attacks for JSON response
            attack_data = []
            for attack in attacks:
                timestamp, ip, service, exploit, payload = attack
                attack_data.append({
                    "timestamp": timestamp,
                    "ip": ip,
                    "service": service,
                    "exploit": exploit,
                    "payload": payload
                })
            
            # Send JSON response
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(attack_data).encode())
            
        except Exception as e:
            logging.error(f"[DASHBOARD API ERROR] {e}")
            self.send_error(500, str(e))

    def handle_api_stats(self):
        """Handle API requests for statistics"""
        try:
            stats = get_attack_stats()
            
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(stats).encode())
            
        except Exception as e:
            logging.error(f"[DASHBOARD STATS ERROR] {e}")
            self.send_error(500, str(e))

def start_dashboard(port=8080):
    """Start the dashboard web server"""
    try:
        server = HTTPServer(("0.0.0.0", port), DashboardHandler)
        logging.info(f"[*] Dashboard listening on port {port}")
        server.serve_forever()
    except Exception as e:
        logging.error(f"[DASHBOARD ERROR] Port {port} failed: {e}")
        raise