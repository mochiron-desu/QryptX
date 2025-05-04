"""Database handler for attack logging and retrieval"""
import sqlite3
import logging
from typing import List, Dict, Tuple, Optional
from ..config.config import DB_FILE

def init_database():
    """Initialize the SQLite database and create necessary tables"""
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
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
        conn.close()
    except Exception as e:
        logging.error(f"[DB ERROR] Failed to initialize database: {e}")
        raise

def log_attack_to_db(timestamp: str, ip: str, service: str, payload: str, 
                     exploit: str, encrypted_data: Dict[str, str], signature: str) -> None:
    """Log an attack to the database with encrypted data"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attacks (
                timestamp, ip, service, payload, exploit, 
                encrypted_log, tag, nonce, ciphertext_pqc, 
                public_key, private_key, signature
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, ip, service, payload, exploit,
            encrypted_data["ciphertext"],
            encrypted_data["tag"],
            encrypted_data["nonce"],
            encrypted_data["ciphertext_pqc"],
            encrypted_data["public_key"],
            encrypted_data["private_key"],
            signature
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"[DB ERROR] Failed to log attack: {e}")

def fetch_recent_attacks(limit: int = 5) -> List[Tuple]:
    """Fetch the most recent attacks from the database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT timestamp, ip, service, exploit, payload 
            FROM attacks 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (limit,))
        attacks = cursor.fetchall()
        conn.close()
        return attacks
    except Exception as e:
        logging.error(f"[DB ERROR] Failed to fetch recent attacks: {e}")
        return []

def get_attack_stats() -> Dict[str, any]:
    """Get statistics about recorded attacks"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Total attacks
        cursor.execute("SELECT COUNT(*) FROM attacks")
        total_attacks = cursor.fetchone()[0]
        
        # Unique IPs
        cursor.execute("SELECT COUNT(DISTINCT ip) FROM attacks")
        unique_ips = cursor.fetchone()[0]
        
        # Top targeted service
        cursor.execute("""
            SELECT service, COUNT(*) as count 
            FROM attacks 
            GROUP BY service 
            ORDER BY count DESC 
            LIMIT 1
        """)
        top_service_result = cursor.fetchone()
        top_service = top_service_result[0] if top_service_result else "None"
        
        # Latest attack timestamp
        cursor.execute("SELECT timestamp FROM attacks ORDER BY timestamp DESC LIMIT 1")
        latest_result = cursor.fetchone()
        latest_attack = latest_result[0] if latest_result else "None"
        
        conn.close()
        
        return {
            "total_attacks": total_attacks,
            "unique_ips": unique_ips,
            "top_service": top_service,
            "latest_attack": latest_attack
        }
    except Exception as e:
        logging.error(f"[DB ERROR] Failed to get attack stats: {e}")
        return {
            "total_attacks": 0,
            "unique_ips": 0,
            "top_service": "Unknown",
            "latest_attack": "Unknown"
        }