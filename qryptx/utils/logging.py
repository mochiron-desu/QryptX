"""Logging utilities for the honeypot"""
import logging
import json
import time
import oqs
import base64
from datetime import datetime
import telebot
from ..config.config import BOT_TOKEN, CHAT_ID, LOG_FORMAT
from ..database.db_handler import log_attack_to_db
from .crypto import pqc_encrypt, pqc_sign

# Initialize Logging
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

# Initialize Telegram Bot
bot = telebot.TeleBot(BOT_TOKEN)

def log_attack(ip: str, service: str, data: str, exploit: str = "None") -> None:
    """
    Log an attack with encryption and notify via Telegram
    
    Args:
        ip (str): Attacker's IP address
        service (str): Service being attacked (HTTP, FTP, etc.)
        data (str): Attack payload or data
        exploit (str): Type of exploit attempted
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event_id = time.time()
    
    # Debug logging
    logging.debug(f"[DEBUG] Logging attack: {ip}, {service}, {data}, {exploit}")
    
    # Create log entry
    log_entry = f"[{service}] {ip} - {exploit} - {data} (Event ID: {event_id})"
    logging.info(log_entry)
    
    # Convert dict data to string if necessary
    if isinstance(data, dict):
        data = json.dumps(data)
    
    # Create plaintext for encryption
    plaintext = f"{timestamp} - {ip} - {service} - {data} - {exploit}"
    
    # Encrypt attack data
    encrypted_data = pqc_encrypt(plaintext)
    
    # Sign the encrypted log
    signature = pqc_sign(encrypted_data["ciphertext"])
    
    # Log to database
    log_attack_to_db(
        timestamp=timestamp,
        ip=ip,
        service=service,
        payload=data,
        exploit=exploit,
        encrypted_data=encrypted_data,
        signature=signature
    )
    
    # Send Telegram Alert
    telegram_message = (
        f"🚨 *Honeypot Alert* 🚨\n"
        f"🔹 *Time:* {timestamp}\n"
        f"🌍 *Attacker IP:* {ip}\n"
        f"🛠 *Service:* {service}\n"
        f"💥 *Exploit:* {exploit}\n"
        f"📜 *Payload:*\n```{data}```"
    )
    
    try:
        bot.send_message(CHAT_ID, telegram_message, parse_mode="Markdown")
    except Exception as e:
        logging.error(f"[TELEGRAM ERROR] Failed to send alert: {e}")

def start_telegram_bot():
    """Start the Telegram bot in polling mode"""
    print("Starting Telegram Bot...")
    bot.polling()

# Command handlers for Telegram bot
@bot.message_handler(commands=['stats'])
def send_stats(message):
    """Handle /stats command in Telegram"""
    from ..database.db_handler import get_attack_stats
    
    stats = get_attack_stats()
    response = (
        f"📊 *Honeypot Stats*:\n"
        f"🔹 *Total Attacks:* {stats['total_attacks']}\n"
        f"🔹 *Unique Attackers:* {stats['unique_ips']}\n"
        f"🔹 *Top Targeted Service:* {stats['top_service']}\n"
        f"🔹 *Latest Attack:* {stats['latest_attack']}"
    )
    bot.send_message(message.chat.id, response, parse_mode="Markdown")

@bot.message_handler(commands=['attacks'])
def send_recent_attacks(message):
    """Handle /attacks command in Telegram"""
    from ..database.db_handler import fetch_recent_attacks
    
    attacks = fetch_recent_attacks()
    if not attacks:
        bot.send_message(message.chat.id, "No attack logs available.")
        return
    
    response = "📡 *Recent Attacks:*\n"
    for attack in attacks:
        timestamp, ip, service, exploit, payload = attack
        response += (
            f"\n🕒 *Time:* {timestamp}\n"
            f"🌍 *IP:* {ip}\n"
            f"🛠 *Service:* {service}\n"
            f"💥 *Exploit:* {exploit}\n"
            f"📜 *Payload:*\n```{payload}```\n"
            f"———————————"
        )
    
    bot.send_message(message.chat.id, response, parse_mode="Markdown")