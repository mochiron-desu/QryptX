# QryptX Honeypot
POST-QUANTUM CRYPTOGRAPHIC HONEYPOT FOR SECURE THREAT INTELLIGENCE AND INTRUSION LOGGING 

## Overview

QryptX is an advanced honeypot system that simulates multiple network services to detect, track, and analyze potential cyber attacks. It leverages post-quantum cryptography (PQC) to securely log and store attack data, making it future-proof against quantum computing threats.

## Features

- **Multi-Service Honeypot**: Simulates HTTP, FTP, SMTP, and SSH services
- **Post-Quantum Cryptography**: Uses Kyber1024 for key encapsulation and Dilithium5 for digital signatures
- **Encrypted Logging**: All attack data is encrypted and digitally signed 
- **Real-time Alerts**: Integration with Telegram for instant attack notifications
- **Interactive Dashboard**: Web-based UI to monitor and analyze attack data
- **Fake File System**: Realistic Linux environment to engage attackers
- **SQLite Database**: Persistent storage of attack information

## Requirements

- Python 3.8+
- SQLite3
- Required Python packages:
  - paramiko
  - pyfiglet
  - oqs (Open Quantum Safe)
  - pycryptodome
  - telebot
  - requests

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/fiyanmehfil/QryptX.git
   ```

2. Install dependencies:
   ```
   pip install paramiko pyfiglet oqs-python pycryptodome pyTelegramBotAPI requests
   ```

3. Configure Telegram alerts:
   - Create a Telegram bot via BotFather
   - Update the `BOT_TOKEN` and `CHAT_ID` variables in the script

4. Run the honeypot:
   ```
   sudo $(which python3) QryptX.py
   ```
![WhatsApp Image 2025-04-08 at 02 40 23_3c452913](https://github.com/user-attachments/assets/f177cf81-1864-4cdc-b6b4-8e767ec2f215)

   

## Port Configuration

QryptX runs the following services by default:

- HTTP: Port 80
- FTP: Port 21
- SMTP: Port 25
- SSH: Port 22
- Dashboard: Port 8080

## Dashboard

Access the dashboard by navigating to `http://localhost:8080` in your web browser. The dashboard provides:

- Real-time statistics on attack attempts
- Detailed logs of each attack
- Visual representations of attack patterns
- Geographic distribution of attackers

![WhatsApp Image 2025-04-08 at 02 41 42_6770f113](https://github.com/user-attachments/assets/8808ad0c-c16d-47de-b2f7-cf2617deeb9e)

## Telegram Integration

QryptX integrates with Telegram to provide real-time alerts and command functionality:

<img src="https://github.com/user-attachments/assets/c5e7fbdb-f76d-4316-ac25-82cfada31c9e" alt="WhatsApp Image 2025-04-02 at 04 42 29_7658c9db" width="22%"/>



- `/stats`: Get current honeypot statistics
<img src="https://github.com/user-attachments/assets/fbcb55c2-ba56-4504-be1d-64a64ba8ed10" alt="WhatsApp Image 2025-04-02 at 04 42 29_a3e777c5" width="22%"/>

- `/attacks`: View recent attac k attempts
<img src="https://github.com/user-attachments/assets/a0d9a534-3c5e-405e-be98-97f3f0bc1224" alt="WhatsApp Image 2025-04-02 at 04 42 29_44256652" width="22%"/>

## Security Features

### Post-Quantum Cryptography

QryptX implements post-quantum cryptographic algorithms to ensure that captured data remains secure even against future quantum computer attacks:

- **Kyber1024**: Used for key encapsulation
- **Dilithium5**: Used for digital signatures
- **AES-GCM**: Used for symmetric encryption of log data

### Secure Logging

All attack data is:
1. Encrypted using a hybrid PQC-AES scheme
2. Digitally signed with Dilithium
3. Stored in a local SQLite database

## Fake Services

### SSH Server
- Simulates a Linux environment
- Provides a fake file system with common directories
- Implements basic shell commands (ls, cd, cat, etc.)
- Detects privilege escalation attempts

### HTTP Server
- Simulates a corporate login portal
- Detects SQL injection attempts
- Presents a fake admin panel on successful login

### FTP Server
- Simulates file listings and transfers
- Captures authentication attempts

### SMTP Server
- Simulates an email server
- Captures email content and authentication attempts

## Attack Detection

QryptX is designed to detect various types of attacks, including:

- Brute force login attempts
- SQL injection
- Command injection
- Privilege escalation
- Data exfiltration
- File upload attempts
- Reconnaissance activities

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Legal Disclaimer

QryptX is designed for educational and defensive security research only. Users must ensure they comply with all applicable laws and regulations when deploying this honeypot. Do not deploy on production systems without understanding the potential implications.

