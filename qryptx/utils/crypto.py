"""Cryptographic utilities using post-quantum cryptography"""
import os
import base64
from Crypto.Cipher import AES
import oqs
from ..config.config import (
    DILITHIUM_PRIVATE_KEY,
    DILITHIUM_PUBLIC_KEY
)

def generate_dilithium_keys():
    """Generate Dilithium signature keys if they don't exist"""
    try:
        with open(DILITHIUM_PRIVATE_KEY, "rb") as f:
            dilithium_private_key = f.read()
        with open(DILITHIUM_PUBLIC_KEY, "rb") as f:
            dilithium_public_key = f.read()
    except FileNotFoundError:
        # Create a signer using Dilithium5
        with oqs.Signature("Dilithium5") as signer:
            dilithium_public_key = signer.generate_keypair()
            dilithium_private_key = signer.export_secret_key()
            
            # Save the keys
            os.makedirs(os.path.dirname(DILITHIUM_PRIVATE_KEY), exist_ok=True)
            with open(DILITHIUM_PRIVATE_KEY, "wb") as f:
                f.write(dilithium_private_key)
            with open(DILITHIUM_PUBLIC_KEY, "wb") as f:
                f.write(dilithium_public_key)
    
    return dilithium_public_key, dilithium_private_key

def pqc_encrypt(data):
    """Encrypt data using Kyber1024 for key encapsulation and AES-GCM for data encryption"""
    # Initialize Kyber1024 for key encapsulation
    with oqs.KeyEncapsulation("Kyber1024") as kem:
        # Generate keypair
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        
        # Generate shared secret and ciphertext
        ciphertext_pqc, shared_secret = kem.encap_secret(public_key)
        
        # Use shared_secret as AES key (trimmed to 32 bytes for AES-256)
        aes_key = shared_secret[:32]
        
        # AES Encryption
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext_aes, tag = cipher.encrypt_and_digest(data.encode())
        
        # Encode all parameters in base64
        return {
            "ciphertext": base64.b64encode(ciphertext_aes).decode(),
            "tag": base64.b64encode(tag).decode(),
            "nonce": base64.b64encode(cipher.nonce).decode(),
            "ciphertext_pqc": base64.b64encode(ciphertext_pqc).decode(),
            "public_key": base64.b64encode(public_key).decode(),
            "private_key": base64.b64encode(private_key).decode()
        }

def pqc_sign(data):
    """Digitally sign data using Dilithium"""
    try:
        with open(DILITHIUM_PRIVATE_KEY, "rb") as f:
            dilithium_private_key = f.read()
            
        # Create a signer with the private key
        with oqs.Signature("Dilithium5", secret_key=dilithium_private_key) as signer:
            # Sign the data and return base64 encoded signature
            signature = signer.sign(data.encode())
            return base64.b64encode(signature).decode()
    except Exception as e:
        print(f"[ERROR] Failed to sign data: {e}")
        return None

# Initialize PQC keys when module is imported
generate_dilithium_keys()