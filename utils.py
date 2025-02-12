import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from config import Config

def generate_salt():
    return os.urandom(16)

def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.b64encode(kdf.derive(password.encode()))

def hash_data(data, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    # Convert dictionary to string before encoding
    data_string = json.dumps(data)
    return base64.b64encode(kdf.derive(data_string.encode()))
def encrypt_data(data):
    f = Fernet(Config.ENCRYPTION_KEY)
    return f.encrypt(json.dumps(data).encode())

def decrypt_data(encrypted_data):
    f = Fernet(Config.ENCRYPTION_KEY)
    return json.loads(f.decrypt(encrypted_data))

def save_master_password(hashed_password, salt):
    data = {
        'password': base64.b64encode(hashed_password).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8')
    }
    encrypted_data = encrypt_data(data)
    
    with open(Config.MASTER_PASSWORD_FILE, 'wb') as f:
        f.write(encrypted_data)

def save_password_entry(title, hashed_data, salt):
    data = {
        'password': base64.b64encode(hashed_data).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8')
    }
    encrypted_data = encrypt_data(data)

    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(Config.PASSWORDS_FILE), exist_ok=True)

    with open(Config.PASSWORDS_FILE, 'ab') as f:
        # Write as bytes with proper encoding
        entry = f"{title}: {encrypted_data.decode('utf-8')}\n"
        f.write(entry.encode('utf-8'))

def verify_master_password(password):
    if not os.path.exists(Config.MASTER_PASSWORD_FILE):
        return False
        
    with open(Config.MASTER_PASSWORD_FILE, 'rb') as f:
        encrypted_data = f.read()
    
    data = decrypt_data(encrypted_data)
    stored_password = base64.b64decode(data['password'].encode('utf-8'))
    salt = base64.b64decode(data['salt'].encode('utf-8'))
    
    return hash_password(password, salt) == stored_password
