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

def get_encryption_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    # Handle both string and bytes input
    if isinstance(password, str):
        password = password.encode()
    return base64.b64encode(kdf.derive(password))

def encrypt_data(data, password, salt):
    key = get_encryption_key(password, salt)
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode())

def decrypt_data(encrypted_data, password, salt):
    key = get_encryption_key(password, salt)
    f = Fernet(key)
    return json.loads(f.decrypt(encrypted_data))

def save_password_entry(title, data, master_password, salt):
    encrypted_data = encrypt_data(data, master_password, salt)

    os.makedirs(os.path.dirname(Config.PASSWORDS_FILE), exist_ok=True)

    with open(Config.PASSWORDS_FILE, 'ab') as f:
        entry = f"{title}: {encrypted_data.decode('utf-8')}\n"
        f.write(entry.encode('utf-8'))

def verify_master_password(password):
    if not os.path.exists(Config.MASTER_PASSWORD_FILE):
        return False
        
    with open(Config.MASTER_PASSWORD_FILE, 'rb') as f:
        encrypted_data = f.read()
    
    # First decrypt using master password to get the stored salt
    key = Fernet(get_encryption_key(password, b'initial_salt'))
    try:
        decrypted_data = json.loads(key.decrypt(encrypted_data))
        stored_salt = base64.b64decode(decrypted_data['salt'].encode('utf-8'))
        stored_password = base64.b64decode(decrypted_data['password'].encode('utf-8'))
        
        # Verify using the stored salt
        test_hash = hash_password(password, stored_salt)
        return test_hash == stored_password
    except:
        return False

def save_master_password(password, salt):
    hashed_password = hash_password(password, salt)
    data = {
        'password': base64.b64encode(hashed_password).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8')
    }
    
    key = Fernet(get_encryption_key(password, b'initial_salt'))
    encrypted_data = key.encrypt(json.dumps(data).encode())
    
    with open(Config.MASTER_PASSWORD_FILE, 'wb') as f:
        f.write(encrypted_data)
    
def get_stored_passwords(password, salt):
    if not os.path.exists(Config.PASSWORDS_FILE):
        return []
        
    passwords = []
    # Use the same key derivation as when saving
    key = Fernet(get_encryption_key(password, b'initial_salt'))
    
    with open(Config.PASSWORDS_FILE, 'rb') as f:
        for line in f:
            if line.strip():
                title, encrypted_data = line.decode('utf-8').strip().split(': ', 1)
                encrypted_bytes = encrypted_data.encode('utf-8')
                try:
                    decrypted_data = json.loads(key.decrypt(encrypted_bytes))
                    stored_data = {
                        'title': title,
                        'username': decrypted_data['username'],
                        'password': decrypted_data['password'],
                        'url': decrypted_data['url'],
                        'notes': decrypted_data['notes']
                    }
                    passwords.append(stored_data)
                except:
                    continue
    return passwords
