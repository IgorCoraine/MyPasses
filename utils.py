"""
Utility functions for MyPasses application.
Handles cryptographic operations, password management, and security checks.
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
from config import Config
import secrets, base64, hashlib  
import os, string, json, requests, fcntl
from filelock import FileLock

# Cryptographic Functions
def generate_salt() -> bytes:
    """Generate random salt for password hashing."""
    return os.urandom(16)

def hash_password(password: str, salt: bytes) -> bytes:
    """Hash password using PBKDF2 with SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.b64encode(kdf.derive(password.encode()))

def hash_data(data: dict, salt: bytes) -> bytes:
    """Hash dictionary data using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    data_string = json.dumps(data)
    return base64.b64encode(kdf.derive(data_string.encode()))

def get_encryption_key(password: str | bytes, salt: bytes) -> bytes:
    """Generate encryption key from password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    if isinstance(password, str):
        password = password.encode()
    return base64.b64encode(kdf.derive(password))

# Data Encryption Functions
def encrypt_data(data: dict, password: str, salt: bytes) -> bytes:
    """Encrypt data using Fernet symmetric encryption."""
    key = get_encryption_key(password, salt)
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode())

def decrypt_data(encrypted_data: bytes, password: str, salt: bytes) -> dict:
    """Decrypt data using Fernet symmetric encryption."""
    key = get_encryption_key(password, salt)
    f = Fernet(key)
    return json.loads(f.decrypt(encrypted_data))

# File management functions
def with_file_lock(filename):
    def decorator(func):
        def wrapper(*args, **kwargs):
            lock = FileLock(filename + ".lock")
            with lock:
                return func(*args, **kwargs)
        return wrapper
    return decorator

# Password Management Functions
def save_password_entry(title: str, data: dict, master_password: str) -> None:
    """Save encrypted password entry with its salt."""
    salt = generate_salt()  # Gera salt único
    encrypted_data = encrypt_data(data, master_password, salt)
    
    entry_data = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'data': encrypted_data.decode('utf-8')
    }
    
    os.makedirs(os.path.dirname(Config.PASSWORDS_FILE), exist_ok=True)
    with open(Config.PASSWORDS_FILE, 'ab') as f:
        entry = f"{title}: {json.dumps(entry_data)}\n"
        f.write(entry.encode('utf-8'))

@with_file_lock(Config.MASTER_PASSWORD_FILE)
def verify_master_password(username: str, password: str) -> bool:
    if not os.path.exists(Config.MASTER_PASSWORD_FILE):
        return False
        
    with open(Config.MASTER_PASSWORD_FILE, 'rb') as f:
        stored_data = json.loads(f.read())

    for entry in stored_data.values():
        try:
            salt = base64.b64decode(entry['salt'])
            key = Fernet(get_encryption_key(password, salt))
            
            decrypted_username = json.loads(key.decrypt(entry['encrypted_username'].encode()))
            if decrypted_username == username:
                decrypted_data = json.loads(key.decrypt(entry['encrypted_data'].encode()))
                stored_password = base64.b64decode(decrypted_data['password'])
                test_password = hash_password(password, salt)
                return stored_password == test_password
        except Exception:
            continue
            
    return False

@with_file_lock(Config.MASTER_PASSWORD_FILE)
def save_master_password(username: str, password: str, salt: bytes) -> None:
    """Save master password hash and salt."""
    hashed_password = hash_password(password, salt)
    data = {
        'password': base64.b64encode(hashed_password).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8')
    }
    
    # Store salt separately for verification
    entry = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'encrypted_data': Fernet(get_encryption_key(password, salt)).encrypt(json.dumps(data).encode()).decode('utf-8'),
        'encrypted_username': Fernet(get_encryption_key(password, salt)).encrypt(json.dumps(username).encode()).decode('utf-8')
    }

    existing_data = {}
    if os.path.exists(Config.MASTER_PASSWORD_FILE):
        with open(Config.MASTER_PASSWORD_FILE, 'rb') as f:
            existing_data = json.loads(f.read())
    
    existing_data[entry['encrypted_username']] = entry
    
    with open(Config.MASTER_PASSWORD_FILE, 'wb') as f:
        f.write(json.dumps(existing_data).encode())

def get_stored_passwords(password: str) -> list:
    """Retrieve and decrypt stored passwords using their unique salts."""
    if not os.path.exists(Config.PASSWORDS_FILE):
        return []
        
    passwords = []
    with open(Config.PASSWORDS_FILE, 'rb') as f:
        for line in f:
            if line.strip():
                title, entry_data = line.decode('utf-8').strip().split(': ', 1)
                entry = json.loads(entry_data)
                salt = base64.b64decode(entry['salt'])
                encrypted_bytes = entry['data'].encode('utf-8')
                
                try:
                    decrypted_data = decrypt_data(encrypted_bytes, password, salt)
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

def generate_random_password(length: int = 32) -> str:
    """Generate cryptographically secure random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def save_passwords(passwords: list, master_password: str, salt: bytes) -> None:
    """Save updated password list to storage."""
    key = Fernet(get_encryption_key(master_password, salt))
    with open(Config.PASSWORDS_FILE, 'wb') as f:
        for entry in passwords:
            title = entry['title']
            encrypted_data = key.encrypt(json.dumps({
                'username': entry['username'],
                'password': entry['password'],
                'url': entry['url'],
                'notes': entry['notes']
            }).encode('utf-8'))
            f.write(f"{title}: {encrypted_data.decode('utf-8')}\n".encode('utf-8'))

# URL Monitoring Functions
def save_url_to_monitor(url: str) -> None:
    """Add URL to monitoring list."""
    if not url:
        return
        
    os.makedirs(os.path.dirname(Config.URLS_MONITOR_FILE), exist_ok=True)
    with open(Config.URLS_MONITOR_FILE, 'a') as f:
        f.write(f"{url}\n")

def delete_url_from_monitor(url: str) -> None:
    """Remove URL from monitoring list."""
    with open(Config.URLS_MONITOR_FILE, 'r') as f:
        lines = f.readlines()

    with open(Config.URLS_MONITOR_FILE, 'w') as f:
        for line in lines:
            if line.strip() != url:
                f.write(line)

def check_password_pwned(data_list: list) -> list:
    """Check if passwords have been compromised using HIBP API."""
    pwned_items = []
    for item in data_list:
        password = item['password']
        hashed_password = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = hashed_password[:5], hashed_password[5:]
        api_url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(api_url)

        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for hash_suffix, count in hashes:
                if hash_suffix == suffix:
                    pwned_items.append(item)
                    break
    
    return pwned_items