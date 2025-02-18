from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
from config import Config
import secrets, base64, hashlib  
import os, string, json, requests

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

def generate_random_password(length=32):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

# Função para salvar as senhas atualizadas no arquivo
def save_passwords(passwords, master_password, salt):
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

def save_url_to_monitor(url):
    if not url:
        return
        
    os.makedirs(os.path.dirname(Config.URLS_MONITOR_FILE), exist_ok=True)
    with open(Config.URLS_MONITOR_FILE, 'a') as f:
        f.write(f"{url}\n")

def delete_url_from_monitor(url):
    # Read all lines from the URL monitor file
    with open(Config.URLS_MONITOR_FILE, 'r') as f:
        lines = f.readlines()

    # Filter out the URL associated with the title
    with open(Config.URLS_MONITOR_FILE, 'w') as f:
        for line in lines:
            if line.strip() == url:
                continue  # Skip the URL to be deleted
            f.write(line)

def check_password_pwned(data_list):
    """Check if a password has been pwned using Have I Been Pwned API v3."""
    pwned_itens = []
    for item in data_list:
        password = item['password']
        hashed_password = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = hashed_password[:5], hashed_password[5:]
        api_url =f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(api_url)

        if response.status_code != 200:
            print(f"Error fetching data from Have I Been Pwned API: {response.status_code}")
        else:
            # Check if the hash suffix appears in the response
            hashes = (line.split(':') for line in response.text.splitlines())
            for hash, count in hashes:
                if hash == suffix:
                    pwned_itens.append(item)
    print(pwned_itens)
    return pwned_itens