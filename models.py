from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import json
from config import Config

class PasswordEntry:
    def __init__(self, title, username, password, url="", notes=""):
        self.id = base64.urlsafe_b64encode(os.urandom(8)).decode('utf-8')
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.notes = notes
        self.created_at = datetime.utcnow().isoformat()
        self.updated_at = self.created_at
        self.salt = os.urandom(16)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'username': self.username,
            'password': self.password,
            'url': self.url,
            'notes': self.notes,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'salt': base64.b64encode(self.salt).decode('utf-8')
        }

class PasswordManager:
    def __init__(self, master_key):
        self.passwords_file = 'instance/passwords.json'
        self.master_key = master_key
        self._ensure_passwords_file()

    def _ensure_passwords_file(self):
        if not os.path.exists(self.passwords_file):
            self._save_passwords({})

    def _encrypt_data(self, data):
        f = Fernet(Config.ENCRYPTION_KEY)
        return f.encrypt(json.dumps(data).encode())

    def _decrypt_data(self, encrypted_data):
        f = Fernet(Config.ENCRYPTION_KEY)
        return json.loads(f.decrypt(encrypted_data))

    def _save_passwords(self, passwords):
        encrypted_data = self._encrypt_data(passwords)
        with open(self.passwords_file, 'wb') as f:
            f.write(encrypted_data)

    def _load_passwords(self):
        with open(self.passwords_file, 'rb') as f:
            encrypted_data = f.read()
        return self._decrypt_data(encrypted_data)

    def add_password(self, title, username, password, url="", notes=""):
        entry = PasswordEntry(title, username, password, url, notes)
        passwords = self._load_passwords()
        passwords[entry.id] = entry.to_dict()
        self._save_passwords(passwords)
        return entry.id

    def get_password(self, password_id):
        passwords = self._load_passwords()
        return passwords.get(password_id)

    def get_all_passwords(self):
        return self._load_passwords()

    def update_password(self, password_id, **kwargs):
        passwords = self._load_passwords()
        if password_id not in passwords:
            return False
        
        entry = passwords[password_id]
        for key, value in kwargs.items():
            if key in entry:
                entry[key] = value
        entry['updated_at'] = datetime.utcnow().isoformat()
        
        self._save_passwords(passwords)
        return True

    def delete_password(self, password_id):
        passwords = self._load_passwords()
        if password_id not in passwords:
            return False
        
        del passwords[password_id]
        self._save_passwords(passwords)
        return True
