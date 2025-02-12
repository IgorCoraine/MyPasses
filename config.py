from cryptography.fernet import Fernet
import os

class Config:
    SECRET_KEY = os.urandom(32)
    MASTER_PASSWORD_FILE = 'instance/master.json'
    ENCRYPTION_KEY = Fernet.generate_key()
    PASSWORDS_FILE = 'instance/keys.keys'  
