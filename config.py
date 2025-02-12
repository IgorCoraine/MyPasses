from cryptography.fernet import Fernet
import os

class Config:
    SECRET_KEY = os.urandom(32)
    MASTER_PASSWORD_FILE = 'instance/master.json'
    PASSWORDS_FILE = 'instance/keys.keys'  
