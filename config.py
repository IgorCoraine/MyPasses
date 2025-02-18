from cryptography.fernet import Fernet
import os

class Config:
    SECRET_KEY = os.urandom(32)
    MASTER_PASSWORD_FILE = 'instance/master.json'
    PASSWORDS_FILE = 'instance/keys.keys'  
    SESSION_TIMEOUT = 300  # 5 minutes in seconds
    URLS_MONITOR_FILE = 'data/urls_to_monitor.txt'
