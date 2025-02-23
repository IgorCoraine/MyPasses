"""
Configuration module for MyPasses application.
Defines application-wide settings and constants.
"""

from cryptography.fernet import Fernet
import os

class Config:
    """Application configuration settings."""
    
    # Security Settings
    SECRET_KEY = os.urandom(32)  # Random secret key for session management
    
    # File Paths
    MASTER_PASSWORD_FILE = 'instance/master.json'  # Master password storage
    PASSWORDS_FILE = 'instance/keys.keys'  # User passwords storage
    URLS_MONITOR_FILE = 'data/urls_to_monitor.txt'  # URLs for security monitoring
    
    # Session Settings
    SESSION_TIMEOUT = 300  # Session timeout in seconds (5 minutes)
