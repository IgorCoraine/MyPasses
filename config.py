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
    MASTER_PASSWORD_FILE = os.getenv('MASTER_PASSWORD_FILE') # Master password storage
    PASSWORDS_FILE = os.getenv('PASSWORDS_FILE')  # User passwords storage
    URLS_MONITOR_FILE = os.getenv('URLS_MONITOR_FILE')  # URLs for security monitoring
    
    # Session Settings
    SESSION_TIMEOUT = 300 # Session timeout 
