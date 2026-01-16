import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'True') == 'True'
    
    # Tor Configuration
    TOR_PROXY_HOST = os.getenv('TOR_PROXY_HOST', '127.0.0.1')
    TOR_PROXY_PORT = int(os.getenv('TOR_PROXY_PORT', 9050))
    TOR_CONTROL_PORT = int(os.getenv('TOR_CONTROL_PORT', 9051))
    TOR_PASSWORD = os.getenv('TOR_PASSWORD', '')
    
    # Scanner Settings
    MAX_SCAN_DEPTH = int(os.getenv('MAX_SCAN_DEPTH', 5))
    SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', 30))
    MAX_THREADS = int(os.getenv('MAX_THREADS', 10))
