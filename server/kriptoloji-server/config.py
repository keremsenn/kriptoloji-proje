
import os

class Config:
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5000))
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    

    DEFAULT_METHOD = 'aes'
    DEFAULT_USE_LIBRARY = True
    

    RSA_KEY_SIZE = 2048

    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

    WEBSOCKET_TIMEOUT = 30


