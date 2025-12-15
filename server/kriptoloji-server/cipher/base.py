
try:
    from Crypto.Cipher import AES, DES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    LIBRARY_MODE_AVAILABLE = True
except ImportError:
    LIBRARY_MODE_AVAILABLE = False
    AES = None
    DES = None
    pad = None
    unpad = None
    get_random_bytes = None
    RSA = None
    PKCS1_OAEP = None
    SHA256 = None
    print("⚠️  Kriptografi kütüphaneleri bulunamadı. Sadece manuel mod kullanılabilir.")

__all__ = [
    'LIBRARY_MODE_AVAILABLE',
    'AES',
    'DES',
    'pad',
    'unpad',
    'get_random_bytes',
    'RSA',
    'PKCS1_OAEP',
    'SHA256'
]

