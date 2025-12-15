
from cipher.aes import AESCipher
from cipher.des import DESCipher
from cipher.rsa import RSACipher


class CipherFactory:
    METHODS = {
        'aes': 'AES-128',
        'des': 'DES',
        'rsa': 'RSA'
    }

    @staticmethod
    def encrypt(text: str, method: str, key, use_library: bool = True) -> str:
        if method == 'aes':
            return AESCipher.encrypt(text, key, use_library)
        elif method == 'des':
            return DESCipher.encrypt(text, key, use_library)
        elif method == 'rsa':
            return RSACipher.encrypt(text, key, use_library)
        else:
            raise ValueError(f"Bilinmeyen şifreleme yöntemi: {method}")

    @staticmethod
    def decrypt(text: str, method: str, key, use_library: bool = True) -> str:
        if method == 'aes':
            return AESCipher.decrypt(text, key, use_library)
        elif method == 'des':
            return DESCipher.decrypt(text, key, use_library)
        elif method == 'rsa':
            return RSACipher.decrypt(text, key, use_library)
        else:
            raise ValueError(f"Bilinmeyen şifreleme yöntemi: {method}")


