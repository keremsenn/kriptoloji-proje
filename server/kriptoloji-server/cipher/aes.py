import base64
import hashlib
from cipher.base import LIBRARY_MODE_AVAILABLE, AES, pad, unpad

class AESCipher:

    @staticmethod
    def _ensure_key(key) -> bytes:
        if isinstance(key, str):
            key_bytes = hashlib.md5(key.encode()).digest()
        elif isinstance(key, bytes):
            key_bytes = key[:16] if len(key) >= 16 else key.ljust(16, b'\0')
        else:
            raise ValueError("AES anahtarı string veya bytes olmalı")
        return key_bytes[:16]

    @staticmethod
    def encrypt(text: str, key, use_library: bool = True) -> str:
        key_bytes = AESCipher._ensure_key(key)
        text_bytes = text.encode('utf-8')

        if use_library and LIBRARY_MODE_AVAILABLE:
            return AESCipher._encrypt_library(text_bytes, key_bytes)
        else:
            return AESCipher._encrypt_manual(text_bytes, key_bytes)

    @staticmethod
    def decrypt(ciphertext: str, key, use_library: bool = True) -> str:
        key_bytes = AESCipher._ensure_key(key)

        if use_library and LIBRARY_MODE_AVAILABLE:
            return AESCipher._decrypt_library(ciphertext, key_bytes)
        else:
            return AESCipher._decrypt_manual(ciphertext, key_bytes)

    @staticmethod
    def _encrypt_library(text_bytes: bytes, key: bytes) -> str:
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        padded_text = pad(text_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    @staticmethod
    def _decrypt_library(ciphertext: str, key: bytes) -> str:
        data = base64.b64decode(ciphertext)
        iv = data[:16]
        encrypted = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode('utf-8')

    @staticmethod
    def _encrypt_manual(text_bytes: bytes, key: bytes) -> str:
        result = bytes(b ^ key[i % len(key)] for i, b in enumerate(text_bytes))
        return base64.b64encode(result).decode('utf-8')

    @staticmethod
    def _decrypt_manual(ciphertext: str, key: bytes) -> str:
        data = base64.b64decode(ciphertext)
        result = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        return result.decode('utf-8')