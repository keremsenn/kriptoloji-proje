
import base64
import hashlib
import os
from cipher.base import LIBRARY_MODE_AVAILABLE, DES, pad, unpad


class DESCipher:

    @staticmethod
    def _ensure_key(key) -> bytes:
        if isinstance(key, str):
            key_bytes = hashlib.md5(key.encode()).digest()[:8]
        elif isinstance(key, bytes):
            key_bytes = key[:8] if len(key) >= 8 else key.ljust(8, b'\0')
        else:
            raise ValueError("DES anahtarı string veya bytes olmalı")
        return key_bytes[:8]

    @staticmethod
    def encrypt(text: str, key, use_library: bool = True) -> str:
        key_bytes = DESCipher._ensure_key(key)
        text_bytes = text.encode('utf-8')

        if use_library and LIBRARY_MODE_AVAILABLE:
            return DESCipher._encrypt_library(text_bytes, key_bytes)
        else:
            return DESCipher._encrypt_manual(text_bytes, key_bytes)

    @staticmethod
    def decrypt(ciphertext: str, key, use_library: bool = True) -> str:
        key_bytes = DESCipher._ensure_key(key)

        if use_library and LIBRARY_MODE_AVAILABLE:
            return DESCipher._decrypt_library(ciphertext, key_bytes)
        else:
            return DESCipher._decrypt_manual(ciphertext, key_bytes)

    @staticmethod
    def _encrypt_library(text_bytes: bytes, key: bytes) -> str:
        cipher = DES.new(key, DES.MODE_CBC)
        iv = cipher.iv
        padded_text = pad(text_bytes, DES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        result = base64.b64encode(iv + ciphertext).decode('utf-8')
        return result

    @staticmethod
    def _decrypt_library(ciphertext: str, key: bytes) -> str:
        data = base64.b64decode(ciphertext)
        iv = data[:8]
        encrypted = data[8:]
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        decrypted = unpad(cipher.decrypt(encrypted), DES.block_size)
        return decrypted.decode('utf-8')

    @staticmethod
    def _encrypt_manual(text_bytes: bytes, key: bytes) -> str:
        iv = os.urandom(8) if hasattr(os, 'urandom') else b'\x00' * 8
        result = bytearray()
        
        for i in range(0, len(text_bytes), 8):
            block = text_bytes[i:i+8]
            padded_block = block.ljust(8, b'\0')
            encrypted_block = bytes(a ^ b for a, b in zip(padded_block, key))
            result.extend(encrypted_block)
        
        combined = iv + bytes(result)
        return base64.b64encode(combined).decode('utf-8')

    @staticmethod
    def _decrypt_manual(ciphertext: str, key: bytes) -> str:
        data = base64.b64decode(ciphertext)
        iv = data[:8]
        encrypted = data[8:]
        
        result = bytearray()
        for i in range(0, len(encrypted), 8):
            block = encrypted[i:i+8]
            decrypted_block = bytes(a ^ b for a, b in zip(block, key))
            result.extend(decrypted_block)
        
        decrypted = bytes(result).rstrip(b'\0')
        return decrypted.decode('utf-8', errors='ignore')

