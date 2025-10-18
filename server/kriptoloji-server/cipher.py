
class CipherFactory:
    """Farklı şifreleme yöntemlerini yönetir"""

    METHODS = {
        'caesar': 'Caesar Cipher',
        'vigenere': 'Vigenere Cipher',
        'routed': 'Route Cipher'
    }

    @staticmethod
    def encrypt(text: str, method: str, key: any) -> str:
        if method == 'caesar':
            return CaesarCipher.encrypt(text, key)
        elif method == 'vigenere':
            return VigenereCipher.encrypt(text, key)
        elif method == 'routed':
            return RouteCipher.encrypt(text, key)
        else:
            raise ValueError(f"Bilinmeyen şifreleme yöntemi: {method}")

    @staticmethod
    def decrypt(text: str, method: str, key: any) -> str:
        if method == 'caesar':
            return CaesarCipher.decrypt(text, key)
        elif method == 'vigenere':
            return VigenereCipher.decrypt(text, key)
        elif method == 'routed':
            return RouteCipher.decrypt(text, key)
        else:
            raise ValueError(f"Bilinmeyen şifreleme yöntemi: {method}")


class CaesarCipher:

    @staticmethod
    def encrypt(text: str, shift: int) -> str:
        res = []
        for ch in text:
            if 'a' <= ch <= 'z':
                base = ord('a')
                res.append(chr((ord(ch) - base + shift) % 26 + base))
            elif 'A' <= ch <= 'Z':
                base = ord('A')
                res.append(chr((ord(ch) - base + shift) % 26 + base))
            else:
                res.append(ch)
        return ''.join(res)

    @staticmethod
    def decrypt(text: str, shift: int) -> str:
        return CaesarCipher.encrypt(text, -shift)


class VigenereCipher:

    @staticmethod
    def _process_key(key: str) -> str:
        """Anahtarı işle (sadece harfler)"""
        return ''.join(ch.upper() for ch in key if ch.isalpha())

    @staticmethod
    def encrypt(text: str, key: str) -> str:
        if not key:
            raise ValueError("Vigenere anahtarı boş olamaz")

        key = VigenereCipher._process_key(key)
        if not key:
            raise ValueError("Vigenere anahtarı en az bir harf içermeli")

        res = []
        key_idx = 0

        for ch in text:
            if ch.isalpha():
                is_upper = ch.isupper()
                ch = ch.upper()

                shift = ord(key[key_idx % len(key)]) - ord('A')
                base = ord('A')
                encrypted = chr((ord(ch) - base + shift) % 26 + base)

                res.append(encrypted if is_upper else encrypted.lower())
                key_idx += 1
            else:
                res.append(ch)

        return ''.join(res)

    @staticmethod
    def decrypt(text: str, key: str) -> str:
        if not key:
            raise ValueError("Vigenere anahtarı boş olamaz")

        key = VigenereCipher._process_key(key)
        if not key:
            raise ValueError("Vigenere anahtarı en az bir harf içermeli")

        res = []
        key_idx = 0

        for ch in text:
            if ch.isalpha():
                is_upper = ch.isupper()
                ch = ch.upper()

                shift = ord(key[key_idx % len(key)]) - ord('A')
                base = ord('A')
                decrypted = chr((ord(ch) - base - shift) % 26 + base)

                res.append(decrypted if is_upper else decrypted.lower())
                key_idx += 1
            else:
                res.append(ch)

        return ''.join(res)


class RouteCipher:

    @staticmethod
    def _pad_text(text: str, cols: int) -> str:
        """Metni doldur"""
        padding_needed = (cols - len(text) % cols) % cols
        return text + 'X' * padding_needed

    @staticmethod
    def encrypt(text: str, key: int = 4) -> str:
        """Route Cipher ile şifrele"""
        if key <= 0:
            key = 4

        text = RouteCipher._pad_text(text, key)
        rows = len(text) // key

        # Grid oluştur
        grid = [text[i * key:(i + 1) * key] for i in range(rows)]

        # Sütunları oku
        result = []
        for col in range(key):
            for row in range(rows):
                result.append(grid[row][col])

        return ''.join(result)

    @staticmethod
    def decrypt(text: str, key: int = 4) -> str:
        """Route Cipher deşifrele"""
        if key <= 0:
            key = 4

        rows = len(text) // key

        # Grid oluştur (deşifreleme için)
        grid = [[''] * key for _ in range(rows)]
        idx = 0

        for col in range(key):
            for row in range(rows):
                grid[row][col] = text[idx]
                idx += 1

        # Satırları oku
        result = []
        for row in range(rows):
            result.extend(grid[row])

        return ''.join(result).rstrip('X')