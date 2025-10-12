def vigenere_encrypt(text: str, key: str) -> str:
    """
    Vigenère şifreleme algoritması
    """
    if not text or not key:
        return text

    encrypted_text = ""
    key_index = 0
    key = key.upper()

    for char in text:
        if char.isalpha():
            # Anahtar karakterinin shift değeri
            shift = ord(key[key_index % len(key)]) - 65

            if char.isupper():
                # Büyük harf için şifreleme
                encrypted_char = chr((ord(char) - 65 + shift) % 26 + 65)
                encrypted_text += encrypted_char
            else:
                # Küçük harf için şifreleme
                encrypted_char = chr((ord(char) - 97 + shift) % 26 + 97)
                encrypted_text += encrypted_char

            key_index += 1
        else:
            # Alfabetik olmayan karakterleri olduğu gibi bırak
            encrypted_text += char

    return encrypted_text


def vigenere_decrypt(text: str, key: str) -> str:
    """
    Vigenère deşifreleme algoritması
    """
    if not text or not key:
        return text

    decrypted_text = ""
    key_index = 0
    key = key.upper()

    for char in text:
        if char.isalpha():
            # Anahtar karakterinin shift değeri
            shift = ord(key[key_index % len(key)]) - 65

            if char.isupper():
                # Büyük harf için deşifreleme
                decrypted_char = chr((ord(char) - 65 - shift) % 26 + 65)
                decrypted_text += decrypted_char
            else:
                # Küçük harf için deşifreleme
                decrypted_char = chr((ord(char) - 97 - shift) % 26 + 97)
                decrypted_text += decrypted_char

            key_index += 1
        else:
            # Alfabetik olmayan karakterleri olduğu gibi bırak
            decrypted_text += char

    return decrypted_text


# Test fonksiyonu
if __name__ == "__main__":
    # Test
    plain_text = "HELLO"
    key = "KEY"

    encrypted = vigenere_encrypt(plain_text, key)
    decrypted = vigenere_decrypt(encrypted, key)

    print(f"Orijinal: {plain_text}")
    print(f"Şifreli: {encrypted}")
    print(f"Deşifre: {decrypted}")