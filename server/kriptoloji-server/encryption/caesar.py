def caesar_encrypt(text: str, shift: int) -> str:
    """
    Caesar şifreleme algoritması
    """
    if not text:
        return text

    encrypted_text = ""

    for char in text:
        if char.isalpha():
            if char.isupper():
                # Büyük harf için şifreleme
                encrypted_char = chr((ord(char) - 65 + shift) % 26 + 65)
                encrypted_text += encrypted_char
            else:
                # Küçük harf için şifreleme
                encrypted_char = chr((ord(char) - 97 + shift) % 26 + 97)
                encrypted_text += encrypted_char
        else:
            # Alfabetik olmayan karakterleri olduğu gibi bırak
            encrypted_text += char

    return encrypted_text


def caesar_decrypt(text: str, shift: int) -> str:
    """
    Caesar deşifreleme algoritması
    """
    if not text:
        return text

    decrypted_text = ""

    for char in text:
        if char.isalpha():
            if char.isupper():
                # Büyük harf için deşifreleme
                decrypted_char = chr((ord(char) - 65 - shift) % 26 + 65)
                decrypted_text += decrypted_char
            else:
                # Küçük harf için deşifreleme
                decrypted_char = chr((ord(char) - 97 - shift) % 26 + 97)
                decrypted_text += decrypted_char
        else:
            # Alfabetik olmayan karakterleri olduğu gibi bırak
            decrypted_text += char

    return decrypted_text


# Test fonksiyonu
if __name__ == "__main__":
    # Test
    plain_text = "HELLO"
    shift = 3

    encrypted = caesar_encrypt(plain_text, shift)
    decrypted = caesar_decrypt(encrypted, shift)

    print(f"Orijinal: {plain_text}")
    print(f"Shift: {shift}")
    print(f"Şifreli: {encrypted}")
    print(f"Deşifre: {decrypted}")
