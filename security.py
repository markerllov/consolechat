class SimpleCipher:
    @staticmethod
    def encrypt(message: str, key: str) -> str:
        """Простое XOR-шифрование"""
        encrypted = []
        key_len = len(key)
        for i, char in enumerate(message):
            key_char = key[i % key_len]
            encrypted_char = chr(ord(char) ^ ord(key_char))
            encrypted.append(encrypted_char)
        return ''.join(encrypted)

    @staticmethod
    def decrypt(encrypted: str, key: str) -> str:
        """Расшифровка XOR (та же операция, что и шифрование)"""
        return SimpleCipher.encrypt(encrypted, key)