from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Fonction pour chiffrer un message
def encrypt_aes(plaintext, key):
    # Générer un vecteur d'initialisation (IV)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Chiffrer le texte
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    
    # Retourner le IV et le texte chiffré encodé en base64
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# Fonction pour déchiffrer un message
def decrypt_aes(ciphertext_b64, key):
    # Décoder le texte chiffré
    ciphertext = base64.b64decode(ciphertext_b64)
    
    # Extraire le IV et le texte chiffré
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Déchiffrer le texte
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    return plaintext.decode('utf-8')

# Exemple d'utilisation
if __name__ == "__main__":
    key = get_random_bytes(16)  # Clé de 16 bytes pour AES-128
    message = "BDAD COLLABORATION ENTRE ESCT et ISAMM"

    # Chiffrer le message
    encrypted_message = encrypt_aes(message, key)
    print(f"Message chiffré: {encrypted_message}")

    # Déchiffrer le message
    decrypted_message = decrypt_aes(encrypted_message, key)
    print(f"Message déchiffré: {decrypted_message}")
