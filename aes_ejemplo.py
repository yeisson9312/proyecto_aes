from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def cifrar_aes_256(texto_plano):
    """
    Realiza una sola capa de cifrado AES-256 en modo CBC.
    
    :param texto_plano: Cadena de texto a cifrar.
    :return: Diccionario con la clave, el IV y el texto cifrado (todo en formato Base64).
    """
    # 1. Definir la Clave Secreta (32 bytes = 256 bits)
    # En un sistema real, esta clave de sesión se intercambiaría con RSA.
    key = get_random_bytes(32) 
    
    # 2. Definir el Vector de Inicialización (IV)
    # El IV no es secreto, pero DEBE ser aleatorio para cada cifrado.
    iv = get_random_bytes(AES.block_size) # AES.block_size es 16 bytes
    
    # 3. Crear el Objeto Cipher (con la clave, el modo y el IV)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # 4. Aplicar Padding y Cifrar
    datos_cifrar = texto_plano.encode('utf-8')
    texto_cifrado_bytes = cipher.encrypt(pad(datos_cifrar, AES.block_size))
    
    # 5. Codificar en Base64 para una representación legible y transmisible
    resultado = {
        "clave_secreta": base64.b64encode(key).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8'),
        "texto_cifrado": base64.b64encode(texto_cifrado_bytes).decode('utf-8')
    }
    return resultado

def descifrar_aes_256(clave_b64, iv_b64, texto_cifrado_b64):
    """
    Descifra el texto usando la clave y el IV proporcionados.
    """
    # Decodificar de Base64 a bytes
    key_desc = base64.b64decode(clave_b64)
    iv_desc = base64.b64decode(iv_b64)
    texto_cifrado_desc = base64.b64decode(texto_cifrado_b64)
    
    # Crear objeto Cipher para descifrar (debe usar la misma clave y IV)
    decipher = AES.new(key_desc, AES.MODE_CBC, iv_desc)
    
    # Descifrar y quitar el padding
    texto_descifrado_bytes = unpad(decipher.decrypt(texto_cifrado_desc), AES.block_size)
    
    return texto_descifrado_bytes.decode('utf-8')

# --- EJECUCIÓN PRINCIPAL ---

# Texto que simula un mensaje sensible de SWIFT
texto_original = "Mensaje SWIFT MT103: Transferencia de $150,000.00 a la cuenta 987654."

print("--- Criptosistema Simétrico AES-256 (Confidencialidad) ---")
print(f"TEXTO PLANO ORIGINAL:\n'{texto_original}'\n")

# 1. Cifrado
cifrado = cifrar_aes_256(texto_original)

print("RESULTADO DEL CIFRADO:")
print("-" * 40)
print(f"Clave Secreta (256 bits):\n{cifrado['clave_secreta']}")
print(f"IV (Vector de Inicialización):\n{cifrado['iv']}")
print(f"TEXTO CIFRADO (Ininteligible):\n{cifrado['texto_cifrado']}")

# 2. Descifrado (Usando la misma clave)
print("\n--- Demostración de Descifrado (Confirmación de Clave Privada) ---")

texto_descifrado = descifrar_aes_256(
    cifrado['clave_secreta'], 
    cifrado['iv'], 
    cifrado['texto_cifrado']
)

print(f"Texto Descifrado:\n'{texto_descifrado}'")