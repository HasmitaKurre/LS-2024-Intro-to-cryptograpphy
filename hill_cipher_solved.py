import numpy as np

# Helper functions
def mod_inverse_matrix(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, modulus)
    matrix_mod_inv = (det_inv * np.round(det * np.linalg.inv(matrix)).astype(int) % modulus) % modulus
    return matrix_mod_inv

def text_to_matrix(text, size):
    numbers = [ord(char) - ord('A') for char in text]
    while len(numbers) % size != 0:
        numbers.append(ord('X') - ord('A'))
    return np.array(numbers).reshape(-1, size)

def matrix_to_text(matrix):
    text = ''.join(chr(int(num) + ord('A')) for num in matrix.flatten())
    return text

def encrypt(plaintext, key_matrix):
    block_size = key_matrix.shape[0]
    plaintext_matrix = text_to_matrix(plaintext, block_size)
    ciphertext_matrix = (np.dot(plaintext_matrix, key_matrix) % 26).astype(int)
    return matrix_to_text(ciphertext_matrix)

def discover_key(plaintext, ciphertext, block_size):
    plaintext_matrix = text_to_matrix(plaintext, block_size)
    ciphertext_matrix = text_to_matrix(ciphertext, block_size)
    plaintext_matrix_inv = mod_inverse_matrix(plaintext_matrix, 26)
    key_matrix = (np.dot(plaintext_matrix_inv, ciphertext_matrix) % 26).astype(int)
    return key_matrix

def key_matrix_to_text(matrix):
    return ''.join(chr(int(num) + ord('A')) for num in matrix.flatten())

# Encryption example
plaintext = "ANTCATDOG"
key_matrix = np.array([[6, 24, 1], [13, 16, 10], [20, 17, 15]])  # Example key matrix for illustration
ciphertext = encrypt(plaintext, key_matrix)
print("Ciphertext:", ciphertext)

# Key discovery example
known_plaintext = "ANTCATDOG"
known_ciphertext = "TIMFINWLY"
block_size = 3
discovered_key = discover_key(known_plaintext, known_ciphertext, block_size)
print("Discovered Key Matrix (Numerical):\n", discovered_key)
print("Discovered Key Matrix (Text):", key_matrix_to_text(discovered_key))
