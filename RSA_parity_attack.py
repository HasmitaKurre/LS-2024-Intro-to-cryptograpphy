import numpy as np
from sympy import isprime, mod_inverse
from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes

class RSA:
    """Implements the RSA public key encryption / decryption."""

    def __init__(self, key_length):
        self.key_length = key_length
        self.p = self.generate_large_prime()
        self.q = self.generate_large_prime()
        self.n = self.p * self.q
        self.e = 65537  # Common choice for e
        phi_n = (self.p - 1) * (self.q - 1)
        self.d = mod_inverse(self.e, phi_n)

    def generate_large_prime(self):
        while True:
            prime_candidate = getPrime(self.key_length // 2)
            if isprime(prime_candidate):
                return prime_candidate

    def encrypt(self, binary_data):
        m = bytes_to_long(binary_data)
        c = pow(m, self.e, self.n)
        return c

    def decrypt(self, encrypted_int_data):
        m = pow(encrypted_int_data, self.d, self.n)
        return long_to_bytes(m)

class RSAParityOracle(RSA):
    """Extends the RSA class by adding a method to verify the parity of data."""

    def is_parity_odd(self, encrypted_int_data):
        decrypted_message = self.decrypt(encrypted_int_data)
        return decrypted_message[-1] % 2 == 1

def parity_oracle_attack(ciphertext, rsa_parity_oracle):
    n = rsa_parity_oracle.n
    e = rsa_parity_oracle.e

    # Let's guess the message length; for simplicity, we assume it fits within the modulus
    m_length = len(ciphertext)
    c = ciphertext
    for i in range(256):  # We try each bit position
        c_prime = (c * pow(2, e, n)) % n
        if rsa_parity_oracle.is_parity_odd(c_prime):
            c = c_prime
        else:
            c = (c * pow(2, -1, n)) % n

    plaintext = rsa_parity_oracle.decrypt(c)
    return plaintext

def main():
    input_bytes = input("Enter the message: ")

    # Generate a 1024-bit RSA pair
    rsa_parity_oracle = RSAParityOracle(1024)

    # Encrypt the message
    ciphertext = rsa_parity_oracle.encrypt(input_bytes.encode())
    print("Encrypted message is:", ciphertext)

    # Check if the attack works
    plaintext = parity_oracle_attack(ciphertext, rsa_parity_oracle)
    print("Obtained plaintext:", plaintext.decode())
    assert plaintext == input_bytes.encode()

if __name__ == '__main__':
    main()
