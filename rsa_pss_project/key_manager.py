import os
from math import gcd
from secrets import randbits
from random import randint
from . import utils

class KeySizeTooSmallError(Exception):
    pass

class RSAKey:
    """
    Gerencia um par de chaves RSA (geracao, armazenamento e carregamento)
    """
    def __init__(self, bits=2048):
        if bits < 1024:
            raise KeySizeTooSmallError("A chave deve ter pelo menos 1024 bits.")
        self.bits = bits
        self.n = None
        self.e = None # Expoente publico
        self._d = None # Expoente privado

    def generate(self):
        """
        Gera as partes publicas (n, e) e privada (d) da chave.
        """

        prime_bits = self.bits // 2
        p = self.choosePrimeNumber(prime_bits)
        q = self.choosePrimeNumber(prime_bits)

        # garantir que p != q
        while q == p:
            q = self.choosePrimeNumber(self.bits)

        self.n = p*q
        phi_n = (p-1)*(q-1)
        self.e = self.choosePublicKey(phi_n)

        # d -> inverso multiplicativo de e mod phi_n
        self.d = pow(self.e, -1, phi_n)

        public_key = {'n': self.n, 'e': self.e}
        private_key = {'n': self.n, 'd': self.d}

        # salva chaves em arquivo .pem
        if not os.path.exists('keys'):
            os.makedirs('keys')
        self.store_pem_file('keys/PU.pem', public_key, "PUBLIC")
        self.store_pem_file('keys/PR.pem', private_key)

    @staticmethod
    def store_pem_file(file_name, fields, key_type="PRIVATE"):
        with open(file_name, 'w') as f:
            f.write(f'-----BEGIN {key_type} KEY-----\n')
            for name, value in fields.items():
                line = f'{name}:{utils.int_to_base64(value)}'
                f.write(line + '\n')
            f.write(f'-----END {key_type} KEY-----\n')
    
    @staticmethod
    def load_pem_file(file_name):
        with open(file_name, 'r') as f:
            lines = f.readlines()
        content = {}
        for line in lines:
            if ':' in line:
                name, value = line.strip().split(':', 1)
                content[name] = utils.base64_to_int(value)
        return content
    
    @staticmethod
    def choosePrimeNumber(N):
        # it is expected to find a prime number after testing about Log(p)/2∼ candidates
        candidate = randbits(N) | 1
        candidate |= (1 << (N - 1)) | 1 # garante que o numero tem N bits
        while not utils.isPrime(candidate):
            candidate += 2

        return candidate

    @staticmethod
    def choosePublicKey(phi_n):
        while True:
            e = randint(2, phi_n-1)
            if gcd(phi_n, e) == 1:
                return e
