import rsa
from utils import *
import secrets


class rsa_oaep(rsa):
    def __init__(self, hLen=61, k=256):
        super().__init__(k)
        self.hLen = hLen

    def encrypt(self, PU, M, L=""):
        if len(L) > ((1 << self.hLen) - 1):
            raise ValueError("Label too long")
        if len(M) > (self.k - (2 * self.hLen) - 2):
            raise ValueError("Message too long")
        
        lHash = hashlib.sha3_256(L).digest()
        PS = b'\x00' * (self.k - len(M) - (2 * self.hLen) - 2)
        DB = lHash + PS + b'\x01' + M
        seed = secrets.token_bytes(self.hLen)
        dbMask = mgf(seed, self.k - self.hLen - 1)
        maskedDB = bytes(x ^ y for x, y in zip(DB, dbMask))
        seedMask = mgf(maskedDB, self.hLen)
        maskedSeed = bytes(x ^ y for x, y in zip(seed, seedMask))
        EM = b'\x00' + maskedSeed + maskedDB

        C = super().encrypt(EM, PU)
        return C
    
    def decrypt(self, PR, C, L=""):
        if len(L) > ((1 << self.hLen) - 1):
            raise ValueError("Decryption error")
        if len(C) != self.k:
            raise ValueError("Decryption error")
        if self.k < 2*self.hLen + 2 :
            raise ValueError("Decryption error")
        
        EM = super().decrypt(C, PR)
        Y, maskedSeed, maskedDB = EM[:1], EM[1: -(self.k - self.hLen - 1)], EM[-(self.k - self.hLen - 1):]
        if Y != b'\x00':
            raise ValueError("Decryption error")
        lHash = hashlib.sha3_256(L).digest()
        seedMask = mgf(maskedDB, self.hLen)
        seed = bytes(x ^ y for x, y in zip(maskedSeed, seedMask))
        dbMask = mgf(seed, (self.k - self.hLen - 1))
        DB = bytes(x ^ y for x, y in zip(maskedDB, dbMask))
        lHash_ =  DB[:self.hLen]
        if lHash_ != lHash:
            raise ValueError("Decryption error")
        try:
            idx = DB.index(b'\x01')
        except ValueError:
            raise ValueError("Decryption error")
        M = DB[idx+1:]
        return M
        



