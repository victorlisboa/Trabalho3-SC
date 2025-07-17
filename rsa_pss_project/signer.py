from . import rsa
from .utils import *
import secrets

class rsa_pss(rsa.rsa):
    def __init__(self, hLen=32, sLen=32, k=256):
        super().__init__(k)
        self.hLen = hLen
        self.sLen = sLen
        self.emLen = k-1

    def sign(self, M, PR):
        if len(M) > ((1 << 61) - 1):
            raise ValueError("Message too long")
        if self.emLen < self.hLen + self.sLen + 2:
            raise ValueError("Encoding error")

        # 1 - generate the salt
        salt = secrets.token_bytes(self.sLen)

        # 2 - compute the hash value H
        H = self.Hash(M, salt)

        # 3 - create the data block (DB)
        PS =  b'\x00' * (self.emLen - self.sLen - self.hLen - 2)  # -2 => (b'\x01' + b'\xbc')
        DB = PS + b'\x01' + salt

        # 4 - MGF1 -> masked generation function
        dbMask = MGF(H, len(DB))

        # 5 - maskedDB -> DB XOR T
        maskedDB = bytes(x ^ y for x, y in zip(DB, dbMask))

        # 6 - create the encoded message
        EM = maskedDB + H + b'\xbc'

        # 7 - sign EM
        signature = self.rsa_decrypt(EM, PR)

        return byte_to_base64(signature)

    def verify_signature(self, M, signature, PU):
        if len(M) > ((1 << 61) - 1):
            return False
        if self.emLen < self.hLen + self.sLen + 2:
            return False
        
        # recover EM
        signature = base64_to_byte(signature)
        EM = self.rsa_encrypt(signature, PU)
        maskedDB, H, bc = EM[-self.emLen:-self.hLen-1], EM[-self.hLen-1:-1], EM[-1:]

        if bc != b'\xbc':
            return False
        
        dbMask = MGF(H, len(maskedDB))
        DB = bytes(x ^ y for x, y in zip(maskedDB, dbMask))

        ps_len = self.emLen - self.hLen - self.sLen - 2
        
        # check if the leftmost ps_len bytes are all zero
        if DB[:ps_len] != b'\x00' * ps_len:
            return False
        
        # check if the byte at position ps_len is 0x01
        if DB[ps_len] != 1:
            return False
        
        salt = DB[-self.sLen:]

        MHash = self.Hash(M, salt)

        if not MHash == H:
            return False

        return True
    
    @staticmethod
    def Hash(m, salt):
        # 1 - hash the message (using sha3-256)
        mHash = hashlib.sha3_256(m).digest()

        # 2 - padding -> a prefix of eight zero byte
        padding = b'\x00' * 8

        # 3 - create the block M'
        m_ = padding + mHash + salt

        # 4 - create the second hash(H) (the one to be compared in the verification process)
        return hashlib.sha3_256(m_).digest()