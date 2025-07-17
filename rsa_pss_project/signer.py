import rsa
from utils import *
import secrets

class rsa_pss(rsa):
    def __init__(self, hLen=61, sLen=32, emBits=2047):
        self.hLen = hLen
        self.sLen = sLen
        self.emBits = emBits
        self.emLen = emBits + 7 // 8
        super().__init__(self.emLen)

    def sign(self, M, PR):
        if len(M) > ((1 << self.hLen) - 1):
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
        signature = super().decrypt(EM, PR)

        return signature

    def verify_signature(self, message, signature, PU):
        # recover EM
        EM = super().encrypt(signature, PU)
        maskedDB, H, bc = EM[-255:-33], EM[-33:-1], EM[-1:]

        if bc != b'\xbc':
            raise ValueError("Trailer byte 0xBC not found in the signed message")
        
        T = MGF(H, len(maskedDB))
        DB = bytes(x ^ y for x, y in zip(maskedDB, T))
        salt = DB[-32:]

        MHash = self.Hash(message, salt)

        return MHash == H
    
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