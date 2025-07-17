import rsa
from utils import *
import secrets

class rsa_pss(rsa):
    def __init__(self, k=256):
        super().__init__(k)

    def sign(self, m, PR):
        # 1 - generate the salt
        salt = secrets.token_bytes(32)

        # 2 - compute the hash value H
        H = Hash(m, salt)

        # 3 - create the data block (DB)
        padding2 =  b'\x00' * 189  # 189 = 255 (Em_len) - 32 (salt_len) - 32 (h_len) - 2 (b'\x01' + b'\xbc')
        DB = padding2 + b'\x01' + salt

        # 4 - MGF1 -> masked generation function
        T = mgf(H, len(DB))

        # 5 - maskedDB -> DB XOR T
        maskedDB = bytes(x ^ y for x, y in zip(DB, T))

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
        
        T = mgf(H, len(maskedDB))
        DB = bytes(x ^ y for x, y in zip(maskedDB, T))
        salt = DB[-32:]

        MHash = Hash(message, salt)

        return MHash == H
    
    @staticmethod
    def Hash(m, salt):
        # 1 - hash the message (using sha3-256)
        mHash = hashlib.sha3_256(m).digest()

        # 2 - padding -> a prefix of eight zero byte
        padding1 = b'\x00' * 8

        # 3 - create the block M'
        m_ = padding1 + mHash + salt

        # 4 - create the second hash(H) (the one to be compared in the verification process)
        return hashlib.sha3_256(m_).digest()