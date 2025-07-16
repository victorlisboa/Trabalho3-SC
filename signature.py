import hashlib
import secrets
import rsa

def mgf1(H, lenT):
    T = b''
    cnt = 0
    while(len(T) < lenT):
        T += hashlib.sha3_256(H + cnt.to_bytes(4, byteorder='big')).digest()
        cnt += 1
    return T[:lenT]

def pss(m):
    # 1 - hash the message (using sha3-256)
    mHash = hashlib.sha3_256(m).digest()

    # 2 - generate the salt
    salt = secrets.token_bytes(32)

    # 3 - padding -> a prefix of eight zero byte
    padding1 = b'\x00' * 8

    # 4 - create the block M'
    m_ = padding1 + mHash + salt

    # 5 - create the second hash (the one to be compared in the verification process)
    H = hashlib.sha3_256(m_).digest()

    # 6 - create the data block (DB)
    padding2 =  b'\x00' * 190  # 190 = 256 (Em_len) - 32 (salt_len) - 32 (h_len) - 2 (b'\x01' + b'\xbc')
    DB = padding2 + b'\x01' + salt

    # 7 - MGF1 -> masked generation function
    T = mgf1(H, len(DB))

    # 8 - maskedDB -> DB XOR T
    maskedDB = bytes(x ^ y for x, y in zip(DB, T))

    # 9 - create the encoded message
    EM = maskedDB + H + b'\xbc'

m = pss(b'\x0a32bc')
PU, PR = rsa.generate_keys(1024)
C = rsa.encrypt(m, PU)
