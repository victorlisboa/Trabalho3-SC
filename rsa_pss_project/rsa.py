class rsa:
    def __init__(self, k=256):
        self.k = k
    
    def rsa_encrypt(self, M, PU):
        # eh esperado que M seja bytes
        # retorna C em bytes
        M = int.from_bytes(M, 'big')
        e = PU['e']
        n = PU['n']
        C = pow(M, e, n)
        return C.to_bytes(self.k, 'big')

    def rsa_decrypt(self, C, PR):
        # eh esperado que C seja bytes
        # retorna M em bytes

        C = int.from_bytes(C, 'big')
        d = PR['d']
        n = PR['n']
        M = pow(C, d, n)

        return M.to_bytes(self.k, 'big')
