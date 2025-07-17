class rsa:
    def __init__(self, k):
        # tamanho do módulo RSA n em bytes
        self.k = k
        
    def encrypt(M, PU):
        # eh esperado que M seja bytes
        # retorna C em bytes

        M = int.from_bytes(M, 'big')
        e = PU['e']
        n = PU['n']
        C = pow(M, e, n)

        return C.to_bytes(256, 'big')

    def decrypt(C, PR):
        # eh esperado que C seja bytes
        # retorna M em bytes

        C = int.from_bytes(C, 'big')
        d = PR['d']
        n = PR['n']
        M = pow(C, d, n)

        return M.to_bytes(256, 'big')
