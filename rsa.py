from math import sqrt, gcd
from secrets import randbits
from random import randint
import base64
import os

prime_numbers = []

def sieve(n):
    primo = [True for _ in range(n+1)]
    
    p = 2
    while(p*p <= n):
        if primo[p]:
            for i in range(p*2, n+1, p):
                primo[i] = False
        p += 1
    
    for i in range(2, n+1):
        if primo[i]:
            prime_numbers.append(i)

def miller_rabin(n):
    # O(k*n^3)
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    
    k = 40
    for i in range(k):
        a = randint(2, n-2)
        d = n-1
        s = 0
        while d%2==0:
            d //= 2
            s += 1
        
        x = pow(a, d, n)
        for j in range(s):
            y = pow(x, 2, n)
            if y == 1 and x != 1 and x != n-1:
                return False
            x = y
        if y != 1:
            return False
        return True

def isPrime(n):
    for prime in prime_numbers:
        if n % prime == 0:
            return False
    return miller_rabin(n)

def choosePrimeNumber(N):
    # it is expected to find a prime number after testing about Log(p)/2∼ candidates
    candidate = randbits(N) | 1
    while not isPrime(candidate):
        candidate += 2

    return candidate

def choosePublicKey(phi_n):
    while True:
        e = randint(2, phi_n-1)
        if gcd(phi_n, e) == 1:
            return e

def int_to_base64(n):
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
    return base64.b64encode(b).decode('ascii')

def base64_to_int(b64):
    return int.from_bytes(base64.b64decode(b64), 'big')

def store_pem_file(file_name, fields):
    with open(file_name, 'w') as f:
        f.write(f'-----BEGIN PRIVATE KEY-----\n')
        for name, value in fields.items():
            line = f'{name}:{int_to_base64(value)}'
            f.write(line + '\n')
        f.write(f'-----END PRIVATE KEY-----\n')

def load_pem_file(file_name):
    with open(file_name, 'r') as f:
        lines = f.readlines()
    content = {}
    for line in lines:
        if ':' in line:
            name, value = line.strip().split(':', 1)
            content[name] = base64_to_int(value)
    return content


def generate_keys(N):
    sieve(1000000)
    p = choosePrimeNumber(N)
    q = choosePrimeNumber(N)

    # garantir que p != q
    while q == p:
        q = choosePrimeNumber(N)

    n = p*q
    phi_n = (p-1)*(q-1)
    e = choosePublicKey(phi_n)
    d = pow(e, -1, phi_n)

    public_key = {'n': n, 'e': e}
    private_key = {'n': n, 'd': d}

    # salva chaves em arquivo .pem
    if not os.path.exists('keys'):
        os.makedirs('keys')
    store_pem_file('keys/PU.pem', public_key)
    store_pem_file('keys/PR.pem', private_key)

    # carrega chaves
    public_key = load_pem_file('keys/PU.pem')
    private_key = load_pem_file('keys/PR.pem')

    return public_key, private_key

def encrypt(M, PU):
    e = PU['e']
    n = PU['n']
    C = pow(M, e, n)
    return C

def decrypt(C, PR):
    d = PR['d']
    n = PR['n']
    M = pow(C, d, n)
    return M

def main():
    PU, PR = generate_keys(1024)
    C = encrypt(5, PU)
    print(f'Encrypted message: {C}')
    M = decrypt(C, PR)
    print(f'Decrypted message: {M}')


if __name__ == '__main__':
    main()
