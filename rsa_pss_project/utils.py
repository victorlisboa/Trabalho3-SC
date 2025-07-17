import base64
import hashlib
from random import randint

prime_numbers = []

def MGF(H, lenT):
    T = b''
    cnt = 0
    while(len(T) < lenT):
        T += hashlib.sha3_256(H + cnt.to_bytes(4, byteorder='big')).digest()
        cnt += 1
    return T[:lenT]

def byte_to_base64(bytes):
    return base64.b64encode(bytes).decode('ascii')

def base64_to_byte(b64):
    return base64.b64decode(b64)

def int_to_base64(n):
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, 'big')
    return base64.b64encode(b).decode('ascii')

def base64_to_int(b64):
    return int.from_bytes(base64.b64decode(b64), 'big')

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
