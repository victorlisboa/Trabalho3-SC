from math import sqrt, gcd
from secrets import randbits
from random import randint
import time

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


def generate_keys(N):
    p = choosePrimeNumber(N)
    q = choosePrimeNumber(N)

    # garantir que p != q
    while q == p:
        q = choosePrimeNumber(N)

    n = p*q
    phi_n = (p-1)*(q-1)
    e = choosePublicKey(phi_n)
    d = pow(e, -1, phi_n)


def main():
    # generate_keys(512)
    n = 65535
    print(n.to_bytes(2, 'little'))

if __name__ == '__main__':
    main()
