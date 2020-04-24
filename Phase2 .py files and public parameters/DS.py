""" Public parameter generation: Two prime numbers p and q are generated with q|p − 1,
where q and p are 224-bit and 2048-bit integers, respectively. The generator g generates a
subgroup of Z
∗
p with q elements. Naturally, g
q ≡ 1 mod p. Note that in your system q, p,
and g are public parameters shared by all users, who have different secret/public key pairs.
Refer to the slide (with title “DSA Setup” in chapter 10 for an efficient method for parameter
generation).
"""
from random import randint
import pyprimes
import random
import sys
import hashlib, binascii
sys.float_info.max
import warnings
from Crypto.Hash import SHA3_256
import sympy
import string

small_primes = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
                109, 113}


def isPrime_fast(number):
    for x in small_primes:
        if number % x == 0:
            return False
        elif not sympy.isprime(number):
            return False
        else:
            return True


def modinv(a, m):
    if a < 0:
        a = a + m
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m


def random_prime(bitsize):
    warnings.simplefilter('ignore')
    chck = False
    while not chck:
        p = random.randrange(2 ** (bitsize - 1), 2 ** (bitsize) - 1)
        chck = isPrime_fast(p) #sympy.isprime(p)
    warnings.simplefilter('default')
    return p


def large_DL_Prime(q, bitsize):
    warnings.simplefilter('ignore')
    chck = False
    while not chck:
        k = random.randrange(2**(bitsize-1), 2**bitsize-1)
        p = k*q+1
        chck = isPrime_fast(p) #sympy.isprime(p)
        if p.bit_length() != 2048:
            chck = False
    warnings.simplefilter('default')
    return p


def Param_Generator(qsize, psize):
    q = random_prime(qsize)
    p = large_DL_Prime(q, psize-qsize)
    tmp = (p-1)//q
    g = 1
    while g == 1:
        alpha = random.randrange(1, p)
        g = pow(alpha, tmp, p)
    return q, p, g


def Key_Gen(q, p, g):
    alpha = random.randint(1, q)  # private key
    beta = pow(g, alpha, p)  # public key
    return alpha, beta


def egcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y


def random_string(random_num):
    password_characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(password_characters) for i in range(random_num))

def SignGen(message, q, p, g, alpha):
    h = SHA3_256.new(message).digest()
    hashh = int.from_bytes(h, byteorder='big') % q

    k = randint(1, q - 2)
    r = pow(g, k, p) % q
    s = ((alpha * r) - (k * hashh)) % q
    return s, r

def SignVer(message, s, r, q, p, g, beta):
    h2 = SHA3_256.new(message).digest()
    hash2 = int.from_bytes(h2, byteorder='big') % q

    v = modinv(hash2, q)
    z1 = (s * v) % q
    z2 = (r * v) % q

    u = ((pow(modinv(g,p), z1, p) * pow(beta, z2, p)) % p) % q

    if u == r:
        return 0
    else:
        return -1


def GenerateOrRead(filename):
    try:
        fh = open(filename, "r")
        line = fh.readline()
        q = int(line)
        p = int(fh.readline())
        g = int(fh.readline())
        fh.close()
        return q, p, g

    except FileNotFoundError: # therx"e is no pubparams, we need to generate p g and q
            q, p, g = Param_Generator(224, 2048)
            f = open("pubparams.txt", "w")
            f.write(str(q)+"\n" + str(p) + "\n" + str(g))
            f.close()
            return q, p, g


def KeyGen(q, p, g):
    alpha, beta = Key_Gen(q, p, g)
    return alpha, beta