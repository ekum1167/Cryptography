import random
import sys
from Crypto.Hash import SHA3_256
from ecpy.curves import Curve


def egcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y


def modinv(a, m):
    if a < 0:
        a = a + m
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m




E = Curve.get_curve('secp256k1')

def KeyGen(E):
  n = E.order
  P = E.generator
  S_A = random.randint(0,n)
  Q_A= S_A*P
  return S_A, Q_A

#S_A secret key
def SignGen(message, E, SA):
    n = E.order
    P = E.generator
    h = SHA3_256.new(message).digest()
    hashh = int.from_bytes(h, byteorder='big') % n
    k = random.randint(2,n-1)
    R = k*P
    r = R.x % n
    s = (SA*r - k*hashh) %n
    return (s,r)
    

def SignVer(message, s, r, E, QA):
    n = E.order
    P = E.generator
    h = SHA3_256.new(message).digest()
    hashh = int.from_bytes(h, byteorder='big') % n
    v = modinv(hashh, n)
    z_1 = (s*v) %n
    z_2 = (r*v) %n
    u = ((n-z_1)*P + z_2*QA )
    if  (u.x )%n == r:
       return 0
    else:
        return -1
    


