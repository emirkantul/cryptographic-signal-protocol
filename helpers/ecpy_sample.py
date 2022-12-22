# Run "pip install ecpy" if ecpy is not installed
from random import randint, seed
from ecpy.curves import Curve
from Crypto.Hash import SHA3_256
from Crypto import Random   # a bit better secure random number generation 
import math

E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b
print("Base point:\n", P)
print("p :", p)
print("a :", a)
print("b :", b)
print("n :", n)

k = Random.new().read(int(math.log(n,2)))
k = int.from_bytes(k, byteorder='big')%n

Q = k*P
print("\nQ:\n", Q)
print("Q on curve?", E.is_on_curve(Q))
