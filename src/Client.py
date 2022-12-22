import math
import time
import sympy
import warnings
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import re
import json


API_URL = 'http://10.92.55.4:5000'

stuID = 28129 #Enter Your ID

# Given helper functions
def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code, stuID, IKey_Pub):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    else:
        print(response.json())
        f = open('Identity_Key.txt', 'w')
        f.write("IK.Prv: "+str(IKey_Pr)+"\n"+"IK.Pub.x: "+str(IKey_Pub.x)+"\n"+"IK.Pub.y: "+str(IKey_Pub.y))
        f.close()

def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    if((response.ok) == False): print(response.json())

# Get the curve, field, order and generator
curve = Curve.get_curve('secp256k1')
field = curve.field
order = curve.order
generator = curve.generator

# Server's identity public key 
IKey_Ser = Point(0xce1a69ecc226f9e667856ce37a44e50dbea3d58e3558078baee8fe5e017a556d , 0x13ddaf97158206b1d80258d7f6a6880e7aaf13180e060bb1e94174e419a4a093, curve)

# Client's identity public key and private key
IKey_Pub = Point(0xf061448e9f63ae9015605c705a2fe16da20270dac4518910fb66995cdd2b30c , 0xb363aae72aefeb60b50f692c980488d160140ca373d881347ac8e1c8150eb415, curve)
IKey_Pr = 88811684008176007899207926081968991205376073643343601281773818664985783616780

'''
Identity Key generation

# Select random secret sA where 0 < sA < n-1
sA = Random.new().read(int(math.log(order - 1, 2)))
sA = int.from_bytes(sA, byteorder = 'big') % order
print("sA =",sA)

# create long term public key
Ik_pub = sA*generator
print("Ik_pub =",Ik_pub)
print("Ik_pub.x =",Ik_pub.x)
print("Ik_pub.y =",Ik_pub.y)

sA = 88811684008176007899207926081968991205376073643343601281773818664985783616780
Ik_pub = (0xf061448e9f63ae9015605c705a2fe16da20270dac4518910fb66995cdd2b30c , 0xb363aae72aefeb60b50f692c980488d160140ca373d881347ac8e1c8150eb415)
Ik_pub.x = 6795433811819819131752285391518736675983624010180123841332452236942390768396
Ik_pub.y = 81140097284966191459956522116616668579410872729031413673803328453907451917333
'''

# Signature generator
def generate_signature(stuID, IKey_Pr, generator, order): 
    stuID_bytes = stuID.to_bytes(2,byteorder="big")
    k = random.randint(1, order-1)
    R = k * generator
    r = (R.x) % order
    r_bytes = r.to_bytes(32, 'big')
    h = SHA3_256.SHA3_256_Hash(r_bytes+ stuID_bytes, True)
    h = SHA3_256.SHA3_256_Hash.digest(h)
    h = int.from_bytes(h,"big") % order
    s = (k + (IKey_Pr*h)) % order

    print("h =", h)
    print("s =", s)
    return h, s

'''
Registration signature generation 
h, s = generate_signature(stuID=stuID, IKey_Pr=IKey_Pr, generator=generator, order=order)
IKRegReq(h, s, IKey_Pub.x, IKey_Pub.y)

code = 380271
'''

code = 380271
'''
Registration verification 
IKRegVerify(code=code, stuID=stuID, IKey_Pub=IKey_Pub)

rcode = 765639
'''
#signature for SPK
h, s = generate_signature(stuID=stuID, IKey_Pr=IKey_Pr, generator=generator, order=order)
V = s * generator + h * IKey_Pub
v = V.x % order

v_byte = v.to_bytes(32, 'big')
stuID_byte = stuID.to_bytes(2, 'big')

h_new = SHA3_256.SHA3_256_Hash(v_byte+ stuID_byte, True)
h_new = SHA3_256.SHA3_256_Hash.digest(h_new)
h_new = int.from_bytes(h_new,"big")
h_new = h_new % order

if (h == h_new):
    print("Your h and h_new is same, verified") #verified
else:
    print("Your h and h_new is not the same, not verified!") #not verified
