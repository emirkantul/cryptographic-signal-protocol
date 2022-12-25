import math
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, SHA256
import requests
from Crypto.Random import random
from Crypto.Hash import  HMAC

API_URL = 'http://10.92.55.4:5000'

stuID = 28129 #Enter Your ID
X:0xce1a69ecc226f9e667856ce37a44e50dbea3d58e3558078baee8fe5e017a556d
Y:0x13ddaf97158206b1d80258d7f6a6880e7aaf13180e060bb1e94174e419a4a093
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
print("Server Public Identity Key:", IKey_Ser)

# Client's identity public key and private key
IKey_Pub = Point(0xf061448e9f63ae9015605c705a2fe16da20270dac4518910fb66995cdd2b30c , 0xb363aae72aefeb60b50f692c980488d160140ca373d881347ac8e1c8150eb415, curve)
IKey_Pr = 88811684008176007899207926081968991205376073643343601281773818664985783616780
print("Client Public Identity Key:", IKey_Pub)
print("Client Private Identity Key:", IKey_Pr)

'''
Identity Key generation

# Select random secret sA where 0 < sA < n-1
sA = random.randint(1, order-1)
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

# Identity Key signature generator
def generate_idk_signature(stuID, IKey_Pr, generator, order): 
    stuID_bytes = stuID.to_bytes((stuID.bit_length() +7)//8,byteorder="big")
    k = random.randint(1, order-2)
    R = k * generator
    r = (R.x) % order
    r_bytes = r.to_bytes(32, 'big')
    h = SHA3_256.SHA3_256_Hash(r_bytes+ stuID_bytes, True)
    h = SHA3_256.SHA3_256_Hash.digest(h)
    h = int.from_bytes(h,"big") % order
    s = (k + (IKey_Pr * h)) % order

    print("Signature h:", h)
    print("Signature s:", s)
    
    return h, s

'''
IK Registration signature generation 
h, s = generate_idk_signature(stuID=stuID, IKey_Pr=IKey_Pr, generator=generator, order=order)
IKRegReq(h, s, IKey_Pub.x, IKey_Pub.y)

code = 380271
'''
code = 380271

'''
IK Registration verification 
IKRegVerify(code=code, stuID=stuID, IKey_Pub=IKey_Pub)
'''
rcode = 765639

'''
#verify idk
V = s * generator + h * IKey_Pub
v = V.x % order

v_byte = v.to_bytes(32, 'big')
stuID_byte = stuID.to_bytes(2, 'big')


h2 = SHA3_256.SHA3_256_Hash(v_byte+ stuID_byte, True)
h2 = SHA3_256.SHA3_256_Hash.digest(h2)
h2 = int.from_bytes(h2,"big")
h2 = h2 % order
print(h2)

if (h == h2):
    print("Accept!") #verified
else:
    print("Not verified!") #not verified

'''



SPKey_Pr = 28443734698429915435235675841149788796036813575072998764382184205284851724196
SPKey_Pub = Point(int("0x53b28329f905959ff156edef5a760174f77068994acbdbeb0faf7881dc487e9f",base=16) , int("0x4430dd6595e5d6ad36439523d88ab239b6783e0a9506ba7ba9e5586532a9a7",base = 16), curve=curve)
print("\nSigned Pre-key Private:", SPKey_Pr)
print("Signed Pre-key Public:",SPKey_Pub)
SPKey_Pub.x:  284440755748455301221211980686918077798988279098356633098201790404106566834
SPKey_Pub.y: 45347188833655408095659911893603159693192956049050462530814683658147455843366

'''
Signed Pre-key generation

# Select random secret sA where 0 < sA < n-1
SPKey_Pr = random.randint(1, order-1)
print("SPKey_Pr:", SPKey_Pr)

# create long term public key
SPKey_pub = SPKey_Pr * generator
print("SPKey_Pub:",SPKey_pub)
print("SPKey_Pub.x:",SPKey_Pub.x)
print("SPKey_Pub.y:",SPKey_Pub.y)



SPKey_Pr: 94741850143076570100947103970147402003043264805151825233728149463189264816411
SPKey_Pub: (0x53b28329f905959ff156edef5a760174f77068994acbdbeb0faf7881dc487e9f , 0x4430dd6595e5d6ad36439523d88ab239b6783e0a9506ba7ba9e5586532a9a7)
SPKey_Pub.x:  284440755748455301221211980686918077798988279098356633098201790404106566834
SPKey_Pub.y: 45347188833655408095659911893603159693192956049050462530814683658147455843366

'''
#  Signed Pre-key signature generator
def generate_spk_signature(SPKey_Pub, IKey_Pr, generator, order): 
    xBytes = SPKey_Pub.x.to_bytes(32, 'big')
    yBytes = SPKey_Pub.y.to_bytes(32, 'big')
    msg = xBytes + yBytes
    k = random.randint(1, order-2)
    R = k * generator
    r = (R.x) % order
    #r_bytes = r.to_bytes(32, 'big')
    h = int.from_bytes(SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+msg).digest(), byteorder='big')%order
    #h = SHA3_256.SHA3_256_Hash(r_bytes+ msg, True)
    #h = SHA3_256.SHA3_256_Hash.digest(h)
    #h = int.from_bytes(h,"big") % order
    s = (k + (IKey_Pr * h)) % order

    print("Signature h:", h)
    print("Signature s:", s)
    print(curve.is_on_curve(SPKey_Pub))
    
    return h, s



msg = SPKey_Pub.x.to_bytes((SPKey_Pub.x.bit_length()+7)//8,byteorder="big") + SPKey_Pub.y.to_bytes((SPKey_Pub.y.bit_length()+7)//8,byteorder="big")
msg = int.from_bytes(msg,byteorder="big")
h, s = generate_idk_signature(msg,IKey_Pr,generator,order)
h = SPKReg(h, s, SPKey_Pub.x, SPKey_Pub.y)

#k_hmac generation
T = SPKey_Pr * SPKey_Pub
t_byte_x = T.x.to_bytes(32, 'big')
t_byte_y = T.y.to_bytes(32, 'big')
curiosity_byte = b'CuriosityIsTheHMACKeyToCreativity'
U = curiosity_byte + t_byte_y + t_byte_x 

hasher = SHA3_256.new()
hasher.update(U)
k_hmac = str(hasher.hexdigest())


#registration of otk
'''
# Select random secret sA where 0 < sA < n-1
sA0 = random.randint(1, order-1)
print("sA1 =",sA0)

sA1 = random.randint(1, order-1)
print("sA1 =",sA1)

sA2 = random.randint(1, order-1)
print("sA2 =",sA2)

sA3 = random.randint(1, order-1)
print("sA3 =",sA3)

sA4 = random.randint(1, order-1)
print("sA4 =",sA4)

sA5 = random.randint(1, order-1)
print("sA5 =",sA5)

sA6 = random.randint(1, order-1)
print("sA6 =",sA6)

sA7 = random.randint(1, order-1)
print("sA1 =",sA7)

sA8 = random.randint(1, order-1)
print("sA1 =",sA8)

sA9 = random.randint(1, order-1)
print("sA1 =",sA9)


'''
def otk_cal (k_hmac, okt):
    h_temp = HMAC.new(k_hmac, digestmod=SHA256)
    okt_x_y = okt.x.to_bytes(32, 'big') + okt.y.to_bytes(32, 'big')
    h_temp.update(okt_x_y)
    return h_temp.hexdigest()

otk_priv_arr = []

for i in range(0,10):

    otk_priv = random.randint(0, order-1) #otk_priv is private key
    print("otk_priv_ ", i ,":", otk_priv)

    otk_pub = otk_priv * generator #otk_pub is public key
    print("otk_pub_ ", i ,":",otk_pub)

    a = OTKReg(i,otk_pub.x,otk_pub.y,otk_cal(k_hmac, otk_pub))

    print("Result :", a)
    print("")
    otk_priv_arr.append(otk_priv)

print(otk_priv_arr)