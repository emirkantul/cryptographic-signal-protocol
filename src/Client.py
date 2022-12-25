# Melike Soyturk 28129
# Emir Kantul 27041
# CS411 Project Phase I

from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, SHA256
import requests
from Crypto.Random import random
from Crypto.Hash import  HMAC

# NOTE: 
# Parts for key generation and registration are commented to 
# prevent repeated key generation and request to servers. After
# getting appropriate results, static variables used and rest
# is commented. For full functionality and test those sections
# should be uncommented.
    
# Also all methods were tried with the other member's student id as well

API_URL = 'http://10.92.55.4:5000'

stuID = 27041 #Enter Your ID

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

# Signature Generator
def generate_signature(msg, sA, generator, order):
    k = random.randint(1, order-2)
    R = k * generator
    r = (R.x) % order
    r_bytes = r.to_bytes(32, 'big')
    h = SHA3_256.SHA3_256_Hash(r_bytes + msg, True)
    h = SHA3_256.SHA3_256_Hash.digest(h)
    h = int.from_bytes(h,"big") % order
    s = (k + (sA * h)) % order

    print("\nSignature h:", h)
    print("Signature s:", s)
    
    return h, s

# Private key generator
def generate_private_key(order, generator):
    print("\nGenerating private and public keys..")
    # Select random secret sA where 0 < sA < n-1
    sA = random.randint(1, order-1)
    print("sA =",sA)

    # create long term public key
    sA_pub = sA*generator
    print("sA_pub =",sA_pub)
    print("sA_pub.x =",sA_pub.x)
    print("sA_pub.y =",sA_pub.y)

    return sA, sA_pub

def verify_signature(h, s, qA, msg, order, generator):
    V = s * generator - h * qA
    v = V.x % order

    v_byte = v.to_bytes(32, 'big')

    h2 = SHA3_256.SHA3_256_Hash(v_byte+ msg, True)
    h2 = SHA3_256.SHA3_256_Hash.digest(h2)
    h2 = int.from_bytes(h2,"big")
    h2 = h2 % order
    print(h2)

    if (h == h2):
        print("Signature verified!") #verified
    else:
        print("Signature not verified!") #not verified


# Server's identity public key 
IKey_Ser = Point(0xce1a69ecc226f9e667856ce37a44e50dbea3d58e3558078baee8fe5e017a556d , 0x13ddaf97158206b1d80258d7f6a6880e7aaf13180e060bb1e94174e419a4a093, curve)
print("Server Public Identity Key:", IKey_Ser)

# Client's identity public key and private key
IKey_Pr = 54711695610845891711285415678093810504562500554097973349097378295447174968645
IKey_Pub = Point(0xeaa0b601668eba6177eb13991f611a8a3017fe64ca9635fc2b8154d3f78e1954 , 0x576cc7f8888c1291a324704a695539cf8e4f86634a4527b69cc27dcb4109c424, curve)
print("\nClient Public Identity Key:", IKey_Pub)
print("Client Private Identity Key:", IKey_Pr)

'''
# Identity Key generation
IKey_Pr, IKey_Pub = generate_private_key(order, generator)

# IKey_Pr: 54711695610845891711285415678093810504562500554097973349097378295447174968645
# IKey_Pub: (0xeaa0b601668eba6177eb13991f611a8a3017fe64ca9635fc2b8154d3f78e1954 , 0x576cc7f8888c1291a324704a695539cf8e4f86634a4527b69cc27dcb4109c4240x576cc7f8888c1291a324704a695539cf8e4f86634a4527b69cc27dcb4109c424)
# IKey_Pub.x: 106125158254444507586124357737838011183233385576686272071348298652513412716884
# IKey_Pub.y: 39543417457710120237121373054221395027999800633142105468250786347587046327332
'''


'''
IK Registration signature generation 

stuID_bytes = stuID.to_bytes((stuID.bit_length() +7)//8,byteorder="big")
h, s = generate_signature(msg=stuID_bytes, sA=IKey_Pr, generator=generator, order=order)
IKRegReq(h, s, IKey_Pub.x, IKey_Pub.y)

code = 103096
'''
code = 103096

'''
# IK Registration verification 
IKRegVerify(code=code, stuID=stuID, IKey_Pub=IKey_Pub)
'''
rcode = 368095


# Client Signed Pre-key
SPKey_Pr = 24373054577699454663564151012111011615866473942778748787713915925292914841793
SPKey_Pub = Point(int("0xc763f5b6ca6fc8fb746d204b99fd47df2a79056d668dc613894c55bdff47398d",base=16) , int("0x5b7cf45b7ee2d189189fa38d47a6cbb2b986bf539620b2695840711bc32c9333",base = 16), curve=curve)
print("\nSigned Pre-key Private:", SPKey_Pr)
print("Signed Pre-key Public:",SPKey_Pub)

'''
# Signed Pre-key generation

SPKey_Pr, SPKey_pub = generate_private_key(order, generator)

# SPKey_Pr: 24373054577699454663564151012111011615866473942778748787713915925292914841793
# SPKey_Pub: (0xc763f5b6ca6fc8fb746d204b99fd47df2a79056d668dc613894c55bdff47398d , 0x5b7cf45b7ee2d189189fa38d47a6cbb2b986bf539620b2695840711bc32c9333)
# SPKey_Pub.x:  90186870583367397078994984968597413955227984672863262182290021294247000881549
# SPKey_Pub.y: 41381244749936181075457993058941167828970061873112217764976555947988353848115
'''


'''
# SPK Registration signature generation 

msg = SPKey_Pub.x.to_bytes((SPKey_Pub.x.bit_length()+7)//8,byteorder="big") + SPKey_Pub.y.to_bytes((SPKey_Pub.y.bit_length()+7)//8,byteorder="big")
h, s = generate_signature(msg=msg, sA=IKey_Pr, generator=generator, order=order)
resp_x, resp_y, resp_h, resp_s  = SPKReg(h, s, SPKey_Pub.x, SPKey_Pub.y)

# Server Point: (0x7d38f788a09a94b29ef81b95e812816889e9d2fcbbd51909c94cbda2e9bcc736 , 0x8585933fcc79add8ab5bb6a824e5170b68d82c12a543b1576610dd4210775333)
'''


'''
# Signature Verification

resp_x_bytes = resp_x.to_bytes((resp_x.bit_length() + 7) // 8, byteorder='big')
resp_y_bytes = resp_y.to_bytes((resp_y.bit_length() + 7) // 8, byteorder='big')
resp_h_bytes = resp_h.to_bytes((resp_h.bit_length() + 7) // 8, byteorder='big')
resp_s_bytes = resp_s.to_bytes((resp_s.bit_length() + 7) // 8, byteorder='big')
resp_msg = resp_x_bytes + resp_y_bytes
SPK_Pub_Server = Point(resp_x, resp_y, curve)
print("Server Point:", SPK_Pub_Server)

msg = SPKey_Pub.x.to_bytes((resp_x.bit_length()+7)//8,byteorder="big") + resp_y.to_bytes((SPKey_Pub.y.bit_length()+7)//8,byteorder="big")
verify_signature(h=resp_h, s=resp_s, qA=IKey_Ser, msg=resp_msg, order=order, generator=generator)
msg = SPKey_Pub.x.to_bytes((resp_x.bit_length()+7)//8,byteorder="big") + resp_y.to_bytes((SPKey_Pub.y.bit_length()+7)//8,byteorder="big")
verify_signature(resp_h, resp_s, SPKey_Pub, msg, order, generator)
'''
SPK_Pub_Server = Point(0x7d38f788a09a94b29ef81b95e812816889e9d2fcbbd51909c94cbda2e9bcc736 , 0x8585933fcc79add8ab5bb6a824e5170b68d82c12a543b1576610dd4210775333, curve=curve)


# Generating HMAC Key
T = SPKey_Pr * SPK_Pub_Server
Tx_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
Ty_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
U = b'CuriosityIsTheHMACKeyToCreativity' + Ty_bytes + Tx_bytes
hashVal3 = SHA3_256.new(U)
k_HMAC = int.from_bytes(hashVal3.digest(), 'big') % order
k_HMAC_bytes = k_HMAC.to_bytes((k_HMAC.bit_length() + 7) // 8, byteorder='big')
print("\nT: ({} , {})".format(hex(T.x), hex(T.y)))
print("U:",U)
print("HMAC key:", k_HMAC_bytes)


# Create and register OTKs
for i in range(10):
    OTK_pr, OTK0_pub = generate_private_key(order=order, generator=generator)
    print("\n", str(i) + "th OTK.")
    print("OTK private:", OTK_pr)
    print("OTK public:", OTK0_pub)
    OTK0_x_bytes = OTK0_pub.x.to_bytes((OTK0_pub.x.bit_length() + 7) // 8, byteorder='big')
    OTK0_y_bytes = OTK0_pub.y.to_bytes((OTK0_pub.y.bit_length() + 7) // 8, byteorder='big')
    temp = OTK0_x_bytes + OTK0_y_bytes
    hmac0 = HMAC.new(key=k_HMAC_bytes, msg=temp, digestmod=SHA256)
    OTKReg(i, OTK0_pub.x, OTK0_pub.y, hmac0.hexdigest())