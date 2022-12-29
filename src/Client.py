# Melike Soyturk 28129
# Emir Kantul 27041
# CS411 Project Phase II

from random import randint
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, SHA256
import requests
from Crypto.Random import random
from Crypto.Hash import  HMAC
    
API_URL = 'http://10.92.52.255:5000/'

stuIDB = 2014
stuID = 27041

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
IKey_Pr, IKey_Pub = generate_private_key(order, generator)
'''


'''
IK Registration signature generation 
stuID_bytes = stuID.to_bytes((stuID.bit_length() +7)//8,byteorder="big")
h, s = generate_signature(msg=stuID_bytes, sA=IKey_Pr, generator=generator, order=order)
IKRegReq(h, s, IKey_Pub.x, IKey_Pub.y)
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
'''


'''
# SPK Registration signature generation
msg = SPKey_Pub.x.to_bytes((SPKey_Pub.x.bit_length()+7)//8,byteorder="big") + SPKey_Pub.y.to_bytes((SPKey_Pub.y.bit_length()+7)//8,byteorder="big")
h, s = generate_signature(msg=msg, sA=IKey_Pr, generator=generator, order=order)
resp_x, resp_y, resp_h, resp_s  = SPKReg(h, s, SPKey_Pub.x, SPKey_Pub.y)

# Signature Verification
resp_x_bytes = resp_x.to_bytes((resp_x.bit_length() + 7) // 8, byteorder='big')
resp_y_bytes = resp_y.to_bytes((resp_y.bit_length() + 7) // 8, byteorder='big')
resp_h_bytes = resp_h.to_bytes((resp_h.bit_length() + 7) // 8, byteorder='big')
resp_s_bytes = resp_s.to_bytes((resp_s.bit_length() + 7) // 8, byteorder='big')
resp_msg = resp_x_bytes + resp_y_bytes
SPK_Pub_Server = Point(resp_x, resp_y, curve)
msg = SPKey_Pub.x.to_bytes((resp_x.bit_length()+7)//8,byteorder="big") + resp_y.to_bytes((SPKey_Pub.y.bit_length()+7)//8,byteorder="big")
verify_signature(h=resp_h, s=resp_s, qA=IKey_Ser, msg=resp_msg, order=order, generator=generator)
msg = SPKey_Pub.x.to_bytes((resp_x.bit_length()+7)//8,byteorder="big") + resp_y.to_bytes((SPKey_Pub.y.bit_length()+7)//8,byteorder="big")
verify_signature(resp_h, resp_s, SPKey_Pub, msg, order, generator)
'''

SPK_Pub_Server = Point(0x7d38f788a09a94b29ef81b95e812816889e9d2fcbbd51909c94cbda2e9bcc736 , 0x8585933fcc79add8ab5bb6a824e5170b68d82c12a543b1576610dd4210775333, curve=curve)
print("Server Point:", SPK_Pub_Server)


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

#####################################################################################
###################################### PHASE 2 ######################################
#####################################################################################

# phase 2 helpers

API_URL = 'http://10.92.52.255:5000/'

stuID = 26045
stuIDB = 2014

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

def Setup():
    E = Curve.get_curve('secp256k1')
    return E

def KeyGen(E):
    n = E.order
    P = E.generator
    sA = randint(1,n-1)
    QA = sA*P
    return sA, QA

def SignGen(message, E, sA):
    n = E.order
    P = E.generator
    k = randint(1, n-2)
    R = k*P
    r = R.x % n
    h = int.from_bytes(SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    s = (sA*h + k) % n
    return h, s

def SignVer(message, h, s, E, QA):
    n = E.order
    P = E.generator
    V = s*P - h*QA
    v = V.x % n
    h_ = int.from_bytes(SHA3_256.new(v.to_bytes((v.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    if h_ == h:
        return True
    else:
        return False

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

#Get your messages. server will send 1 message from your inbox
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

#Get the list of the deleted messages' ids.
def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)      
    print(response.json())      
    if((response.ok) == True): 
        res = response.json()
        return res["MSGID"]

#If you decrypted the message, send back the plaintext for checking
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)	


# OTK data
otk_private = [81661962775791531255393590218032810348611196057800092950972910673728483913293, 52808665550935137250118206376573576203141304345939680267257950392200540207015, 28886528209940086927211574720079351376569346129303597582466848064924258131196, 11114466964466141026367702073664155613887604275985718533928007399121172719121, 17166357728138738026932544999677587823688912721806684576840951659670965088038, 89828764614649288349946443494126545878918699713795459712736909795019648787538, 48168878674606644491705808962129225172098876787988203995044137678806445123558, 91179985255603002478337425498383773831413918717804015885447630247048388959701, 82924893139980026608916710627158509866282852529554964410349276866878225755082, 90870193415124165058039276172179735704530307717037153962822467285881689168350]

# Signing my stuID with my private IK in order to get messages from the server:
k = random.randint(1, order - 2)
R = k * generator
r = R.x % order

r_byte_array = r.to_bytes((r.bit_length() +7)//8, byteorder = 'big')
m_byte_array = stuID.to_bytes((stuID.bit_length() +7)//8, byteorder = 'big')
r_m = r_byte_array + m_byte_array #concatenation of r and m where m is stuID

h = SHA3_256.new(r_m)
h = int.from_bytes(h.digest(), byteorder='big') % order

s = (k - (IKey_Pr * h)) % order
print("s:", s)
print("h:", h)

PseudoSendMsg(h,s)

# requesting messages from the server:
otkID_array = []
msgID_array = []
msg_array = []
for i in range(5):
    stuIDB, otkID, msgID, msg, ek_x, ek_y = ReqMsg(h,s)
    msg_array.append(msg)
    otkID_array.append(otkID)
    msgID_array.append(msgID)

first_iteration = True
counter = 0
for message in msg_array:
    message_byte_array = message.to_bytes((message.bit_length() +7)//8, byteorder = 'big')
    
    # hmac of the message
    message_HMAC = message_byte_array[len(message_byte_array)-32:]
    #print(message_HMAC) 

    # nonce and the ciphertext
    message_with_nonce = message_byte_array[:len(message_byte_array)-32]
    #print(message_with_nonce)

    # ciphertext
    ciphertext = message_byte_array[8:len(message_byte_array)-32]
    #print(ciphertext)


    # _session key generation start_
    EK_B_point = Point(ek_x, ek_y, curve = curve)
    T = otk_private[otkID] * EK_B_point
    T_x = T.x
    T_y = T.y

    T_x_byte_array = T_x.to_bytes((T_x.bit_length() +7)//8, byteorder = 'big')
    T_y_byte_array = T_y.to_bytes((T_y.bit_length() +7)//8, byteorder = 'big')
    U = T_x_byte_array + T_y_byte_array + b'ToBeOrNotToBe'

    K_S = SHA3_256.new(U)
    # _session key generation end_

    # _key derivation start_
    if(first_iteration):
        K_KDF = K_S
        first_iteration = False
    else:
        K_KDF = SHA3_256.new(K_ENC.digest() + K_HMAC.digest() + b'MayTheForceBeWithYou')

    K_ENC = SHA3_256.new(K_KDF.digest() + b'YouTalkingToMe')
    K_HMAC = SHA3_256.new(K_KDF.digest() + K_ENC.digest() + b'YouCannotHandleTheTruth')
    # _key derivation end_

    # obtaining hmac from ciphertext
    hmac = HMAC.new(K_HMAC.digest(), ciphertext, digestmod=SHA256)
    hmac = hmac.digest()

    # checking MAC values
    if(hmac == message_HMAC):
        print("HMAC is verified")

        # dencryption of the message
        cipher = AES.new(K_ENC.digest(), AES.MODE_CTR, nonce = message_with_nonce[0:8])
        dtext = cipher.decrypt(message_with_nonce[8:])
        decrypted_message = dtext.decode('utf-8')

        print("Decrypted message:", decrypted_message)

        # cheking decrypted message
        Checker(stuID, stuIDB, msgID_array[counter], decrypted_message)
    else: 
        print("HMAC is not verified")
        Checker(stuID, stuIDB, msgID_array[counter], 'INVALIDHMAC')

    counter = counter + 1

