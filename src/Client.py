# Melike Soyturk 28129
# Emir Kantul 27041
# CS411 Project Phase II

from random import randint
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, SHA256
import requests
from Crypto.Random import random
from Crypto.Hash import  HMAC
from Crypto.Cipher import AES

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

# Get the curve, field, order and generator
curve = Curve.get_curve('secp256k1')
field = curve.field
order = curve.order
generator = curve.generator

# Server's identity public key 
IKey_Ser = Point(0xce1a69ecc226f9e667856ce37a44e50dbea3d58e3558078baee8fe5e017a556d , 0x13ddaf97158206b1d80258d7f6a6880e7aaf13180e060bb1e94174e419a4a093, curve)
print("Server Public Identity Key:", IKey_Ser)

# Client's identity public key and private key
IKey_Pr = 54711695610845891711285415678093810504562500554097973349097378295447174968645
IKey_Pub = Point(0xeaa0b601668eba6177eb13991f611a8a3017fe64ca9635fc2b8154d3f78e1954 , 0x576cc7f8888c1291a324704a695539cf8e4f86634a4527b69cc27dcb4109c424, curve)
print("\nClient Public Identity Key:", IKey_Pub)
print("Client Private Identity Key:", IKey_Pr)

code = 103096

rcode = 368095

stuID_bytes = stuID.to_bytes((stuID.bit_length() +7)//8,byteorder="big")

# Client Signed Pre-key
SPKey_Pr = 7148617522993900837421013426385682407108504206372655816402300215068244918645
SPKey_Pub = Point(0xc313d1e58cbc227bdfa626a4fb3b2974c356ef1268a7c81128b370bfb70cd6ed , 0x3a06831a7df557e7c4b07953bf3d0b54c2a4947ece31d38a14a2eb9035fb0310, curve=curve)
SPK_Pub_Server = Point(0xbc0360774a6ae550633c37ddde5f38a0497a7a1af5f7a60bb532aaf28957344b , 0x667bc03d5faafd1d9ad4c44507ec00871ae35a63d688732c44710918ca67e5e9, curve=curve)

print("\nSigned Pre-key Private:", SPKey_Pr)
print("Signed Pre-key Public:",SPKey_Pub)
print("Server Point:", SPK_Pub_Server)


''' reset, generate and register spk
h, s = SignGen(stuID_bytes, curve, IKey_Pr)
ResetSPK(h, s)
SPKey_Pr, SPKey_Pub = KeyGen(curve)
print(SPKey_Pr, SPKey_Pub)
msg = SPKey_Pub.x.to_bytes((SPKey_Pub.x.bit_length()+7)//8,byteorder="big") + SPKey_Pub.y.to_bytes((SPKey_Pub.y.bit_length()+7)//8,byteorder="big")
h, s = SignGen(msg, curve, IKey_Pr)
resp_x, resp_y, resp_h, resp_s  = SPKReg(h, s, SPKey_Pub.x, SPKey_Pub.y)
resp_x_bytes = resp_x.to_bytes((resp_x.bit_length() + 7) // 8, byteorder='big')
resp_y_bytes = resp_y.to_bytes((resp_y.bit_length() + 7) // 8, byteorder='big')
resp_h_bytes = resp_h.to_bytes((resp_h.bit_length() + 7) // 8, byteorder='big')
resp_s_bytes = resp_s.to_bytes((resp_s.bit_length() + 7) // 8, byteorder='big')
SPK_Pub_Server = Point(resp_x, resp_y, curve)
print("Server Point:", SPK_Pub_Server)
msg = SPKey_Pub.x.to_bytes((resp_x.bit_length()+7)//8,byteorder="big") + resp_y.to_bytes((SPKey_Pub.y.bit_length()+7)//8,byteorder="big")
SignVer(resp_x_bytes + resp_y_bytes, resp_h, resp_s, curve, IKey_Ser)
SignVer(resp_x_bytes + resp_y_bytes, resp_h, resp_s, curve, SPKey_Pub)
'''


''' reset, generate and register otk 
h, s = SignGen(stuID_bytes, curve, IKey_Pr)
ResetOTK(h, s)
T = SPKey_Pr * SPK_Pub_Server
Tx_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
Ty_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
U = b'CuriosityIsTheHMACKeyToCreativity' + Ty_bytes + Tx_bytes
k_hmac = int.from_bytes(SHA3_256.new(U).digest(), 'big') % order
k_HMAC_bytes = k_hmac.to_bytes((k_hmac.bit_length() + 7) // 8, byteorder='big')
for i in range(10):
    OTK_pr, OTK0_pub = KeyGen(curve)
    print("\n", str(i) + "th OTK.")
    print("OTK private:", OTK_pr)
    print("OTK public:", OTK0_pub)
    OTK0_x_bytes = OTK0_pub.x.to_bytes((OTK0_pub.x.bit_length() + 7) // 8, byteorder='big')
    OTK0_y_bytes = OTK0_pub.y.to_bytes((OTK0_pub.y.bit_length() + 7) // 8, byteorder='big')
    hmac0 = HMAC.new(key=k_HMAC_bytes, msg=OTK0_x_bytes + OTK0_y_bytes, digestmod=SHA256)
    OTKReg(i, OTK0_pub.x, OTK0_pub.y, hmac0.hexdigest())
'''

# One-time Pre-Key
otks = [13167037760740671140990449358459659422787549909046292082689766791367774274103, 49074722223096510818794301623063439196126172231975406962576566370264994940755, 109193606621385610033924164924357328326510515039599667080037936911717042663680, 12851821767966603728446452972861951635820252187324447237533899735058956495068, 17133614516402517586196656961873571292403374292198954133874529380616771250607, 86183370604684194693656179218282742353253136442466143641850966530955737395039, 97916912925244259371666849769647438459117947622458372711824170297813704271261, 89391436421908655670061523375496840350297942660286415005713215119160832830742, 34659092723109736398157206080649439968359442116039971958727533919469528315283, 17871196282393870547677902637948970410031290577887360821746204405420314797400]
print("10 One-time Pre-Key:", otks)

# get messages from server
print("Requesting server to send pseudo messages..")
h, s = SignGen(stuID_bytes, curve, IKey_Pr)
PseudoSendMsg(h,s)

# request 5 mesages from server:
print("Requesting 5 messages from server..")
messages = []
for i in range(5):
    stuIDB, otkID, msgID, msg, ek_x, ek_y = ReqMsg(h,s)
    messages.append({
        'stuIDB': stuIDB,
        'otkID': otkID,
        'msgID': msgID,
        'msg': msg,
        'ek_x': ek_x,
        'ek_y': ek_y,
    })

# decrypt all messages given 
# messages: array of messages
def decrypt_messages(messages, otks, stuID):
    decrypted_messages = {}
    kdf_next = None

    for message in messages:
        msg = message["msg"].to_bytes((message["msg"].bit_length() +7)//8, byteorder = 'big')
        
        msg_hmac = msg[len(msg)-32:]               # hmac of the message
        message_with_nonce = msg[:len(msg)-32]     # message with nonce
        ciphertext = msg[8:len(msg)-32]            # nonce removed

        # generate session key if first iteration
        if kdf_next is None:
            ek_point = Point(message['ek_x'], message['ek_y'], curve = curve)
            T = otks[otkID] * ek_point
            U = T.x.to_bytes((T.x.bit_length() +7)//8, byteorder = 'big') + T.y.to_bytes((T.y.bit_length() +7)//8, byteorder = 'big') + b'ToBeOrNotToBe'
            k_s = SHA3_256.new(U)
            kdf_next = k_s
        else:
            kdf_next = SHA3_256.new(k_enc.digest() + k_hmac.digest() + b'MayTheForceBeWithYou')

        k_enc = SHA3_256.new(kdf_next.digest() + b'YouTalkingToMe')
        k_hmac = SHA3_256.new(kdf_next.digest() + k_enc.digest() + b'YouCannotHandleTheTruth')

        # create hmac from ciphertext
        hmac = HMAC.new(k_hmac.digest(), ciphertext, digestmod=SHA256).digest()

        # checking MAC values
        if(hmac == msg_hmac):
            print("HMAC verified")
            # decrypt message
            cipher = AES.new(k_enc.digest(), AES.MODE_CTR, nonce = message_with_nonce[0:8])
            dtext = cipher.decrypt(message_with_nonce[8:])
            decrypted_message = dtext.decode('utf-8')
            print("Decrypted message:", decrypted_message)
            Checker(stuID, message["stuIDB"], message["msgID"], decrypted_message)
            decrypted_messages[message["msgID"]] = decrypted_message

        else: 
            print("HMAC not verified")
            Checker(stuID, message["stuIDB"], message["msgID"], 'INVALIDHMAC')
            decrypted_messages[message["msgID"]] = 'INVALIDHMAC'

    return decrypted_messages

print("Decrypting messages from server")
decrypted_messages = decrypt_messages(messages=messages, otks=otks, stuID=stuID)

# display final message block
print("Retrieving deleted messages from server")
h, s = SignGen(stuID_bytes, curve, IKey_Pr)
deleted_message_ids = ReqDelMsg(h,s)

print("Deleted messages:")
for id in deleted_message_ids:
    print(decrypted_messages[id])