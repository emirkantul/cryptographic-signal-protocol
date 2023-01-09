# Melike Soyturk 28129
# Emir Kantul 27041
# CS411 Project Phase III

from random import randint
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, SHA256
import requests
from Crypto.Random import random
from Crypto.Hash import  HMAC
from Crypto.Cipher import AES

###################################### INITIALIZATIONS #############################################
API_URL = 'http://10.92.52.255:5000/'
stuIDA = 27041
stuIDB = 28129

# Get the curve, field, order and generator
curve = Curve.get_curve('secp256k1')
field = curve.field
order = curve.order
generator = curve.generator

# Server's identity public key 
IKey_Ser = Point(0xce1a69ecc226f9e667856ce37a44e50dbea3d58e3558078baee8fe5e017a556d , 0x13ddaf97158206b1d80258d7f6a6880e7aaf13180e060bb1e94174e419a4a093, curve)
SPK_Pub_Server = Point(0xbc0360774a6ae550633c37ddde5f38a0497a7a1af5f7a60bb532aaf28957344b , 0x667bc03d5faafd1d9ad4c44507ec00871ae35a63d688732c44710918ca67e5e9, curve=curve)

# Client's identity public key and private key
IKey_Pr = 54711695610845891711285415678093810504562500554097973349097378295447174968645
IKey_Pub = Point(0xeaa0b601668eba6177eb13991f611a8a3017fe64ca9635fc2b8154d3f78e1954 , 0x576cc7f8888c1291a324704a695539cf8e4f86634a4527b69cc27dcb4109c424, curve)
IKey_PrB = 88811684008176007899207926081968991205376073643343601281773818664985783616780
IKey_PubB = Point(0xf061448e9f63ae9015605c705a2fe16da20270dac4518910fb66995cdd2b30c , 0xb363aae72aefeb60b50f692c980488d160140ca373d881347ac8e1c8150eb415, curve)

code = 103096
codeB = 380271

rcode = 368095
rcodeB = 765639

stuIDA_bytes = stuIDA.to_bytes((stuIDA.bit_length() +7) // 8, byteorder = "big")
stuIDB_bytes = stuIDB.to_bytes((stuIDA.bit_length() +7) // 8, byteorder = "big")
####################################################################################################

# Given helper functions
def IKRegReq(h, s, x, y, idA):
    mes = {'ID':idA, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code, idA, IKey_Pub):
    mes = {'ID':idA, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    else:
        print(response.json())
        f = open('Identity_Key.txt', 'w')
        f.write("IK.Prv: "+str(IKey_Pr)+"\n"+"IK.Pub.x: "+str(IKey_Pub.x)+"\n"+"IK.Pub.y: "+str(IKey_Pub.y))
        f.close()

def SPKReg(h, s, x, y, idA):
    mes = {'ID':idA, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

def OTKReg(keyID, x, y, hmac, idA):
    mes = {'ID':idA, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetIK(rcode, idA):
    mes = {'ID':idA, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h, s, idA):
    mes = {'ID':idA, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(h, s, idA):
    mes = {'ID':idA, 'H': h, 'S': s}
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
def PseudoSendMsg(h, s, idA):
    mes = {'ID':idA, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

#Get your messages. server will send 1 message from your inbox
def ReqMsg(h, s, idA):
    mes = {'ID':idA, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

#Get the list of the deleted messages' ids.
def ReqDelMsg(h, s, idA):
    mes = {'ID':idA, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)      
    print(response.json())      
    if((response.ok) == True): 
        res = response.json()
        return res["MSGID"]

#If you decrypted the message, send back the plaintext for checking
def Checker(idA, idB, msgID, decmsg):
    mes = {'IDA':idA, 'IDB':idB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)	

def reqOTKB(idA, idB, h, s):
    OTK_request_msg = {'IDA': idA, 'IDB':idB, 'S': s, 'H': h}
    print("Requesting party B's OTK ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqOTK"), json=OTK_request_msg)
    print(response.json()) 
    if((response.ok) == True):
        res = response.json()
        return res['KEYID'], res['OTK.X'], res['OTK.Y']
        
    else:
        return -1, 0, 0

def Status(h, s, idA):
    mes = {'ID': idA, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']

def SendMsg(idA, idB, otkID, msgid, msg, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())    


''' reset, generate and register spk

    Globals used:
    IKey_Pr, stuID_bytes, curve
'''
def GenerateSPK(stuID_bytes, idA, IKey_Pr):
    h, s = SignGen(stuID_bytes, curve, IKey_Pr)
    ResetSPK(h, s, idA)
    SPKey_Pr, SPKey_Pub = KeyGen(curve)
    msg = SPKey_Pub.x.to_bytes((SPKey_Pub.x.bit_length()+7)//8,byteorder="big") + SPKey_Pub.y.to_bytes((SPKey_Pub.y.bit_length()+7)//8,byteorder="big")
    h, s = SignGen(msg, curve, IKey_Pr)
    resp_x, resp_y, resp_h, resp_s  = SPKReg(h, s, SPKey_Pub.x, SPKey_Pub.y, idA)
    resp_x_bytes = resp_x.to_bytes((resp_x.bit_length() + 7) // 8, byteorder='big')
    resp_y_bytes = resp_y.to_bytes((resp_y.bit_length() + 7) // 8, byteorder='big')
    msg = SPKey_Pub.x.to_bytes((resp_x.bit_length()+7)//8,byteorder="big") + resp_y.to_bytes((SPKey_Pub.y.bit_length()+7)//8,byteorder="big")
    SignVer(resp_x_bytes + resp_y_bytes, resp_h, resp_s, curve, IKey_Ser)
    SignVer(resp_x_bytes + resp_y_bytes, resp_h, resp_s, curve, SPKey_Pub)
    return SPKey_Pr, SPKey_Pub

''' reset, generate and register otk

    Globals used:
    IKey_Pr, stuID_bytes, SPKey_Pr, SPK_Pub_Server, curve
'''
def GenerateOTKS(stuID_bytes, idA, IKey_Pr, SPKey_Pr, SPK_Pub_Server, number_of_otks):
    otks = {}
    h, s = SignGen(stuID_bytes, curve, IKey_Pr)
    ResetOTK(h, s, idA)
    T = SPKey_Pr * SPK_Pub_Server
    Tx_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
    Ty_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
    U = b'CuriosityIsTheHMACKeyToCreativity' + Ty_bytes + Tx_bytes
    k_hmac = int.from_bytes(SHA3_256.new(U).digest(), 'big') % order
    k_HMAC_bytes = k_hmac.to_bytes((k_hmac.bit_length() + 7) // 8, byteorder='big')
    for i in range(number_of_otks):
        OTK_pr, OTK0_pub = KeyGen(curve)
        otks[i] = OTK_pr
        print("\n", str(i) + "th OTK.")
        print("OTK private:", OTK_pr)
        print("OTK public:", OTK0_pub)
        OTK0_x_bytes = OTK0_pub.x.to_bytes((OTK0_pub.x.bit_length() + 7) // 8, byteorder='big')
        OTK0_y_bytes = OTK0_pub.y.to_bytes((OTK0_pub.y.bit_length() + 7) // 8, byteorder='big')
        hmac0 = HMAC.new(key = k_HMAC_bytes, msg=OTK0_x_bytes + OTK0_y_bytes, digestmod = SHA256)
        OTKReg(i, OTK0_pub.x, OTK0_pub.y, hmac0.hexdigest(), idA)
    return otks


# reset and generate spk and otks in case for client A
SPKey_Pr, SPKey_Pub = GenerateSPK(stuIDA_bytes, stuIDA, IKey_Pr)
otks = GenerateOTKS(stuIDA_bytes, stuIDA, IKey_Pr, SPKey_Pr, SPK_Pub_Server, 10)

# reset and generate spk and otks in case for client B
SPKey_PrB, SPKey_PubB = GenerateSPK(stuIDB_bytes, stuIDB, IKey_PrB)
otksB = GenerateOTKS(stuIDB_bytes, stuIDB, IKey_PrB, SPKey_PrB, SPK_Pub_Server, 10)


print("Server Public Identity Key:", IKey_Ser)
print("Server Point:", SPK_Pub_Server)

print("\n*****************************************************************************************")
print("Client A:", stuIDA)
print("Public Identity Key:", IKey_Pub)
print("Private Identity Key:", IKey_Pr)
print("\nSigned Pre-key Private:", SPKey_Pr)
print("Signed Pre-key Public:", SPKey_Pub)
print("10 One-time Pre-Key:", otks)
print("*****************************************************************************************\n")
print("\n*****************************************************************************************")
print("Client B:", stuIDB)
print("Public Identity Key:", IKey_PubB)
print("Private Identity Key:", IKey_PrB)
print("\nSigned Pre-key Private:", SPKey_PrB)
print("Signed Pre-key Public:", SPKey_PubB)
print("10 One-time Pre-Key:", otksB)
print("*****************************************************************************************\n")

# function: request n messages
def requestMessages(h, s, n, idA):
    print("Requesting", n, "messages from server..")
    messages = []
    for i in range(n):
        idB, otkID, msgID, msg, ek_x, ek_y = ReqMsg(h, s, idA)
        messages.append({
            'stuIDB': idB,
            'otkID': otkID,
            'msgID': msgID,
            'msg': msg,
            'ek_x': ek_x,
            'ek_y': ek_y,
        })
    return messages

# function: decrypt given messages
def decrypt_messages(messages, otks, idA):
    decrypted_messages = {}
    kdf_next = None

    for message in messages:
        msg = message["msg"].to_bytes((message["msg"].bit_length() +7) // 8, byteorder = 'big')
        
        msg_hmac = msg[len(msg)-32:]               # hmac of the message
        message_with_nonce = msg[:len(msg)-32]     # message with nonce
        ciphertext = msg[8:len(msg)-32]            # nonce removed

        # generate session key if first iteration
        if kdf_next is None:
            ek_point = Point(message['ek_x'], message['ek_y'], curve = curve)
            T = otks[message["otkID"]] * ek_point
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
            Checker(idA, message["stuIDB"], message["msgID"], decrypted_message)
            decrypted_messages[message["msgID"]] = decrypted_message

        else: 
            print("HMAC not verified")
            Checker(stuIDA, message["stuIDB"], message["msgID"], 'INVALIDHMAC')
            decrypted_messages[message["msgID"]] = 'INVALIDHMAC'

    return decrypted_messages

# function: encrypt and send given messages
def encrypt_and_send_messages(messages, idA, idB, otkPubB, idKey):
    msgID = 0
    kdf_next = None
    EkPrivA, EkPubA = KeyGen(curve)
    T = EkPrivA * otkPubB 
    U = (T.x).to_bytes(((T.x).bit_length()+7)//8, "big") + (T.y).to_bytes(((T.y).bit_length()+7)//8, "big") + b'ToBeOrNotToBe'
    k_s = SHA3_256.new(U).digest()

    print("T:",T)
    print("U:",U)
    print("k_s:", k_s)

    for message in messages:
        # generate session key if first iteration
        if kdf_next is None:
            k_s = SHA3_256.new(U)
            kdf_next = k_s
        else:
            kdf_next = SHA3_256.new(k_enc.digest() + k_hmac.digest() + b'MayTheForceBeWithYou')

        k_enc = SHA3_256.new(kdf_next.digest() + b'YouTalkingToMe')
        k_hmac = SHA3_256.new(kdf_next.digest() + k_enc.digest() + b'YouCannotHandleTheTruth')

        cipher = AES.new(k_enc.digest(), AES.MODE_CTR)
        ctext = cipher.nonce + cipher.encrypt(bytes(message, 'utf-8'))
        print("Cipher text after encryption:", ctext)

        hmac = HMAC.new(k_hmac.digest(), digestmod = SHA256).update(ctext).digest()
        msg = ctext + hmac
        print("Final message: ", msg)
        int_msg = int.from_bytes(msg, byteorder = "big")
        SendMsg(idA, idB, idKey, msgID, int_msg, EkPubA.x, EkPubA.y) 
        msgID += 1


# get otk of client B from server
print("Requesting client B's public OTK")
h, s = SignGen(stuIDB_bytes, curve, IKey_Pr)
idKey, otkX, otkY = reqOTKB(stuIDA, stuIDB, h, s)
otkPubB = Point(otkX, otkY, curve) #public client
print()

# check status
print("Checking client B's status..")
h, s = SignGen(stuIDB_bytes, curve, IKey_PrB)
numMSG, numOTK, statusMSG = Status(h, s, stuIDB)
print("Status message:", statusMSG)
print("Is there enough OTK keys to read all messages:", numOTK >= numMSG, "\n")

messages_to_send = [
    "myMessage0",
    "myMessage1",
    "myMessage2",
    "myMessage3",
    "myMessage4"
]
print("Messages to send to client B:", messages_to_send)

# sent 5 messages from client A to client B
encrypt_and_send_messages(messages_to_send, stuIDA, stuIDB, otkPubB, idKey)

# receive 5 messages of client B
h, s = SignGen(stuIDB_bytes, curve, IKey_PrB)
messages = requestMessages(h, s, 5, stuIDB)

# decrypt receive messages
decrypted_messages = decrypt_messages(messages, otksB, stuIDB)

# check status
print("Checking client B's status again..")
h, s = SignGen(stuIDB_bytes, curve, IKey_PrB)
numMSG, numOTK, statusMSG = Status(h, s, stuIDB)
print("Status message:", statusMSG)

