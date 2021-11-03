import socket
import threading
from Crypto import Random
from Crypto.Cipher import AES
import string
import random
import base64
import sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, MD5

# 서버 연결정보; 자체 서버 실행시 변경 가능
SERVER_HOST = "homework.islab.work"
SERVER_PORT = 8080

connectSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connectSocket.connect((SERVER_HOST, SERVER_PORT))

global Key 
Key=''

global IVKey
IVKey=''

global recvKey
recvKey = ''

global recvIVKey
recvIVKey = ''

global tempKey
tempKey = ''

global tempIVKey
tempIVKey = ''

global recvClientID
recvClientID = ''

global myID
myID = ''

global exKeyEXCHFlag
exKeyEXCHFlag = 0

global recvPubkey
recvPubKey = ''

global privateKey
privateKey = ''

global Algorithm
Algorithm = ["AES-256-CBC"]

def socket_read():
    while True:
        readbuff = connectSocket.recv(2048)

        if len(readbuff) == 0:
            continue

        recv_payload = readbuff.decode('utf-8')
        parse_payload(recv_payload)

def socket_send():
    while True:
        str = input("MESSAGE: ")
        if(str.split()[1]=="CONNECT"):
            str1 = input("Credential: ")
            global myID
            global tempKey
            global tempIVKey
            myID = str1
            str = str+"\nCredential:"+str1
        elif(str.split()[1]=="DISCONNECT"):
            str1 = input("Credential: ")
            str = str+"\nCredential:"+str1
        elif(str.split()[1]=="KEYXCHG"):
            str1 = input("Algo: ")
            str2 = input("From: ")
            str3 = input("To: ")
            print("")
            str4 = createRandomKey(32)
            print(str4)
            tempKey = str4.encode('ascii')
            str5 = createRandomKey(16)
            print(str5)
            tempIVKey= str5.encode('ascii')
            print("")
            str = str+"\nAlgo:"+str1+"\nFrom:"+str2+"\nTo:"+str3+"\n\n"+str4+"\n"+str5
        elif(str.split()[1]=="KEYXCHGRST"):
            str1 = input("Algo: ")
            str2 = input("From: ")
            str3 = input("To: ")
            print("")
            str4 = createRandomKey(32)
            print(str4)
            tempKey = str4.encode('ascii')
            str5 = createRandomKey(16)
            print(str5)
            tempIVKey= str5.encode('ascii')
            print("")
            str = str+"\nAlgo:"+str1+"\nFrom:"+str2+"\nTo:"+str3+"\n\n"+str4+"\n"+str5
        elif(str.split()[1]=="MSGSEND"):
            str1 = input("From: ")
            str2 = input("To: ")
            str3 = input("Nonce: ")
            print("")
            print("")
            str4 = input("")
            str4 = encryptAES(str4)
            str = str+"\nFrom:"+str1+"\nTo:"+str2+"\nNonce:"+str3+"\n\n"+str4

        send_bytes = str.encode('utf-8')
        connectSocket.sendall(send_bytes)

def encryptAES(data):
    global Key
    global IVKey
    if (len(data)%16!=0):
        data = data+('\n'*(16-len(data)%16))
    data = data.encode()
    mycrypto = AES.new(Key, AES.MODE_CBC, IVKey)
    enc = mycrypto.encrypt(data)
    enc = base64.b64encode(enc)
    enc = enc.decode('ascii')
    return enc

def decryptAES(enc):
    global Key
    global IVKey
    temp = base64.b64decode(enc)
    if(sys.getsizeof(temp)%16!=0):
        enc = enc+('\n'*(16-sys.getsizeof(temp)%16))
    enc = base64.b64decode(enc)
    mycrypto = AES.new(Key, AES.MODE_CBC, IVKey)
    dec = mycrypto.decrypt(enc)
    dec = dec.decode('utf-8')
    dec = dec.split('\n')[0]
    return dec

def createRandomKey(length):
    key = ''.join(random.choice(string.ascii_letters+string.digits+string.punctuation) for _ in range(length))
    return key

def parse_payload(payload):
    # 수신된 페이로드를 여기서 처리; 필요할 경우 추가 함수 정의 가능
    message = payload.split()
    global Algorithm
    global recvKey
    global recvIVKey
    global Key
    global IVKey
    global exKeyEXCHFlag
    global tempKey
    global tempIVKey
    if(message[1]=="KEYXCHG"):
        if(message[2].split(':')[1]==Algorithm[0]):
            keyxchg = payload.split('\n')
            recvKey = keyxchg[6]
            recvIVKey = keyxchg[7]
            if(exKeyEXCHFlag == 0):
                Key = recvKey.encode('ascii')
                IVKey = recvIVKey.encode('ascii')
                sendKeyCHGOK(0, message[4].split(':')[1],message[3].split(':')[1])
                exKeyEXCHFlag = 1  
            else:
                sendKeyCHGFail(0, message[4].split(':')[1],message[3].split(':')[1])
            print("")
    elif(message[1]=='KEYXCHGOK'):
        keyxchgok = payload.split('\n')
        exKeyEXCHFlag = 1
        Key = tempKey
        IVKey = tempIVKey
        print(keyxchgok[0])
        print(keyxchgok[1])
        print(keyxchgok[2])
        print(keyxchgok[4])
        print("")
    elif(message[1]=='KEYXCHGRST'):
        recvKey = message[6]
        recvIVKey = message[7]
        Key = recvKey
        IVKey = recvIVKey
        sendKeyCHGOK(0, message[4].split(':')[1],message[3].split(':')[1])
        exKeyEXCHFlag = 1
        print("")
    elif(message[1]=='MSGRECV'):
        msgsend = payload.split('\n')
        encryptTXT = msgsend[5]
        plain = decryptAES(encryptTXT)
        print(msgsend[0])
        print(msgsend[1])
        print(msgsend[2])
        print(msgsend[3])
        print(msgsend[4])
        print("")
        print(plain)
        print("")
        #sendMsgOk(msgsend[3].split(':')[1], msgsend[1].split(':')[1], msgsend[2].split(':')[1])
    
    else:
        print(payload)
def sendMsgOk(nonce, fromC, toC):
    send_bytes = "3EPROTO MSGSENDOK"+"\nNonce:"+nonce+"\nFrom:"+fromC+"\nTo:"+toC
    send_bytes = send_bytes.encode('utf-8')
    connectSocket.sendall(send_bytes)

def sendKeyCHGFail(mode,fromC,toC):
    global Algorithm
    send_bytes = "3EPROTO KEYXCHGFAIL"+"\nAlgo:"+Algorithm[mode]+"\nFrom:"+fromC+"\nTo:"+toC
    send_bytes=send_bytes.encode('utf-8')
    connectSocket.sendall(send_bytes)

def sendKeyCHGOK(mode, fromC, toC):
    global Algorithm
    send_bytes = "3EPROTO KEYXCHGOK"+"\nAlgo:"+Algorithm[mode]+"\nFrom:"+fromC+"\nTo:"+toC
    send_bytes=send_bytes.encode('utf-8')
    connectSocket.sendall(send_bytes)

reading_thread = threading.Thread(target=socket_read)
sending_thread = threading.Thread(target=socket_send)

reading_thread.start()
sending_thread.start()

reading_thread.join()
sending_thread.join()


