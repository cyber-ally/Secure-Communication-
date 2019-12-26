from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Cipher import PKCS1_OAEP
import binascii
import os
import sys

args = sys.argv
if len(args) != 4:
   print("Usage:  send.py <message_file> <send_priv_key> <rec_pub_key>")
   exit(0)

msg_file,send_priv_key,rec_pub_key = args[1],args[2],args[3]



def sign_message(message,privkeyfile_der):
    key = RSA.importKey(open(privkeyfile_der,'rb').read())
    h = SHA256.new(message)
    signature = PKCS1_PSS.new(key).sign(h)
    return signature


def AES_encrypt(message, key):
    
    iv = os.urandom(16)
    ctr = Counter.new(128, initial_value=int(binascii.hexlify(iv), 16))
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return iv + aes.encrypt(message)

def RSAencrypt(message, rec_pub_key):
    key = RSA.importKey(open(rec_pub_key,'rb').read())
    cipher = PKCS1_OAEP.new(key)  ### Padding Scheme
    ciphertext = cipher.encrypt(message)
    return ciphertext


message = open(msg_file,'rb').read()
key = open("symkey",'rb').read()

sig = sign_message(message,send_priv_key)
f = open("msg.sig","wb").write(sig)

ct = AES_encrypt(message,key)
f = open("msg.crypt","wb").write(ct)

ciphertext = RSAencrypt(key,rec_pub_key)
f = open("symkey.crypt","wb").write(ciphertext)
