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
   print("Usage:  receive.py <symkey> <msg_crypt> <msg_sig> ")
   exit(0)

symkey_crypt,msg_crypt,msg_sig = args[1],args[2],args[3]


def verify_sig(message,signature,key):
    key = RSA.importKey(key)
    h = SHA256.new(message)
    verifier = PKCS1_PSS.new(key)
    try:
        verifier.verify(h, signature)
        print( "The signature is authentic.")
    except (ValueError, TypeError):
        print( "The signature is not authentic.")

def RSAdecrypt(ciphertext,privatekey_der):
    key = RSA.importKey(open(privatekey_der,'rb').read())
    dsize = SHA256.digest_size
    sentinel = Random.new().read(15+dsize)     # Let's assume that average data length is 15
    cipher = PKCS1_OAEP.new(key)
    message = cipher.decrypt(ciphertext)
    return message

def AES_decrypt(message, key):
    iv = message[:16]
    ctr = Counter.new(128, initial_value=int(binascii.hexlify(iv), 16))
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    return aes.decrypt(message[16:])

ciphertext = open(symkey_crypt,"rb").read()
k = RSAdecrypt(ciphertext,'rec_priv.der')

message = open(msg_crypt,"rb").read()
ct = AES_decrypt(message,k)
key = open('send_pub.der','rb').read()

verify_sig(ct,msg_sig,key)
