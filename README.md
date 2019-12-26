# Secure Communication Simulation

The project is a simulation of secure communication between two parties, hence include two applications *sender* and *reciver*. Programs use Pyhton Cryptograyphy toolkit to achive their tasks.

Sender do the following:

1. Digitally sign a message (file) using RSA PKCS1_PSS to produce a file     called *msg.sig*.
2. Encrypt the message using AES with a 128 bit key  𝐾  to produce a        file called *msg.crypt*.
3. Encrypt  𝐾  using RSA with the receiver's public key and save to a       file called *symkey.crypt*.
4. "Transmit" *msg.sig,msg.crypt,sym.key* (No need to do anything for           transmission).

Takes three command line inputs all of which are filenames:

1. Message file
2. Sender's private key file for signing.
3. Reciver's public key (for encrypting the symmetric key)

Receiver performs the following:

1. Use her private key to decrypt *symkey.crypt* to produce *symkey*.
2. Use symkey to decrypt *msg.crypt* to produce *msg*.
3. Use the sender's public key to verify that *msg.sig* is a valid             signature for msg.

Reciever also takes three command line inputs.

## Key Generation

Key for both parties are generated through openSSl (software library for applications that secure communications over computer networks).

openssl genrsa -out private.pem 2048\
openssl rsa -in private.pem -out private.der -outform DER\
openssl rsa -in private.pem -outform DER -pubout -out public.der\
openssl rand 16 > aes.key

### Run programs

*send.py* msg.txt send_priv.der rec_pub.der\
*receive.py* symkey.crypt msg.crypt msg.sig
