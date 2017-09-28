#!/bin/bash
#

# Generate public/private key-pair for Alice

cd alice
rm -f *.pem 

openssl genpkey -algorithm RSA -out alice_priv_key.pem -pkeyopt rsa_keygen_bits:2048

openssl rsa -pubout -in alice_priv_key.pem -out alice_pub_key.pem

#openssl rsa -text -in alice_priv_key.pem

# Generate public/private key pair for Bob

cd ../bob
rm -f *.pem

openssl genpkey -algorithm RSA -out bob_priv_key.pem -pkeyopt rsa_keygen_bits:2048

openssl rsa -pubout -in bob_priv_key.pem -out bob_pub_key.pem

ln -s  ../alice/alice_pub_key.pem  alice_pubKey.pem

cd ../alice

ln -s ../bob/bob_pub_key.pem bob_pubKey.pem

# Compile & Run Bob's encryption code
echo
echo "**** Compiling & Executing Bob's Encryption Code"
cd ../bob
rm -f encr
gcc -o encr rsa_encr.c -lcrypto
./encr

# Share files from Bob to Alice
cd ../alice
rm -f        file.encr key.encr  iv.bin
ln -s ../bob/file.encr file.encr
ln -s ../bob/key.encr  key.encr
ln -s ../bob/iv.bin    iv.bin

# Compile & Run Alice's decryption code
echo
echo "**** Compiling & Executing Alice's Decryption Code"
rm -f decr
gcc -o decr rsa_decr.c -lcrypto
./decr

# Verify the decrypted file
cd ..
echo
diff -s  bob/file.txt   alice/file.decr
echo

