#!/bin/bash
echo
echo "Script to run Programming Assignment #2"
echo "By: Mohamed Aboutabl"
echo

rm -f dispatcher amal/amal amal/logAmal.txt basim/basim basim/logBasim.txt basim/bunny.mp4 

# Generate public/private key-pair for Amal
cd amal
rm -f *.pem 
openssl genpkey -algorithm RSA -out amal_priv_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa     -pubout        -in  amal_priv_key.pem -out amal_pub_key.pem

# Now, share Amal's public key with Basim
cd ../basim
rm -f  amal_pubKey.pem
ln -s  ../amal/amal_pub_key.pem  amal_pubKey.pem

cd ..

echo "=============================="
echo "Compiling all source"
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -lcrypto
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -lcrypto
	gcc wrappers.c     dispatcher.c -o dispatcher

echo "=============================="
echo "Starting the dispatcher"
./dispatcher

echo "=============================="
echo "Verifying File Transmission via the pipe"
echo
diff -s amal/bunny.mp4 basim/bunny.mp4

echo
echo "======  Amal's  LOG  ========="
cat amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat basim/logBasim.txt
echo
echo

