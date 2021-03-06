#!/bin/bash
echo
echo "Script to run final assessment"
echo "By: Sydney Edwards"
echo

rm -f dispatcher kdc/kdc kdc/logKdc.txt amal/amal basim/basim basim/logBasim.txt amal/logAmal.txt basim/bunny.mp4 

# Generate public/private key-pair for Amal
cd amal
rm -f *.pem

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

echo
echo "======  Amal's  LOG  ========="
cat amal/logAmal.txt

echo
echo "======  Basim's  LOG  ========="
cat basim/logBasim.txt
echo
echo
