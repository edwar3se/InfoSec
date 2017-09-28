#!/bin/sh

gcc -o gen genKey.c -lcrypto
./gen
gcc -o encr encrypt.c -lcrypto
./encr
gcc -o decr decrypt.c -lcrypto
./decr
diff -s file.decr file.txt