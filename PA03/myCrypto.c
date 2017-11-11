/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   myCrypto.c

Written By: 
     1- Sydney Edwards 
     2- James Nordike
     
Submitted on: October 13, 2017
----------------------------------------------------------------------------*/
#include <openssl/evp.h>
#include "myCrypto.h"
#include <stdlib.h>

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------
#define INPUT_CHUNK   16384

size_t fileDigest( int fd_in , uint8_t *digest , int fd_save )
// Read all the incoming data from 'fd_in' file descriptor
// Compute the SHA256 hash value of this incoming data into the array 'digest'
// If the file descriptor 'fd_save' is > 0, store a copy of the incoming data to 'fd_save'
// Returns actual size in bytes of the computed hash value
{
	uint8_t buffer[INPUT_CHUNK];
    EVP_MD_CTX *md_ctx;
    size_t bytes;
    unsigned int  mdLen = 0;
    
    if ( ! (md_ctx = EVP_MD_CTX_create() ) )
        handleErrors("EVP_MD_CTX_create failed");

    if( EVP_DigestInit(md_ctx, EVP_sha256()) != 1 )
        handleErrors("EVP_DigestInit failed");

    
    while(1)
    {
        bytes = read(fd_in, buffer, INPUT_CHUNK);

        if(bytes <= 0)
            break;

        if (EVP_DigestUpdate( md_ctx, buffer, bytes ) != 1) 
            handleErrors("EVP_DigestUpdate failed");            

        if ( fd_save > 0 )
            write(fd_save, buffer, bytes);
    }

    if ( 1 != EVP_DigestFinal_ex(md_ctx, digest, &mdLen) ) 
        handleErrors("EVP_DigestFinal failed");

    EVP_MD_CTX_destroy(md_ctx);

    return mdLen ;
}

// Sends the #of bytes , then the bytes themselves of a BIGNUM to file descriptor fd_out
// Returns 1 on success, 0 on failure
int BN_write_fd( const BIGNUM *bn , int fd_out)
{
	char * number;
	int len = BN_bn2bin(bn, number);
	if(len == -1)
		return 0;
	write(fd_out, &len, sizeof(len));
	write(fd_out, number, sizeof(number));
	return 1;
}

// Read the #of bytes , then the bytes themselves of a BIGNUM from file descriptor fd_in
// Returns: a newly-created BIGNUM, which should be freed later by the caller
//          NULL on failure
BIGNUM * BN_read_fd( int fd_in )
{
	char* num;
	int * size;

	read(fd_in, size, sizeof(int));
	read(fd_in, num, *size);

	return BN_bin2bn(num, *size, NULLi;
}

// Returns a newly-created BIGNUM such that:1 < BN< (p-1)
BIGNUM * BN_myRandom(const BIGNUM *p )
{
	
}

// Usethe prime 'q', the primitive root 'gen',and the private 'x' 
// to compute the Elgamal signature (r,s) on the 'len'-byte long 'digest'
void elgamalSign( const uint8_t *digest , int len,  const BIGNUM *q , const BIGNUM *gen ,const BIGNUM *x , BIGNUM *r , BIGNUM *s, BN_CTX*ctx)
{

}
// Use the prime 'q', the primitive root'gen',  and the public 'y' 
// to validate the Elgamal signature (r,s) on the 'len'-byte long 'digest'
// Return 1 if valid, 0 otherswise
int elgamalValidate( const uint8_t *digest , int len ,  const BIGNUM *q , const BIGNUM *gen , const BIGNUM *y , BIGNUM *r , BIGNUM *s , BN_CTX *ctx )
{
	return 0;
}
//-----------------------------------------------------------------------------
RSA * getRSAfromFile(char * filename, int public)
{
    FILE * fp = fopen(filename,"rb");
 
    if (fp == NULL)
    {
        printf("Unable to open RSA key file %s \n",filename);
        return NULL;    
    }

    RSA *rsa = RSA_new() ;
 
    if ( public )
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
    else
        rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
 
    fclose( fp );
    return rsa;
}
