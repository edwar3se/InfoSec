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