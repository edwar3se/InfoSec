/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   myCrypto.c

Written By: 
     1- Sydney Edwards
     2- James Nordike
     
Submitted on: 
----------------------------------------------------------------------------*/

#include "myCrypto.h"

void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------
#define INPUT_CHUNK 16384

size_t fileDigest( int fd_in , uint8_t *digest , int fd_save )
{
	//size in bytes of the computed hash value
    unsigned int  mdLen;
    
    EVP_MD_CTX *mdCtx;
    const EVP_MD *md;
    
    mdCtx = EVP_MD_CTX_create();
    md = EVP_get_digestbyname(digest);
    
    unsigned char incoming[INPUT_CHUNK];
    
    // Read all the incoming data from 'fd_in' file descriptor
	if(read(fd_in, incoming, INPUT_CHUNK) < 1)
	{
		abort();
	}
    
    // Compute the SHA256 hash value of this incoming data into the array 'digest'
	EVP_DigestInit_ex(mdCtx, md, NULL);
	EVP_DigestUpdate(mdCtx, incoming, INPUT_CHUNK);
	EVP_DigestFinal_ex(mdCtx,digest, &mdLen);
	EVP_MD_CTX_destroy(mdCtx);
    
    // If the file descriptor 'fd_save' is > 0
    if (fd_save > 0)
	{
		//store a copy of the incoming data to 'fd_save'
		fd_save = fd_in;
	}
	
	EVP_DigestUpdate();
	
    // Returns size of hash value
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


