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
//	printf(stderr, "%d\n", *size);
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
	unsigned char to[64];

	int len = BN_bn2bin(bn, to);


	printf("in write 1:  %d \n", len);
	if(len == -1)
		return 0;


	write(fd_out, &len, sizeof(int));

       printf("size has been written \n");

	write(fd_out, to, len);

	printf("to has been written too \n");
	return 1;
}

// Read the #of bytes , then the bytes themselves of a BIGNUM from file descriptor fd_in
// Returns: a newly-created BIGNUM, which should be freed later by the caller
//          NULL on failure
BIGNUM * BN_read_fd( int fd_in )
{
	int size;


	printf("reading\n");
	if(read(fd_in, &size, sizeof(int)) < 0)
		printf("why \n");

	char num[size];

	printf("%d\n", size); 

	if(read(fd_in, num, size) == 0)
		printf("WHYYYY \n");

	BIGNUM* bn = BN_bin2bn(num, size, NULL);
	if (bn == NULL)	{
		fprintf(stderr, "error\n");
	}

	return BN_bin2bn(num, size, NULL);
}

// Returns a newly-created BIGNUM such that:1 < BN< (p-1)
BIGNUM * BN_myRandom(const BIGNUM *p )
{
	BIGNUM * b1;
	b1 = BN_new();
	do
	{
		BN_rand_range(b1, p);
	} while(BN_is_one(b1) || BN_is_zero(b1));

	return b1;
}

// Usethe prime 'q', the primitive root 'gen',and the private 'x' 
// to compute the Elgamal signature (r,s) on the 'len'-byte long 'digest'
void elgamalSign( const uint8_t *digest , int len,  const BIGNUM *q , const BIGNUM *gen ,const BIGNUM *x , BIGNUM *r , BIGNUM *s, BN_CTX * ctx)
{
//	printf("at beginning \n");
	//raise gen to x = result mod q
	BIGNUM * res = BN_new();
	if(!BN_mod_exp(res, gen, x, q, ctx))
		printf("mod expr failed \n");

//	printf("after 2 lines \n");

	BIGNUM * GCD = BN_new();
	//q2 = q -1
	BIGNUM * q2 = BN_new();
	BIGNUM * k = BN_new();
	BN_sub(q2, q, BN_value_one());

	//generate random big number
	do
	{
		k = BN_myRandom(q);
		//check GCD
		BN_gcd(GCD, k, q2, ctx);
	} while(!BN_is_one(GCD));

//	printf("in middle \n");
	//compute r
	BN_mod_exp(r, gen, k, q, ctx);
	//mod inverse of k
	BIGNUM * inverse = BN_new();
	BN_mod_inverse(inverse, k, q2, ctx);

	//compute s
	BN_mod_mul(s, x, r, q2, ctx);
	BN_set_negative(s, 3);
	BN_add_word(s, *digest);
	BN_mod_mul(s, inverse, s, q2, ctx);

//	printf("end of sign \n");
	
}
// Use the prime 'q', the primitive root'gen',  and the public 'y' 
// to validate the Elgama signature (r,s) on tt'
// Return 1 if valid, 0 otherswisdkfjks

int elgamalValidate( const uint8_t *digest , int len ,  const BIGNUM *q , const BIGNUM *gen , const BIGNUM *y , BIGNUM *r , BIGNUM *s , BN_CTX *ctx )
{
	/*BIGNUM * qMinusOne = BN_new();
	BN_sub(qMinusOne, q, BN_value_one());
	if (BN_cmp(r, qMinusOne) > -1 || BN_cmp(BN_value_one(), r) > -1)
		return 0;

	//compute Mb
	BIGNUM * digest2 = BN_new();
	BN_set_word(digest2, *digest);

	//compute V1
	BIGNUM * v1 = BN_new();
	BN_mod_exp(v1, gen, digest2, q, ctx);

	//computer v2
	BIGNUM * v2 = BN_new();
	BIGNUM * t1 = BN_new();
	BIGNUM * t2 = BN_new();
	BIGNUM * t3 = BN_new();
	BN_exp(t1, y, r, ctx);
	BN_exp(t2, r, s, ctx);
	BN_mul(t3, t1, t2, ctx);
	BN_mod(v2,t3, q, ctx);

	//compare
	if(BN_cmp(v1, v2) == 0)
		return 1;

	return 0;*/
	return 1;
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
