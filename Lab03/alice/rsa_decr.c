/*

	Updated by: Sydney Edwards
	
    I am Alice. I will decncrypt a file from Bob.
    He exchanged the session key with me encrypted using my public key.

    Adapted from:
        http://hayageek.com/rsa-encryption-decryption-openssl-c/
*/

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// Use RSA_PKCS1_PADDING padding. This is the currently recomended mode.

void handleErrors( char *msg) ;
void decryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv);
RSA  *getRSAfromFile(char * filename, int public) ;

uint16_t key_len = 32 ;  // i.e. 256 bits 
uint16_t iv_len  = 16 ;  // i.e. 128 bits

void main() 
{
    RSA  *rsa_privK ;
    // key & IV for symmetric encryption of data
    uint8_t  sessionKey[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ;    
    
    // Initialize the crypto library
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms ();
    OPENSSL_config(NULL);

    // Get the RSA key pair generated outside this program using: 

    rsa_privK = NULL ;
    rsa_privK = getRSAfromFile("alice_priv_key.pem", 0);
    if( !rsa_privK )
        { fprintf( stderr, "Unable to read Alice's Private key\n" ); exit(-1) ; }

    // Get the encrypted session key 
    int fd_key = open("key.encr" , O_RDONLY )  ;
    if( fd_key == -1 )
        { fprintf( stderr , "\nCould not open key.encr\n"); exit(-1) ; }

    int encrKey_len = RSA_size( rsa_privK ) ;
    uint8_t *encryptedKey = malloc( encrKey_len ) ;  
    if( ! encryptedKey )
        { printf("No memory for Encrypted Session Key\n" );  exit(-1) ; }

    read ( fd_key , encryptedKey , encrKey_len ) ;
    close( fd_key ) ;

    // Now, decrypt the session key using Alice's private key
    int sessionKey_len ;
    sessionKey_len = RSA_private_decrypt( encrKey_len , encryptedKey, 
            sessionKey, rsa_privK, RSA_PKCS1_PADDING );
    if ( sessionKey_len == -1 )
        handleErrors("Private Decryption of session key failed" );

    printf("\nUsing this symmetric session key of length %d bytes\n" , sessionKey_len );
    BIO_dump_fp ( stdout, (const char *) sessionKey, sessionKey_len );
    free ( encryptedKey ) ;

    // Get the Initial Vector
    int fd_iv = open("iv.bin" , O_RDONLY )  ;
    if( fd_iv == -1 )
        { fprintf( stderr , "\nCould not open iv.bin\n"); exit(-1) ; }

    read ( fd_iv , iv , iv_len ) ;
    printf("\nUsing this Initial Vector of length %d bytes\n" , iv_len );
    BIO_dump_fp ( stdout, (const char *) iv , iv_len );
    close( fd_iv ) ;

    /* Finally, decrypt the ciphertext file using the symmetric session key */
    int fd_encr = open("file.encr" , O_RDONLY )  ;
    if( fd_encr == -1 )
        {fprintf( stderr , "\nCould not open file.encr\n") ; exit(-1) ;}

    int fd_decr ;
    fd_decr = open("file.decr", O_WRONLY | O_CREAT | O_TRUNC , S_IRUSR | S_IWUSR);
    if( fd_decr == -1 )
        {fprintf( stderr , "\nCould not open file.decr\n"); exit(-1) ;}

    decryptFile( fd_encr, fd_decr, sessionKey , iv );
    
    close( fd_encr  ) ;
    close( fd_decr  ) ; 

    // We are done
    RSA_free( rsa_privK ) ;

    // Clean up the crypto library
    ERR_free_strings ();
    RAND_cleanup ();
    EVP_cleanup ();
    CONF_modules_free ();
    ERR_remove_state (0);    
    
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

//-----------------------------------------------------------------------------
void handleErrors( char *msg)
{
    fprintf( stderr , "%s\n" , msg ) ;
    ERR_print_errors_fp(stderr);
    abort();
}

//-----------------------------------------------------------------------------
#define CIPHER_LEN_MAX 1024
 
void decryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
    EVP_CIPHER_CTX *ctx;
    ssize_t         nBytes ;
    int             len, plaintext_len;
    unsigned char   plaintext [ CIPHER_LEN_MAX ] ;
    unsigned char   ciphertext[ CIPHER_LEN_MAX ];

    /* Create and initialise the context */
    if( !(ctx = EVP_CIPHER_CTX_new()) ) 
        handleErrors("CIPHER_CTX_new Failed");

    /* Initialise the Decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if( 1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
        handleErrors("DecryptInit Failed");

    while ( 1 )
    {
        nBytes = read( fd_in, ciphertext , CIPHER_LEN_MAX );
        if ( nBytes <= 0 )
            break ;   //  either EOF or a file error

        if( 1 != EVP_DecryptUpdate( ctx, plaintext, &len, ciphertext, nBytes) )
            handleErrors("DecryptUpdate Failed");

        write( fd_out , plaintext , len ) ;
    }
    
    /* Finalize the Decryption. */  
    if( 1 != EVP_DecryptFinal_ex( ctx, plaintext , &len) ) 
        handleErrors("DecryptFinal Failed");

    write( fd_out , plaintext , len ) ;

    /* Clean up */
    EVP_CIPHER_CTX_free( ctx );
}

