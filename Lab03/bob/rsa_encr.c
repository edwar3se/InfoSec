/*
	Updated by: Sydney Edwards

    I am Bob. I will encrypt a file to Alice.
    I will exchange the session key with her encrypted using her public key.

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
void encryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv);
RSA  *getRSAfromFile(char * filename, int public) ;

uint16_t sessionKey_len = 32 ;  // i.e. 256 bits 
uint16_t iv_len         = 16 ;  // i.e. 128 bits

void main() 
{
    RSA  *rsa_pubK ;
    // key & IV for symmetric encryption of data
    uint8_t  sessionKey[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ;    
    
    // Initialize the crypto library
    ERR_load_crypto_strings ();
    OpenSSL_add_all_algorithms ();
    OPENSSL_config(NULL);

    // Get the RSA key generated outside this program the opessl tool 

    rsa_pubK  = NULL ;
    rsa_pubK  = getRSAfromFile( "alice_pubKey.pem"  , 1 ) ;
    if( !rsa_pubK )
        { fprintf( stderr, "Unable to read Alice's Public key\n" ); exit(-1) ;  }

    // Generate random session key & IV
    RAND_bytes(iv, iv_len);
    printf("\nUsing this symmetric session key of length %d bytes\n" , sessionKey_len );
    BIO_dump_fp ( stdout, (const char *) sessionKey , sessionKey_len );


    RAND_bytes(iv, iv_len);
    printf("\nUsing this Initial Vector of length %d bytes\n" , iv_len );
    BIO_dump_fp ( stdout, (const char *) iv , iv_len );
     
    // Encrypt the session key using Alice's Public Key
    uint8_t *encryptedKey = malloc( RSA_size(rsa_pubK ) );  
    if( ! encryptedKey )
        { printf("No memory for Encrypted Session Key\n" );  exit(-1) ; }

    int encrKey_len ;
    encrKey_len = RSA_public_encrypt( sessionKey_len, sessionKey, 
        encryptedKey, rsa_pubK, RSA_PKCS1_PADDING);
    if ( encrKey_len == -1 )
        handleErrors("Public Encryption of session key failed" );

    // Write the encrypted session key to a file 
    int fd_keyEncr ;
    fd_keyEncr = open("key.encr", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if( fd_keyEncr == -1 )
        { fprintf( stderr , "\nCould not open key.encr\n"); exit(-1) ; }

    write( fd_keyEncr , encryptedKey , encrKey_len ) ;

    free ( encryptedKey );
    close( fd_keyEncr ) ;
    
    // Write the IV un-encrypted to a file 
    int fd_iv ;
    fd_iv = open("iv.bin", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if( fd_iv == -1 )
        { fprintf( stderr , "\nCould not open iv.bin\n"); exit(-1) ; }

    write( fd_iv , iv, iv_len ) ;

    close( fd_iv ) ;
    
    /* Finally, encrypt the plaintext file using the symmetric session key */
    int fd_plain = open("file.txt" , O_RDONLY )  ;
    if( fd_plain == -1 )
        {fprintf( stderr , "\nCould not open file.txt\n") ; exit(-1) ;}

    int fd_ciph ;
    fd_ciph = open("file.encr", O_WRONLY | O_CREAT | O_TRUNC , S_IRUSR | S_IWUSR);
    if( fd_ciph == -1 )
        {fprintf( stderr , "\nCould not open file.encr\n"); exit(-1) ;}

    encryptFile( fd_plain, fd_ciph, sessionKey , iv );
    
    close( fd_plain ) ;
    close( fd_ciph  ) ; 

    // We are done
    RSA_free( rsa_pubK  ) ;

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
        rsa = PEM_read_RSA_PUBKEY( fp , &rsa , NULL , NULL );
    else
        rsa = PEM_read_RSAPrivateKey( fp , &rsa , NULL , NULL );
 
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
#define PLAINTEXT_LEN_MAX (CIPHER_LEN_MAX-16)
 
void encryptFile( int fd_in, int fd_out, unsigned char *key, unsigned char *iv )
{
    EVP_CIPHER_CTX *ctx;
    ssize_t         nBytes ;
    int             len, ciphertext_len;
    unsigned char   plaintext [ PLAINTEXT_LEN_MAX ] ;
    unsigned char   ciphertext[ CIPHER_LEN_MAX    ];

    /* Create and initialise the context */
    if( !( ctx = EVP_CIPHER_CTX_new() ) ) 
        handleErrors("CIPHER_CTX_new failed");

    /* Initialise the Encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
        handleErrors("EncryptInit failed");

    len = 0 ;
    ciphertext_len = 0 ;
    
    while ( 1 )
    {
        nBytes = read( fd_in, plaintext , PLAINTEXT_LEN_MAX );
        if ( nBytes <= 0 )
            break ;   //  either EOF or a file error

        if( 1 != EVP_EncryptUpdate( ctx, ciphertext, &len, plaintext, nBytes) )
            handleErrors("EncryptUpdate failed");

        write( fd_out , ciphertext , len ) ;
    }

    /* Finalise the encryption. Further ciphertext bytes may be written at
       this stage. */
    if( 1 != EVP_EncryptFinal_ex( ctx, ciphertext , &len) ) 
        handleErrors("EncryptFinal failed");

    write( fd_out , ciphertext , len ) ;

    /* Clean up */
    EVP_CIPHER_CTX_free( ctx );
}

