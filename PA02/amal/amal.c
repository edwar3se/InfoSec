/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   amal.c

Written By: 
     1- Sydney Edwards 
     2- James Nordike
     
Submitted on: 
----------------------------------------------------------------------------*/

#include "../myCrypto.h"

int main ( int argc , char * argv[] )
{

    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    if( argc < 3 )
    {
        printf("Missing command-line arguments: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
        exit(-1) ;
    }
    uint8_t fd_ctrl = atoi( argv[1] ) ;
    uint8_t fd_data = atoi( argv[2] ) ;

    FILE* log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Amal. Could not create log file\n");
        exit(-1) ;
    }
    fprintf( log , "This is Amal. Will send digest to FD %d and file to FD %d\n" ,
                   fd_ctrl , fd_data );

    int fd_in = open("amal/bunny.mp4" , O_RDONLY , S_IRUSR | S_IWUSR ) ;
    if( fd_in == -1 )
    {
        fprintf( stderr , "This is Amal. Could not open input file\n");
        exit(-1) ;
    }

    fprintf( log , "This is Amal. Starting to digest the input file\n");
	//call file digest to get sha
    fprintf( log, "\nThis is Amal. Here is the digest of the file:\n");
    fflush(log);
    
	uint8_t digest[1024];
    uint8_t *sig;


	size_t digestLen = fileDigest(fd_in, digest, fd_data);
    //printf("%lu\n", digestLen);
    //encrypt digest
    RSA *rsa_privK = getRSAfromFile ("amal/amal_priv_key.pem" , 0);
	uint8_t *encryptedDigest = malloc( RSA_size(rsa_privK ) );  
    if( ! encryptedDigest )
        { printf("No memory for Digest\n" );  exit(-1) ; }

	BIO_dump_fp (log, (const char *) digest, digestLen);

    int encrDig_len ;
    encrDig_len = RSA_private_encrypt( digestLen, digest , 
        encryptedDigest, rsa_privK, RSA_PKCS1_PADDING);
    if ( encrDig_len == -1 )
        handleErrors("Public Encryption of digest failed" );
    fprintf(log, "\nThis is Amal. Here is my signature on the file:\n");

	BIO_dump_fp (log, (const char *) encryptedDigest, encrDig_len);
    write(fd_ctrl, encryptedDigest, encrDig_len);
    EVP_cleanup();
    ERR_free_strings();

    free(encryptedDigest);
    close(fd_ctrl);
    close(fd_data);
    fclose( log ) ;  

    return 0 ;
}

