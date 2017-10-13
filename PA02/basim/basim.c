/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   basim.c

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

    FILE* log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Basim. Could not create log file\n");
        exit(-1) ;
    }
    fprintf( log , "This is Basim. Will receive digest from FD %d and file from FD %d\n" ,
                   fd_ctrl , fd_data );

    uint8_t fd_out = open("basim/bunny.mp4" , O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR ) ;
    if( fd_out == -1 )
    {
        fprintf( stderr , "This is Basim. Could not open output file\n");
        exit(-1) ;
    }

    fprintf( log , "This is Basim. Starting to receive incoming file and compute its digest\n");

	//call file digest to get sha
    
	uint8_t encryptedDigest[1024];
    uint8_t signature[1024];
    size_t encrDig_len = fileDigest(fd_data, encryptedDigest, fd_out);
    
	fprintf( log, "\nThis is Basim. Here is the locally-computed digest of the incoming file:\n");
    BIO_dump_fp (log, (const char *) encryptedDigest, encrDig_len);
    fprintf(log,"\nThis is Basim. I received the following signature from Amal:\n");
    //decrypt digest
    RSA *rsa_pubK = getRSAfromFile ("basim/amal_pubKey.pem" , 1);
    int pubKeySize;
	uint8_t *digest = malloc( (pubKeySize = RSA_size(rsa_pubK )) );  
    if( ! digest )
        { printf("No memory for Digest\n" );  exit(-1) ; }

    read(fd_ctrl, encryptedDigest, pubKeySize);

	BIO_dump_fp (log, (const char *) encryptedDigest, pubKeySize);
    int digest_len ;
    
    digest_len = RSA_public_decrypt( pubKeySize, encryptedDigest , 
        digest, rsa_pubK, RSA_PKCS1_PADDING);
    if ( digest_len == -1 )
        handleErrors("Public Encryption of digest failed" );
    
    fprintf(log, "\nThis is Basim. Here is my signature on the file:\n");
    BIO_dump_fp(log, (const char*) digest, digest_len);
    
    //encryptedDigest = digest;
    int valid = memcmp(signature, digest, pubKeySize);
    fprintf(log, "\n\n\nThis is Basim. Amal's signature is %s", valid == 0 ? "INVALID": "VALID");
    EVP_cleanup();
    ERR_free_strings();

    fclose( log ) ;  
    close( fd_ctrl ) ;
    close( fd_data ) ;

    return 0 ;
}