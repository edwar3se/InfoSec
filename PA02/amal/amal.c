/*----------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   amal.c

Written By: 
     1- 
     2-
     
Submitted on: 
----------------------------------------------------------------------------*/

#include "../myCrypto.h"

int main ( int argc , char * argv[] )
{

	/**
	*	Gets the write-end file descriptors of both pipes from the command-line arguments.
	*	
	*	Opens bunny.mp4 and calls fileDigest() to compute the SHA256 hash value of the file 
	*		while transmitting a copy of the file over the AtoB Data pipe.	
	*	
	*	Uses Amal’s RSA private key to encrypt the hash value computed in the previous step. 
	*		This is Amal’s digital signature on this video file
	*	
	*	Transmits Amal’s digital signature to Basim over the AtoB Control pipe
	*/

    /* Initialise the crypto library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    if( argc < 3 )
    {
        printf("Missing command-line arguments: %s <ctrlFD> <dataFD>\n" , argv[0]) ;
        exit(-1) ;
    }
    //Gets the write-end file descriptors of both pipes from the command-line arguments.
    fd_ctrl = atoi( argv[1] ) ;
    fd_data = atoi( argv[2] ) ;

    log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Amal. Could not create log file\n");
        exit(-1) ;
    }
    fprintf( log , "This is Amal. Will send digest to FD %d and file to FD %d\n" ,
                   fd_ctrl , fd_data );

	//Opens bunny.mp4 
    fd_in = open("amal/bunny.mp4" , O_RDONLY , S_IRUSR | S_IWUSR ) ;
    if( fd_in == -1 )
    {
        fprintf( stderr , "This is Amal. Could not open input file\n");
        exit(-1) ;
    }

    fprintf( log , "This is Amal. Starting to digest the input file\n");
	
	//call fileDigest - SHA256 hash value
	
	//encrypt hash value - RSA private key

    // ....

    
    EVP_cleanup();
    ERR_free_strings();

    fclose( log ) ;  

    return 0 ;
}

