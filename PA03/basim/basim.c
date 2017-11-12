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
    int fd_ctrl = atoi( argv[1] ) ;
    int fd_data = atoi( argv[2] ) ;

    FILE * log = fopen("basim/logBasim.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Basim. Could not create log file\n");
        exit(-1) ;
    }
    fprintf( log , "This is Basim. Will receive CTRL from FD %d, data from FD %d\n" ,
                   fd_ctrl , fd_data );

    /*int fd_out = open("basim/bunny.mp4" , O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR ) ;
    if( fd_out == -1 )
    {
        fprintf( stderr , "This is Basim. Could not open output file\n");
        exit(-1) ;
    }*/

    //fprintf( log , "This is Basim. Starting to receive incoming file and compute its digest\n");

	fflush(log);

   	BIGNUM * prime;
	BIGNUM * root = BN_new();
	BIGNUM * pub_key = BN_new();

	prime = BN_read_fd(fd_ctrl);

	fprintf(log, "Basim: Received these parameters(in Hex) from Amal \n");

	fflush(log);
	fprintf(log, "\tPrime        : ");
	BN_print_fp(log, prime);

	fflush(log);
	root = BN_read_fd(fd_ctrl);
	fprintf(log, "\n\tRoot         : ");
	BN_print_fp(log, root);

	fflush(log);
	pub_key = BN_read_fd(fd_ctrl);
	fprintf(log, "\n\tPublic Value : ");
	BN_print_fp(log, pub_key);
	fflush(log);

	fprintf(log, "\n\nBasim: Starting to recieve incoming file and compute it's digest\n");
	fprintf(log, "\nBasim: Here is my locally-computed digest of the incoming file:\n");
	fflush(log);
	
	//read incoming file
	int fd_out2 = open("basim/bunny.mp4" , O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR ) ;
    	if( fd_out2 == -1 )
    	{
        	fprintf( stderr , "This is Basim. Could not open output file\n");
        	exit(-1) ;
    	}

	uint8_t fDigest[1024];
    	uint8_t signature[1024];
    	size_t encrDig_len = fileDigest(fd_data, fDigest, fd_out2);

	BIO_dump_fp (log, (const char *) fDigest, encrDig_len);
    	fflush(log);
	
	fprintf(log, "Basim: Received this Elgamal signature from Amal:\n");
	fprintf(log, "\tr : ");
	BIGNUM * r;
	r = BN_read_fd(fd_ctrl);
	BN_print_fp(log, r);

	fprintf(log,"\n\ts : ");
	BIGNUM * s;
	s = BN_read_fd(fd_ctrl);
	BN_print_fp(log, s);
	
	fprintf(log, "\n");
	
	BN_CTX * ctx = BN_CTX_new();
        BN_CTX_init(ctx);


	//validate
	fprintf(log, "\nBasim: This elgamal signature is .... ");
	if(elgamalValidate(fDigest, encrDig_len, prime, root, pub_key, r, s, ctx))
		fprintf(log, "VALID");
	else
		fprintf(log, "INVALID");

    EVP_cleanup();
    ERR_free_strings();

    fclose( log ) ;  
    close( fd_ctrl ) ;
    close( fd_data ) ;


    return 0 ;
}

