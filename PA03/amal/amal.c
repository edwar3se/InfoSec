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
    int fd_ctrl = atoi( argv[1] ) ;
    int fd_data = atoi( argv[2] ) ;

    FILE * log = fopen("amal/logAmal.txt" , "w" );
    if( ! log )
    {
        fprintf( stderr , "This is Amal. Could not create log file\n");
        exit(-1) ;
    }
    fprintf( log , "This is Amal. Will send CTRL to FD %d, DATA to FD %d\n\n" ,
                   fd_ctrl , fd_data );

    int fd_in = open("amal/bunny.mp4" , O_RDONLY , S_IRUSR | S_IWUSR ) ;
    if( fd_in == -1 )
    {
        fprintf( stderr , "This is Amal. Could not open input file\n");
        exit(-1) ;
    }

    //fprintf( log , "This is Amal. Starting to digest the input file\n");


	DH * dh = DH_new();
	BN_GENCB* cb = NULL;
	
	DH_generate_parameters_ex(dh, 512, 2, cb);

	fprintf(log, "This is Amal. Here are my parameters (in Hex) :\n");

  
	BN_CTX * ctx = BN_CTX_new();
	BN_CTX_init(ctx);
	
	if(!BN_is_prime_ex(dh->p, 80, ctx, cb))
	{
		fprintf(log, "number is so not prime\n");
		return -1;
	}

	DH_generate_key(dh);
	fprintf(log, "\tPrime        : ");
	BN_print_fp(log, dh->p);
    	fprintf( log , "\n\tIt is indeed prime\n");
    	fprintf( log , "\tRoot         : ");
    	BN_print_fp(log, dh->g);
    	fprintf( log , "\n\tPrivate value: ");
    	BN_print_fp(log, dh->priv_key);
    	fprintf( log , "\n\tPublic value : ");
    	BN_print_fp(log, dh->pub_key);
        fprintf(log, "\n\nAmal: sending prime, root, and public value to Basim\n\n");

 	if (!BN_write_fd(dh->p, fd_ctrl)){
		fprintf(log, "error 1\n");
	//	fclose(log);
		return -1;
	}

	if(!BN_write_fd(dh->g, fd_ctrl)){
		fprintf(log, "error 2\n");
	//	fclose(log);
		return -1;
	}

	if(!BN_write_fd(dh->pub_key, fd_ctrl)) {
       	 	fprintf(log, "error 3\n");
	//	fclose(log);
        	return -1;
    	}


	int fd_in2 = open("amal/bunny.mp4" , O_RDONLY , S_IRUSR | S_IWUSR ) ;
	if( fd_in2 == -1 )
    	{
        	fprintf( stderr , "This is Amal. Could not open input file\n");
        	exit(-1) ;
    	}
	fprintf(log, "\nAmal: Successfully opened data file\n");
	fprintf(log, "Amal: Starting to digest the data file\n");


    	//fprintf( log , "\nThis is Amal. Starting to digest the input file\n");
	//call file digest to get sha
    	fprintf( log, "\nAmal: Here is the digest of the file:\n");
    	fflush(log);

	uint8_t digest[1024];
//    	uint8_t *sig;
	size_t digestLen = fileDigest(fd_in2, digest, fd_data);	

//	RSA *rsa_privK = getRSAfromFile ("amal/amal_priv_key.pem" , 0);

//	uint8_t *encryptedDigest = malloc( RSA_size(rsa_privK ) );  
  //  	if( ! encryptedDigest )
    //    	{ printf("No memory for Digest\n" );  exit(-1) ; }

	BIO_dump_fp (log, (const char *) digest, digestLen);

	fflush(log);
  
	//now elgamal sig stuff
	fprintf(log, "\n\nAmal: Generating the elgamal signature\n");
	fprintf(log, "\tr : ");
	//fprintf(log, "%d\n", digestLen);
	fflush(log);

	//palceholders for r and s
	BIGNUM * s = BN_new();
	BIGNUM * r = BN_new();

	BN_CTX * ctx2 = BN_CTX_new();
        BN_CTX_init(ctx2);
	
	elgamalSign(digest, digestLen, dh->p, dh->g, dh->priv_key, r, s, ctx2);
	BN_print_fp(log, r);
	fflush(log);

	fprintf(log, "\n\ts : ");
	BN_print_fp(log, s);
	fprintf(log, "\n");
	fflush(log);

	//write signature over
	BN_write_fd(r, fd_ctrl);
	BN_write_fd(s, fd_ctrl);

    EVP_cleanup();
    ERR_free_strings();

	//free(encryptedDigest);
    fclose( log ) ;  
	close(fd_ctrl);
	close(fd_data);
    return 0 ;
}

