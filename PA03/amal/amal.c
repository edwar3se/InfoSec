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
    fprintf( log , "This is Amal. Will send digest to FD %d and file to FD %d\n" ,
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

	fprintf(log, "This is Amal. Here are my params (in hex) :\n");

  
	BN_CTX * ctx = BN_CTX_new();
	BN_CTX_init(ctx);
	
	if(!BN_is_prime_ex(dh->p, 80, ctx, cb))
	{
		fprintf(log, "number is so not prime\n");
		return -1;
	}

	DH_generate_key(dh);
	fprintf(log, "prime: ");
	BN_print_fp(log, dh->p);
    	fprintf( log , "\nIt is indeed prime\n");
    	fprintf( log , "Root         : ");
    	BN_print_fp(log, dh->g);
    	fprintf( log , "\nPrivate value: ");
    	BN_print_fp(log, dh->priv_key);
    	fprintf( log , "\nPublic value : ");
    	BN_print_fp(log, dh->pub_key);
    	

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


	
	
    EVP_cleanup();
    ERR_free_strings();

    fclose( log ) ;  

    return 0 ;
}

