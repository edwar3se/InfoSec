/**********************************************
	CS457 PA01
	Author: Sydney Edwards
	Last Modified: September 14, 2017
************************************************/

#include <stdint.h> 
#include <stdio.h> 
#include <unistd.h> 
#include <fcntl.h> 

/* OpenSSL headers */ 
#include <openssl/ssl.h> 
#include <openssl/conf.h> 
#include <openssl/err.h> 

void decryptFile(int fd_in, int fd_out, unsigned char * key, unsigned char * iv); 

#define CIPHER_LEN_MAX 1024
#define PLAINTEXT_LEN_MAX 1008
void main()
{
	uint8_t key[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ; 
	unsigned key_len = 32 ; // i.e. 256 bits
	unsigned iv_len = 16 ; // i.e. 128 bits 
	BIO *bio_stdout; 
	int fd_key , fd_iv; 
	int ciph; 
	int decr ; 

	/* Initialize the crypto library */
	ERR_load_crypto_strings(); 
	OpenSSL_add_all_algorithms(); 
	OPENSSL_config(NULL); 

	/* Initiaize the BIO for BASE64 output */
	bio_stdout = BIO_new_fp( stdout , BIO_NOCLOSE ); 

	/*open key and iv and read in values*/
	fd_key = open("key.bin" , O_RDONLY ) ; 
	if( fd_key == -1 )
	{ 
		fprintf( stderr , "\nCould not open key.bin\n"); exit(-1);
	}
	read ( fd_key , key , key_len ) ; 
	printf("\nUsing this symmetric key of length %d bytes\n" , key_len ); 
	BIO_dump ( bio_stdout, (const char *) key, key_len ); 
	close( fd_key ) ; 
	
	fd_iv = open("iv.bin" , O_RDONLY ) ; 
	if( fd_iv == -1 ) 
	{ 
		fprintf( stderr , "\nCould not open iv.bin\n"); 
		exit(-1);
	}

	read ( fd_iv , iv , iv_len ) ; 
	printf("\nUsing this Initial Vector of length %d bytes\n" , iv_len ); 
	BIO_dump ( bio_stdout, (const char *) iv , iv_len ); 
	close( fd_iv ) ; 
	
	/*open file for reading in the encrypted text*/
	ciph = open("file.encr" , O_RDONLY ) ; 
	if( ciph == -1 ) 
	{
		fprintf( stderr , "\nCould not open file.encr\n"); 
		exit(-1) ; 
	}
	
	/*open file to write to when text is decrypted*/
	decr = open("file.decr" , O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR); 
	if(decr == -1 ) 
	{
		fprintf( stderr , "\nCould not open file.decr\n");
		exit(-1); 
	} 
	
	/*actually decrypting files*/
	decryptFile(ciph, decr, key, iv);
	
	/*cleaning up*/
	close(ciph);
	close(decr);
	BIO_flush ( bio_stdout ); 
	EVP_cleanup(); 
	ERR_free_strings(); 
}

/*function that takes in all useful information and decrypts the cipher text, writes
	decrypted text to text.decr file*/
void decryptFile(int fd_in, int fd_out, unsigned char * key, unsigned char * iv)
{
	unsigned ciphertext_len, len;
	unsigned char plaintext[PLAINTEXT_LEN_MAX]; 
	char ciphertext[CIPHER_LEN_MAX];
	EVP_CIPHER_CTX *ctx; 

	/*Create and initialize the context*/
	if( !(ctx = EVP_CIPHER_CTX_new()) ) 
		abort();

	if( 1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
		abort();
	/*while to read ever MAX_LEN bytes and decrypts and writes to file*/
	while(1)
	{
		ciphertext_len = read( fd_in , ciphertext , CIPHER_LEN_MAX ); 
		
		if(ciphertext_len <= 0)
			break;
			
		if( 1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) ) 
			abort();
		
		write(fd_out , (const char *) plaintext, len); 
	}
	
	/*final call to decrypt*/
	if( 1 != EVP_DecryptFinal_ex(ctx, plaintext, &len) )
		abort();	
	write(fd_out , (const char *) plaintext, len); 
	
	/*closes context*/
	EVP_CIPHER_CTX_free(ctx); 
}
