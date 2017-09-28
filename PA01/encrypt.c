/**********************************************
	CS457 PA01
	Author: Sydney Edwards
	Last Modified: September 14, 2017
************************************************/

#include <stdint.h> 
#include <stdio.h> 
#include <unistd.h> 
#include <fcntl.h> 

// OpenSSL headers
#include <openssl/ssl.h> 
#include <openssl/conf.h> 
#include <openssl/err.h> 

#define CIPHER_LEN_MAX 1024 
#define PLAINTEXT_LEN_MAX 1008

void encrypt( int fd_in, int fd_out, unsigned char *key, unsigned char *iv);

void main()
{
	unsigned key_len = 32;
	unsigned iv_len = 16;
	unsigned plaintext_len, ciphertext_len;
	uint8_t key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	int file, output;
	int fd_key, fd_iv;

	/*opens all files to read plain text from and write encrypted text 
		to(file.txt, file.encr)*/
	file = open("file.txt", O_RDONLY);
	if( file == -1 ) 
	{
		fprintf( stderr , "\nCould not open file.txt\n"); 
		exit(-1) ; 
	}
	output = open("file.encr",  O_WRONLY | O_CREAT | O_TRUNC , S_IRUSR | S_IWUSR);
	if( output == -1 ) 
	{
		fprintf( stderr , "\nCould not open file.encr\n"); 
		exit(-1) ; 
	}
	
	/*Bio object & crypto library init*/
 	BIO *bio_stdout;
	ERR_load_crypto_strings(); 
	OpenSSL_add_all_algorithms(); 
	OPENSSL_config(NULL); 
 	bio_stdout = BIO_new_fp( stdout , BIO_NOCLOSE );

	/*opens fd key and fdiv*/
	/*read key and print in hex*/
	fd_key = open("key.bin", O_RDONLY);
	fd_key = open("key.bin" , O_RDONLY ) ; 
	if( fd_key == -1 )
	{ 
		fprintf( stderr , "\nCould not open key.bin\n"); exit(-1);
	}
	read(fd_key, key, key_len);
	printf("\nUsing this symmetric key of length %d bytes\n" , key_len ); 
	BIO_dump ( bio_stdout, (const char *) key, key_len ); 
	close(fd_key);

	/*read iv and print in hex*/
	fd_iv = open("iv.bin" , O_RDONLY );
	if( fd_iv == -1 ) 
	{ 
		fprintf( stderr , "\nCould not open iv.bin\n"); 
		exit(-1);
	}
	read ( fd_iv , iv , iv_len ) ; 
	printf("\nUsing this Initial Vector of length %d bytes\n" , iv_len ); 
	BIO_dump ( bio_stdout, (const char *) iv , iv_len ); 
	close( fd_iv ) ; 

	/*calls encrypt to actually encrypt the file*/
	encrypt(file, output, key, iv);
	
	/*closes all used files*/
	close(file);
	close(output);
}

/*Encrypt function that actually encrypts the plain text. Takes in all necessary
	information, encrypts the plaintext and writes the encrypted text to fd_out*/
void encrypt(int fd_in, int fd_out, unsigned char *key, unsigned char *iv)
{
	unsigned plaintext_len, len;
	unsigned char ciphertext[CIPHER_LEN_MAX]; 
	EVP_CIPHER_CTX *ctx; 
	char plaintext[PLAINTEXT_LEN_MAX];

	/*Create and initialise the context*/
	if( !(ctx = EVP_CIPHER_CTX_new()) )
		abort();
		
	if( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
		abort();

	/*read plaintext from file 1008 bytes at a time*/
	while(1)
	{
		plaintext_len = read(fd_in, plaintext, PLAINTEXT_LEN_MAX);
		if(plaintext_len <= 0)
			break;
		/*encrypt 1008 bytes using AES cypher in CBC mode with a 256 bit key*/
		if( 1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) )
			abort();
		
		/*write encrypted bytes to fd_out*/
		write(fd_out , (const char *) ciphertext, len); 
	}
	
	if( 1 != EVP_EncryptFinal_ex(ctx, ciphertext, &len) ) 
		abort();
			
	write(fd_out , (const char *) ciphertext, len); 
	EVP_CIPHER_CTX_free(ctx);


}