/*

https:://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption 

https://www.openssl.org/docs/man1.0.2/crypto/ 

*/ 

#include <stdint.h> 
#include <stdio.h> 
#include <unistd.h> 
#include <fcntl.h> 

/* OpenSSL headers */ 

#include <openssl/ssl.h> 
#include <openssl/conf.h> 
#include <openssl/err.h> 

int encrypt( unsigned char *plaintext, int plaintext_len, unsigned char *key, 
unsigned char *iv, unsigned char *ciphertext ) ; 

#define CIPHER_LEN_MAX 5000 
#define PLAINTEXT_LEN_MAX (CIPHER_LEN_MAX-32) 

//----------------------------------------------------------------------------


void main() 
{ 

uint8_t key[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ; 
unsigned key_len = 32 ; // i.e. 256 bits
unsigned iv_len = 16 ; // i.e. 128 bits 
unsigned plaintext_len, ciphertext_len; 

/* Message to be encrypted */ 

//INSERT CODE HERE TO READ FROM FILE AND SET PLAIN TEXT EQUAL TO IT

FILE * file = fopen ("file.txt", "r");

unsigned char *plaintext = 
(unsigned char *)"This is a 10 word sentence used in the PA"; 

/* Buffer for ciphertext. Ensure the buffer is long enough for the

 * ciphertext which may be longer than the plaintext, dependant on the 
* algorithm and mode 
*/ 
unsigned char ciphertext[CIPHER_LEN_MAX]; 

/* BIO objects */

 BIO *bio_stdout; 

/* Initialise the crypto library */

 ERR_load_crypto_strings(); 
OpenSSL_add_all_algorithms(); 
OPENSSL_config(NULL); 

/* Initiaize the BIO for BASE64 input/output */

 bio_stdout = BIO_new_fp( stdout , BIO_NOCLOSE ); 

// Get the session symmetric key

int fd_key , fd_iv ; 
fd_key = open("key.bin" , O_RDONLY ) ; 
if( fd_key == -1 )

 { fprintf( stderr , "\nCould not open key.bin\n"); exit(-1) ;}

 read ( fd_key , key , key_len ) ; 
printf("\nUsing this symmetric key of length %d bytes\n" , key_len ); 
BIO_dump ( bio_stdout, (const char *) key, key_len ); 
close( fd_key ) ; 

// Get the session Initial Vector 

fd_iv = open("iv.bin" , O_RDONLY ) ; 
if( fd_iv == -1 ) 
{ fprintf( stderr , "\nCould not open iv.bin\n"); exit(-1) ;}

 read ( fd_iv , iv , iv_len ) ; 
printf("\nUsing this Initial Vector of length %d bytes\n" , iv_len ); 
BIO_dump ( bio_stdout, (const char *) iv , iv_len ); 
close( fd_iv ) ; 

// Display the plaintext for debugging purposes

 plaintext_len = strlen( plaintext ) ; 
printf("HexDump of Plaintext is:\n"); 
BIO_dump ( bio_stdout, (const char *) plaintext, plaintext_len ); 

/* Encrypt the plaintext */

 ciphertext_len = 
encrypt( plaintext, strlen( (char*)plaintext ), key, iv, ciphertext ); 

/* Do something useful with the ciphertext here */

 printf("\nCiphertext in HEX is:\n"); 
BIO_dump ( bio_stdout , (const char *) ciphertext, ciphertext_len); 

int fd_ciph ; 
fd_ciph = open("ciphertext.bin" , O_WRONLY | O_CREAT , S_IRUSR | S_IWUSR) ; 
if( fd_ciph == -1 ) 
{

 fprintf( stderr , "\nCould not open ciphertext.bin\n");

 exit(-1) ; 
} 
write ( fd_ciph , (const char *) ciphertext, ciphertext_len); 
close( fd_ciph ) ; 

/* Clean up */

 BIO_flush ( bio_stdout ); 
EVP_cleanup(); 
ERR_free_strings(); 

} 

//----------------------------------------------------------------------------


void handleErrors(void) 

{ 
ERR_print_errors_fp(stderr); 
abort(); 

} 

//----------------------------------------------------------------------------


int encrypt( unsigned char *plaintext, int plaintext_len, unsigned char *key,
unsigned char *iv, unsigned char *ciphertext ) 
{ 
EVP_CIPHER_CTX *ctx; 

int len; 

int ciphertext_len; 

/* Create and initialise the context */

if( !(ctx = EVP_CIPHER_CTX_new()) ) 
handleErrors(); 

/* Initialise the encryption operation. IMPORTANT - ensure you use a key

 * and IV size appropriate for your cipher 
* In this example we are using 256 bit AES (i.e. a 256 bit key). The 
* IV size for *most* modes is the same as the block size. For AES this 
* is 128 bits */
if( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) ) 
handleErrors(); 

/* Provide the message to be encrypted, and obtain the encrypted output.

 * EVP_EncryptUpdate can be called multiple times if necessary 
*/
if( 1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) ) 
handleErrors(); 
ciphertext_len = len; 

/* Finalise the encryption. Further ciphertext bytes may be written at

 * this stage. 
*/
if( 1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) ) 
handleErrors(); 
ciphertext_len += len; 

/* Clean up */

 EVP_CIPHER_CTX_free(ctx); 

return ciphertext_len; 
} 

