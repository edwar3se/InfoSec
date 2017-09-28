/*adapted from: 

https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption 

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

int decrypt( unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
unsigned char *iv, unsigned char *plaintext) ; 

#define CIPHER_LEN_MAX 5000 
#define PLAINTEXT_LEN_MAX (CIPHER_LEN_MAX-32) 

//----------------------------------------------------------------------------


void main() 

{ 
uint8_t key[EVP_MAX_KEY_LENGTH] , iv[EVP_MAX_IV_LENGTH] ; 
unsigned key_len = 32 ; // i.e. 256 bits
unsigned iv_len = 16 ; // i.e. 128 bits 
unsigned ciphertext_len, decryptedtext_len; 

/* Buffer for ciphertext / Decrypted. Ensure the buffer is long enough for the

 * ciphertext which may be longer than the plaintext, dependant on the 
* algorithm and mode 
*/
unsigned char ciphertext[CIPHER_LEN_MAX]; 
unsigned char decryptedtext[PLAINTEXT_LEN_MAX]; 

/* BIO objects */

 BIO *bio_stdout; 

/* Initialise the crypto library */

 ERR_load_crypto_strings(); 
OpenSSL_add_all_algorithms(); 
OPENSSL_config(NULL); 

/* Initiaize the BIO for BASE64 output */

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

/* Read in the cipher text up to CIPHER_LEN_MAX bytes */

int fd_ciph ; 
fd_ciph = open("ciphertext.bin" , O_RDONLY ) ; 
if( fd_ciph == -1 ) 
{

 fprintf( stderr , "\nCould not open ciphertext.bin\n"); 
exit(-1) ; 
}

 ciphertext_len = read( fd_ciph , ciphertext , CIPHER_LEN_MAX ) ; 
printf("\nHexDump of Ciphertext is:\n"); 
BIO_dump ( bio_stdout, (const char *) ciphertext, ciphertext_len); 
close( fd_ciph ) ; 

/* Deccrypt the cipher text */

 decryptedtext_len = 
decrypt( ciphertext, ciphertext_len, key, iv, decryptedtext );

 printf("Decrypted text is:\n"); 
BIO_dump ( bio_stdout, (const char *) decryptedtext, decryptedtext_len ); 

int fd_decr ; 
fd_decr = open("decryptedtext.bin" , O_WRONLY | O_CREAT , S_IRUSR | S_IWUSR) ; 
if( fd_decr == -1 ) 
{

 fprintf( stderr , "\nCould not open ciphertext.bin\n");

 exit(-1) ; 
} 
write ( fd_decr , (const char *) decryptedtext, decryptedtext_len ); 
close( fd_decr ) ; 

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


int decrypt( unsigned char *ciphertext, int ciphertext_len, unsigned char *key, 
unsigned char *iv, unsigned char *plaintext) 
{ 
EVP_CIPHER_CTX *ctx; 

int len; 

int plaintext_len; 

/* Create and initialise the context */

if( !(ctx = EVP_CIPHER_CTX_new()) ) 
handleErrors(); 

/* Initialise the decryption operation. IMPORTANT - ensure you use a key

 * and IV size appropriate for your cipher 
* In this example we are using 256 bit AES (i.e. a 256 bit key). The 
* IV size for *most* modes is the same as the block size. For AES this 
* is 128 bits */
if( 1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) ) 
handleErrors(); 

/* Provide the message to be decrypted, and obtain the plaintext output.

 * EVP_DecryptUpdate can be called multiple times if necessary 
*/ 
if( 1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) ) 
handleErrors(); 
plaintext_len = len; 

/* Finalise the decryption. Further plaintext bytes may be written at

 * this stage. 
*/
if( 1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len) ) 
handleErrors(); 
plaintext_len += len; 

/* Clean up */

 EVP_CIPHER_CTX_free(ctx); 

return plaintext_len; 
} 

