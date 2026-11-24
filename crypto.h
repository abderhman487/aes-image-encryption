#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>

#define EVP_SUCCESS 1
#define EVP_ERROR 0

const EVP_CIPHER *aes_mode(int mode);

int aes_encrypt_init( EVP_CIPHER_CTX *cipher_ctx, 
                      int mode,
                      const unsigned char *key, 
                      const unsigned char *iv );

int aes_encrypt_update( EVP_CIPHER_CTX *cipher_ctx,
                        const unsigned char *plaintext,
                        int plaintext_len,
                        unsigned char *ciphertext,
                        int *ciphertext_len );

int aes_encrypt_final( EVP_CIPHER_CTX *cipher_ctx,
                       unsigned char *ciphertext,
                       int *ciphertext_len );


int aes_decrypt_init(EVP_CIPHER_CTX *cipher_ctx,
                     int mode,
                     const unsigned char *key,
                     const unsigned char *iv);

int aes_decrypt_update(EVP_CIPHER_CTX *cipher_ctx,
                       const unsigned char *ciphertext,
                       int ciphertext_len,
                       unsigned char *plaintext,
                       int *plaintext_len);

int aes_decrypt_final(EVP_CIPHER_CTX *cipher_ctx,
                      unsigned char *plaintext,
                      int *plaintext_len);

#endif
