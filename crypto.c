/**
 * @file crypto.c
 * @brief Wrapper functions around OpenSSL EVP API for AES-256 encryption
 *        supporting ECB, CBC, and CTR block cipher modes.
 */

#include "crypto.h"

/* Select OpenSSL AES-256 cipher algorithm based on mode ID (1: ECB, 2: CBC, 3: CTR) */
const EVP_CIPHER *aes_mode(int mode)
{
    if (mode == 1)
        return EVP_aes_256_ecb();
    else if (mode == 2)
        return EVP_aes_256_cbc();
    else if (mode == 3)
        return EVP_aes_256_ctr();
    else
        return NULL;
}

/* Initialize the encryption context with the chosen AES-256 mode, key, and IV */
int aes_encrypt_init(EVP_CIPHER_CTX *cipher_ctx,
                     int mode,
                     const unsigned char *key,
                     const unsigned char *iv)
{
    const EVP_CIPHER *cipher = aes_mode(mode);
    if (!cipher)
        return EVP_ERROR;

    if (EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, key, iv) != EVP_SUCCESS)
        return EVP_ERROR;

    return EVP_SUCCESS;
}

/* Encrypt a chunk of plaintext bytes and write output to ciphertext buffer */
int aes_encrypt_update(EVP_CIPHER_CTX *cipher_ctx,
                       const unsigned char *plaintext,
                       int plaintext_len,
                       unsigned char *ciphertext,
                       int *ciphertext_len)
{
    if (EVP_EncryptUpdate(cipher_ctx, ciphertext, ciphertext_len, plaintext, plaintext_len) != EVP_SUCCESS)
        return EVP_ERROR;

    return EVP_SUCCESS;
}

/* Finalize encryption, applying PKCS#7 block padding if required (ECB/CBC) */
int aes_encrypt_final(EVP_CIPHER_CTX *cipher_ctx,
                      unsigned char *ciphertext,
                      int *ciphertext_len)
{
    if (EVP_EncryptFinal_ex(cipher_ctx, ciphertext, ciphertext_len) != EVP_SUCCESS)
        return EVP_ERROR;

    return EVP_SUCCESS;
}
