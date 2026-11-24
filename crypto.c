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

    /* Disable PKCS#7 padding so output matches exact pixel buffer size */
    EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);

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



/* Initialize the decryption context with the chosen AES-256 mode, key, and IV */
int aes_decrypt_init(EVP_CIPHER_CTX *cipher_ctx,
                     int mode,
                     const unsigned char *key,
                     const unsigned char *iv)
{
    const EVP_CIPHER *cipher = aes_mode(mode);
    if (!cipher)
        return EVP_ERROR;

    if (EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, key, iv) != EVP_SUCCESS)
        return EVP_ERROR;

    /* Disable PKCS#7 padding to match encryption behavior */
    EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);

    return EVP_SUCCESS;
}

/* Decrypt a chunk of ciphertext bytes and write output to plaintext buffer */
int aes_decrypt_update(EVP_CIPHER_CTX *cipher_ctx,
                       const unsigned char *ciphertext,
                       int ciphertext_len,
                       unsigned char *plaintext,
                       int *plaintext_len)
{
    if (EVP_DecryptUpdate(cipher_ctx, plaintext, plaintext_len, ciphertext, ciphertext_len) != EVP_SUCCESS)
        return EVP_ERROR;

    return EVP_SUCCESS;
}

/* Finalize decryption and verify/strip PKCS#7 block padding if enabled */
int aes_decrypt_final(EVP_CIPHER_CTX *cipher_ctx,
                      unsigned char *plaintext,
                      int *plaintext_len)
{
    if (EVP_DecryptFinal_ex(cipher_ctx, plaintext, plaintext_len) != EVP_SUCCESS)
        return EVP_ERROR;

    return EVP_SUCCESS;
}
