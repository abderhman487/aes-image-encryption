#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "image_crypto.h"

/* Save 32-byte key and 16-byte IV to a binary file for later decryption */
int save_key_iv(const char *filename, const unsigned char *key, const unsigned char *iv)
{
    FILE *f = fopen(filename, "wb");
    if (!f) return 0;
    size_t w1 = fwrite(key, 1, 32, f);
    size_t w2 = fwrite(iv, 1, 16, f);
    fclose(f);
    return (w1 == 32 && w2 == 16);
}

/* Load 32-byte key and 16-byte IV from a binary file */
int load_key_iv(const char *filename, unsigned char *key, unsigned char *iv)
{
    FILE *f = fopen(filename, "rb");
    if (!f) return 0;
    size_t r1 = fread(key, 1, 32, f);
    size_t r2 = fread(iv, 1, 16, f);
    fclose(f);
    return (r1 == 32 && r2 == 16);
}

unsigned char *crypt_pixels(const unsigned char *img_data, size_t raw_size,
                            int is_encrypt, int mode,
                            const unsigned char *key, const unsigned char *iv,
                            size_t *out_len)
{
    unsigned char *result = NULL;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    unsigned char *input_buf = NULL;
    unsigned char *output_buf = NULL;

    /* Allocate buffer for ciphertext with extra room for block padding */
    /* Align buffer to 16-byte AES block boundary since padding is disabled */
    size_t remainder = raw_size % 16;
    size_t aligned_size = (remainder == 0) ? raw_size : raw_size + (16 - remainder);
    
    input_buf = calloc(1, aligned_size);
    output_buf = malloc(aligned_size + EVP_MAX_BLOCK_LENGTH);
    if (!input_buf || !output_buf) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }
    memcpy(input_buf, img_data, raw_size);

    /* Create and initialize OpenSSL cipher context */
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        fprintf(stderr, "Error creating ctx\n");
        goto cleanup;
    }

    int update_len = 0, final_len = 0;
    const unsigned char *iv_ptr = (mode == 1) ? NULL : iv;

    if (is_encrypt) {
        if (aes_encrypt_init(cipher_ctx, mode, key, iv_ptr) != EVP_SUCCESS ||
            aes_encrypt_update(cipher_ctx, input_buf, (int)aligned_size, output_buf, &update_len) != EVP_SUCCESS ||
            aes_encrypt_final(cipher_ctx, output_buf + update_len, &final_len) != EVP_SUCCESS) {
            fprintf(stderr, "Encryption failed\n");
            goto cleanup;
        }
    } else {
        if (aes_decrypt_init(cipher_ctx, mode, key, iv_ptr) != EVP_SUCCESS ||
            aes_decrypt_update(cipher_ctx, input_buf, (int)aligned_size, output_buf, &update_len) != EVP_SUCCESS ||
            aes_decrypt_final(cipher_ctx, output_buf + update_len, &final_len) != EVP_SUCCESS) {
            fprintf(stderr, "Decryption failed\n");
            goto cleanup;
        }
    }

    *out_len = raw_size;
    result = output_buf;
    output_buf = NULL;  /* ownership passes to the caller */

cleanup:
    if (cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
    free(input_buf);
    free(output_buf);
    return result;
}
