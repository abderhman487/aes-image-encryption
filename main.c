/**
 * @file main.c
 * @brief Encrypts raw pixel data of an image using AES-256 (ECB, CBC, or CTR)
 *        and outputs the encrypted result as a valid PNG image for visual comparison.
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

#include "crypto.h"

/* Save 32-byte key and 16-byte IV to a binary file for later decryption */
static int save_key_iv(const char *filename, const unsigned char *key, const unsigned char *iv)
{
    FILE *f = fopen(filename, "wb");
    if (!f) return 0;
    size_t w1 = fwrite(key, 1, 32, f);
    size_t w2 = fwrite(iv, 1, 16, f);
    fclose(f);
    return (w1 == 32 && w2 == 16);
}

/* Load 32-byte key and 16-byte IV from a binary file */
static int load_key_iv(const char *filename, unsigned char *key, unsigned char *iv)
{
    FILE *f = fopen(filename, "rb");
    if (!f) return 0;
    size_t r1 = fread(key, 1, 32, f);
    size_t r2 = fread(iv, 1, 16, f);
    fclose(f);
    return (r1 == 32 && r2 == 16);
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <enc|dec> <image_path> <mode: 1=ECB, 2=CBC, 3=CTR>\n", argv[0]);
        return 1;
    }

    int is_encrypt;
    if (strcmp(argv[1], "enc") == 0) {
        is_encrypt = 1;
    } else if (strcmp(argv[1], "dec") == 0) {
        is_encrypt = 0;
    } else {
        fprintf(stderr, "Invalid operation: use 'enc' or 'dec'\n");
        return 1;
    }

    int mode = atoi(argv[3]);
    if (mode < 1 || mode > 3) {
        fprintf(stderr, "Invalid mode: 1 (ECB), 2 (CBC), 3 (CTR)\n");
        return 1;
    }

    /* Decode image into raw uncompressed pixel buffer (RGB/RGBA) */
    int width, height, channels;
    unsigned char *img_data = stbi_load(argv[2], &width, &height, &channels, 0);
    if (!img_data) {
        fprintf(stderr, "Failed to load image: %s\n", stbi_failure_reason());
        return 1;
    }

    int ret = 1;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    unsigned char *input_buf = NULL;
    unsigned char *output_buf = NULL;

    /* Allocate buffer for ciphertext with extra room for block padding */
    size_t raw_size = (size_t)width * height * channels;
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

    /* Generate random 256-bit key and 128-bit IV (IV is unused in ECB mode) */
    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};

    if (is_encrypt) {
        if (RAND_bytes(key, sizeof(key)) != EVP_SUCCESS ||
            (mode != 1 && RAND_bytes(iv, sizeof(iv)) != EVP_SUCCESS)) {
            fprintf(stderr, "Random generation failed\n");
            goto cleanup;
        }
        if (!save_key_iv("key.bin", key, iv)) {
            fprintf(stderr, "Failed to save key.bin\n");
            goto cleanup;
        }
    } else {
        if (!load_key_iv("key.bin", key, iv)) {
            fprintf(stderr, "Failed to load key.bin (encrypt an image first)\n");
            goto cleanup;
        }
    }

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

    const char *out_filename = is_encrypt ? "encrypted.png" : "decrypted.png";
    if (!stbi_write_png(out_filename, width, height, channels, output_buf, width * channels)) {
        fprintf(stderr, "Failed to write %s\n", out_filename);
        goto cleanup;
    }

    printf("Success: saved %s\n", out_filename);
    ret = 0;

cleanup:
    if (cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
    free(input_buf);
    free(output_buf);
    stbi_image_free(img_data);
    return ret;
}
