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

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <image_path>\n", argv[0]);
        return 1;
    }

    /* Decode image into raw uncompressed pixel buffer (RGB/RGBA) */
    int width, height, channels;
    unsigned char *img_data = stbi_load(argv[1], &width, &height, &channels, 0);
    if (!img_data) {
        fprintf(stderr, "Failed to load image: %s\n", stbi_failure_reason());
        return 1;
    }

    printf("Enter the required encryption mode:\n1- ECB\n2- CBC\n3- CTR\n: ");
    int mode;
    if (scanf("%d", &mode) != 1 || mode < 1 || mode > 3) {
        fprintf(stderr, "Invalid mode\n");
        stbi_image_free(img_data);
        return 1;
    }

    int ret = 1;
    EVP_CIPHER_CTX *cipher_ctx = NULL;

    /* Allocate buffer for ciphertext with extra room for block padding */
    size_t raw_size = (size_t)width * height * channels;
    unsigned char *ciphertext = malloc(raw_size + EVP_MAX_BLOCK_LENGTH);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    /* Generate random 256-bit key and 128-bit IV (IV is unused in ECB mode) */
    unsigned char key[32];
    unsigned char iv[16];
    if (RAND_bytes(key, sizeof(key)) != EVP_SUCCESS ||
        (mode != 1 && RAND_bytes(iv, sizeof(iv)) != EVP_SUCCESS)) {
        fprintf(stderr, "Random generation failed\n");
        goto cleanup;
    }

    /* Create and initialize OpenSSL cipher context */
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        fprintf(stderr, "Error creating ctx!\n");
        goto cleanup;
    }

    if (aes_encrypt_init(cipher_ctx, mode, key, mode == 1 ? NULL : iv) != EVP_SUCCESS) {
        fprintf(stderr, "Error initializing cipher!\n");
        goto cleanup;
    }

    /* Encrypt raw pixel bytes */
    int update_len = 0, final_len = 0;
    if (aes_encrypt_update(cipher_ctx, img_data, (int)raw_size, ciphertext, &update_len) != EVP_SUCCESS) {
        fprintf(stderr, "Error updating ciphertext\n");
        goto cleanup;
    }

    if (aes_encrypt_final(cipher_ctx, ciphertext + update_len, &final_len) != EVP_SUCCESS) {
        fprintf(stderr, "Error finalizing ciphertext\n");
        goto cleanup;
    }

    /* Re-encode encrypted bytes into a PNG (trailing block padding is truncated to preserve dimensions) */
    if (!stbi_write_png("encrypted.png", width, height, channels, ciphertext, width * channels)) {
        fprintf(stderr, "Failed to write encrypted image\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (cipher_ctx) EVP_CIPHER_CTX_free(cipher_ctx);
    free(ciphertext);
    stbi_image_free(img_data);
    return ret;
}
