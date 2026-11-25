/**
 * @file main.c
 * @brief Encrypts raw pixel data of an image using AES-256 (ECB, CBC, or CTR)
 *        and outputs the encrypted result as a valid PNG image for visual comparison.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

#include "crypto.h"
#include "image_crypto.h"

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
    unsigned char *output_buf = NULL;

    size_t raw_size = (size_t)width * height * channels;
    

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

    size_t out_len = 0;
    output_buf = crypt_pixels(img_data, raw_size, is_encrypt, mode, key, iv, &out_len);
    if (!output_buf) {
        goto cleanup;
    }
    
    const char *out_filename = is_encrypt ? "encrypted.png" : "decrypted.png";
    if (!stbi_write_png(out_filename, width, height, channels, output_buf, width * channels)) {
        fprintf(stderr, "Failed to write %s\n", out_filename);
        goto cleanup;
    }

    printf("Success: saved %s\n", out_filename);
    ret = 0;

cleanup:
    free(output_buf);
    stbi_image_free(img_data);
    return ret;
}
