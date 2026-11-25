#ifndef IMAGE_CRYPTO_H
#define IMAGE_CRYPTO_H

#include <stddef.h>

/* Save 32-byte key and 16-byte IV to a binary file for later decryption */
int save_key_iv(const char *filename, const unsigned char *key, const unsigned char *iv);

/* Load 32-byte key and 16-byte IV from a binary file */
int load_key_iv(const char *filename, unsigned char *key, unsigned char *iv);

/* Encrypts or decrypts a raw pixel buffer (returns newly allocated buffer, caller frees) */
unsigned char *crypt_pixels(const unsigned char *pixels,
                            size_t raw_size,
                            int is_encrypt,
                            int mode,
                            const unsigned char *key,
                            const unsigned char *iv,
                            size_t *out_len);

#endif
