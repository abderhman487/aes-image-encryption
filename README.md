# AES-256 Image Encryption

A C tool using **OpenSSL EVP** and **stb_image** to encrypt raw image pixels using AES-256 (**ECB**, **CBC**, and **CTR** modes) and output a viewable `encrypted.png` to visually compare cipher modes.

## Prerequisites
* GCC & OpenSSL (`libcrypto`)

## Build & Run
```bash
gcc -Wall -Wextra main.c crypto.c -o encrypt -lcrypto -lm
./encrypt <image_path>
```

Select the mode when prompted (`1`: ECB, `2`: CBC, `3`: CTR). The output is saved as `encrypted.png`.

## Visual Comparison

| Original | AES-256-ECB | AES-256-CBC / CTR |
| :---: | :---: | :---: |
| ![Original](samples/original.png) | ![ECB](samples/ecb_encrypted.png) | ![CBC](samples/cbc_encrypted.png) |