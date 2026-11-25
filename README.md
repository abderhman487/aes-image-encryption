# AES-256 Image Encryption

A C tool using **OpenSSL EVP** and **stb_image** to encrypt raw image pixels using AES-256 (**ECB**, **CBC**, and **CTR** modes) and output a viewable `encrypted.png` to visually compare cipher modes.

## Prerequisites
* GCC & OpenSSL (`libcrypto`)
- **For GUI:** `raylib` 

## Build & Run

### CLI
```bash
gcc -Wall -Wextra main.c crypto.c image_crypto.c -o encrypt -lcrypto -lm
./encrypt <enc|dec> <image_path> <mode>
```
Select the mode when prompted (`1`: ECB, `2`: CBC, `3`: CTR). The output is saved as `encrypted.png`.

### GUI
```bash
gcc gui.c crypto.c image_crypto.c -o gui -lraylib -lcrypto -lm
./gui
```
Drag and drop an image onto the window, select ECB, CBC, or CTR, and click Encrypt or Decrypt.

## Visual Comparison

| Original | AES-256-ECB | AES-256-CBC / CTR |
| :---: | :---: | :---: |
| ![Original](samples/original.png) | ![ECB](samples/ecb_encrypted.png) | ![CBC](samples/cbc_encrypted.png) |