/**
 * @file gui.c
 * @brief raylib + raygui front end for the AES image encryption tool.
 *        Drag an image onto the window, pick a mode, press Encrypt/Decrypt.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#include "raylib.h"
#define RAYGUI_IMPLEMENTATION
#include "raygui.h"

#include "crypto.h"
#include "image_crypto.h"

#define WIN_W 1000
#define WIN_H 620
#define CHANNELS 3 /* images are converted to RGB so the byte layout is predictable */

static Image src;        /* original (or "input") image, raylib-owned data */
static Texture2D src_tex;
static int has_src = 0;

static Image res;        /* result image, data is malloc'd by crypt_pixels */
static Texture2D res_tex;
static int has_res = 0;
static int last_was_encrypt = 1;

static int mode = 0;     /* toggle index: 0=ECB, 1=CBC, 2=CTR  (mode id = index + 1) */
static char status[160] = "Drag an image onto the window to begin.";

/* Replace the source image (takes ownership of img) */
static void set_src_image(Image img)
{
    if (has_src) {
        UnloadTexture(src_tex);
        UnloadImage(src);
    }
    ImageFormat(&img, PIXELFORMAT_UNCOMPRESSED_R8G8B8);
    src = img;
    src_tex = LoadTextureFromImage(src);
    has_src = 1;
}

static void load_source(const char *path)
{
    Image img = LoadImage(path);
    if (img.data == NULL) {
        snprintf(status, sizeof(status), "Failed to load image: %s", path);
        return;
    }
    set_src_image(img);
    snprintf(status, sizeof(status), "Loaded %s (%dx%d)", GetFileName(path), src.width, src.height);
}

static void clear_result(void)
{
    if (has_res) {
        UnloadTexture(res_tex);
        free(res.data);
        has_res = 0;
    }
}

/* Same steps as main.c: get key/iv, run crypt_pixels, show the result */
static void process(int is_encrypt)
{
    int mode_id = mode + 1;

    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};

    if (is_encrypt) {
        if (RAND_bytes(key, sizeof(key)) != EVP_SUCCESS ||
            (mode_id != 1 && RAND_bytes(iv, sizeof(iv)) != EVP_SUCCESS)) {
            snprintf(status, sizeof(status), "Random generation failed");
            return;
        }
        if (!save_key_iv("key.bin", key, iv)) {
            snprintf(status, sizeof(status), "Failed to save key.bin");
            return;
        }
    } else {
        if (!load_key_iv("key.bin", key, iv)) {
            snprintf(status, sizeof(status), "Failed to load key.bin (encrypt an image first)");
            return;
        }
    }

    size_t raw_size = (size_t)src.width * src.height * CHANNELS;
    size_t out_len = 0;
    unsigned char *out = crypt_pixels((const unsigned char *)src.data, raw_size,
                                      is_encrypt, mode_id, key, iv, &out_len);
    if (!out) {
        snprintf(status, sizeof(status), "%s failed", is_encrypt ? "Encryption" : "Decryption");
        return;
    }

    clear_result();
    res.data = out;
    res.width = src.width;
    res.height = src.height;
    res.mipmaps = 1;
    res.format = PIXELFORMAT_UNCOMPRESSED_R8G8B8;
    res_tex = LoadTextureFromImage(res);
    has_res = 1;
    last_was_encrypt = is_encrypt;

    snprintf(status, sizeof(status), "%s done (%s)",
             is_encrypt ? "Encryption" : "Decryption", is_encrypt ? "key saved to key.bin" : "used key.bin");
}

/* Draw a texture scaled to fit inside area, keeping aspect ratio */
static void draw_fit(Texture2D t, Rectangle area)
{
    DrawRectangleLinesEx(area, 1, GRAY);
    float scale = area.width / t.width;
    if (area.height / t.height < scale) scale = area.height / t.height;
    float w = t.width * scale, h = t.height * scale;
    Rectangle dst = { area.x + (area.width - w) / 2, area.y + (area.height - h) / 2, w, h };
    DrawTexturePro(t, (Rectangle){ 0, 0, (float)t.width, (float)t.height }, dst, (Vector2){ 0, 0 }, 0, WHITE);
}

int main(void)
{
    InitWindow(WIN_W, WIN_H, "AES Image Encryption");
    SetTargetFPS(60);

    while (!WindowShouldClose()) {
        if (IsFileDropped()) {
            FilePathList files = LoadDroppedFiles();
            if (files.count > 0) {
                load_source(files.paths[0]);
                clear_result();
            }
            UnloadDroppedFiles(files);
        }

        BeginDrawing();
        ClearBackground(RAYWHITE);

        /* Controls */
        GuiLabel((Rectangle){ 20, 15, 50, 30 }, "Mode:");
        GuiToggleGroup((Rectangle){ 70, 15, 70, 30 }, "ECB;CBC;CTR", &mode);

        if (!has_src) GuiDisable();
        if (GuiButton((Rectangle){ 330, 15, 100, 30 }, "Encrypt")) process(1);
        if (GuiButton((Rectangle){ 440, 15, 100, 30 }, "Decrypt")) process(0);
        GuiEnable();

        if (!has_res) GuiDisable();
        if (GuiButton((Rectangle){ 570, 15, 150, 30 }, "Result -> Input")) {
            set_src_image(ImageCopy(res));
            clear_result();
            snprintf(status, sizeof(status), "Result moved to input");
        }
        if (GuiButton((Rectangle){ 730, 15, 120, 30 }, "Save result")) {
            const char *name = last_was_encrypt ? "encrypted.png" : "decrypted.png";
            if (ExportImage(res, name))
                snprintf(status, sizeof(status), "Saved %s", name);
            else
                snprintf(status, sizeof(status), "Failed to save %s", name);
        }
        GuiEnable();

        /* Previews */
        GuiLabel((Rectangle){ 20, 60, 200, 20 }, "Input");
        GuiLabel((Rectangle){ 510, 60, 200, 20 }, "Result");
        Rectangle left  = { 20, 85, 470, 470 };
        Rectangle right = { 510, 85, 470, 470 };
        if (has_src) draw_fit(src_tex, left);   else DrawRectangleLinesEx(left, 1, GRAY);
        if (has_res) draw_fit(res_tex, right);  else DrawRectangleLinesEx(right, 1, GRAY);

        /* Status bar */
        GuiLabel((Rectangle){ 20, 575, 960, 30 }, status);

        EndDrawing();
    }

    clear_result();
    if (has_src) {
        UnloadTexture(src_tex);
        UnloadImage(src);
    }
    CloseWindow();
    return 0;
}
