#ifndef SIGNATURES_H
#define SIGNATURES_H
#include <stddef.h>

#define MAX_SIG_LEN 32

typedef struct {
    const char* name;
    unsigned char pattern[MAX_SIG_LEN];
    unsigned char mask[MAX_SIG_LEN];
    size_t len;
    size_t found_offset;
    int found;
} Signature;

static Signature db[] = {
    {
        .name = "isDeviceSecure",
        .pattern = {0x08, 0xB5, 0x07, 0x4B, 0x7B, 0x44, 0x58, 0x68, 0x02, 0x28, 0x01, 0xD1, 0xFF, 0xF7, 0x40, 0xFF, 0x04, 0x4B, 0x7B, 0x44, 0x58, 0x68, 0xD0, 0xF1, 0x01, 0x00, 0x38, 0xBF, 0x00, 0x20, 0x08, 0xBD},
        .mask = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
        .len = 32,
        .found_offset = 0,
        .found = 0
    }
};

#define SIG_COUNT (sizeof(db) / sizeof(Signature))

#endif // SIGNATURES_H
