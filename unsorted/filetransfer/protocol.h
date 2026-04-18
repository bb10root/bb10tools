#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define PORT 22222
#define MAX_FILENAME 256

// Типи операцій
#define CMD_PUT 1
#define CMD_GET 2
#define CMD_ERROR 404

struct file_header {
    uint32_t command;
    char name[MAX_FILENAME];
    uint32_t size;
    uint32_t crc32;
    uint32_t mode;
}__attribute__((packed));

// CRC32 залишається без змін
uint32_t calculate_crc32(const unsigned char *data, size_t n_bytes) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < n_bytes; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

#endif