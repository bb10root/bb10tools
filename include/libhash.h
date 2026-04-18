#ifndef _LIBHASH_H_INCLUDED
#define _LIBHASH_H_INCLUDED

#include <stdint.h>
#include <string.h>

#define PRIME32_1 2654435761U
#define PRIME32_2 2246822519U
#define PRIME32_3 3266489917U
#define PRIME32_4 668265263U
#define PRIME32_5 374761393U

// Helper for unaligned memory access
static uint32_t XXH_read32(const void *ptr)
{
    uint32_t val;
    memcpy(&val, ptr, sizeof(val));
    return val;
}

static uint32_t XXH_rotl32(uint32_t x, int r)
{
    return (x << r) | (x >> (32 - r));
}

uint32_t xxHash32_Universal(const void *input, size_t len, uint32_t seed)
{
    const uint8_t *p = (const uint8_t *)input;
    const uint8_t *const bEnd = p + len;
    uint32_t h32;

    if (len >= 16)
    {
        const uint8_t *const limit = bEnd - 16;
        uint32_t v1 = seed + PRIME32_1 + PRIME32_2;
        uint32_t v2 = seed + PRIME32_2;
        uint32_t v3 = seed + 0;
        uint32_t v4 = seed - PRIME32_1;

        do
        {
            // Safe unaligned reads
            v1 += XXH_read32(p) * PRIME32_2;
            v1 = XXH_rotl32(v1, 13);
            v1 *= PRIME32_1;
            p += 4;

            v2 += XXH_read32(p) * PRIME32_2;
            v2 = XXH_rotl32(v2, 13);
            v2 *= PRIME32_1;
            p += 4;

            v3 += XXH_read32(p) * PRIME32_2;
            v3 = XXH_rotl32(v3, 13);
            v3 *= PRIME32_1;
            p += 4;

            v4 += XXH_read32(p) * PRIME32_2;
            v4 = XXH_rotl32(v4, 13);
            v4 *= PRIME32_1;
            p += 4;
        } while (p <= limit);

        h32 = XXH_rotl32(v1, 1) + XXH_rotl32(v2, 7) + XXH_rotl32(v3, 12) + XXH_rotl32(v4, 18);
    }
    else
    {
        h32 = seed + PRIME32_5;
    }

    h32 += (uint32_t)len;

    // Remaining 4-byte chunks
    while (p + 4 <= bEnd)
    {
        h32 += XXH_read32(p) * PRIME32_3;
        h32 = XXH_rotl32(h32, 17) * PRIME32_4;
        p += 4;
    }

    // Remaining bytes
    while (p < bEnd)
    {
        h32 += (*p) * PRIME32_5;
        h32 = XXH_rotl32(h32, 11) * PRIME32_1;
        p++;
    }

    // Final mixing (Avalanche)
    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;
}

uint32_t calculate_crc32(const unsigned char *data, size_t n_bytes)
{
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < n_bytes; i++)
    {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
        {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}
#endif