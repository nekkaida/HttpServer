/**
 * Gzip Compression Module Implementation
 *
 * Minimal gzip implementation using stored blocks.
 * For production use, integrate zlib for actual compression.
 */

#include "gzip.h"

// =============================================================================
// CRC32 TABLE
// =============================================================================

static uint32_t crc_table[256];
static int crc_initialized = 0;

void gzip_init(void) {
    if (crc_initialized) return;

    for (int i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            if (c & 1)
                c = 0xEDB88320 ^ (c >> 1);
            else
                c = c >> 1;
        }
        crc_table[i] = c;
    }
    crc_initialized = 1;
}

// =============================================================================
// CRC32 CALCULATION
// =============================================================================

uint32_t gzip_crc32(uint32_t crc, const unsigned char *buf, size_t len) {
    crc = ~crc;
    while (len--) {
        crc = crc_table[(crc ^ *buf) & 0xFF] ^ (crc >> 8);
        buf++;
    }
    return ~crc;
}

// =============================================================================
// GZIP COMPRESSION
// =============================================================================

unsigned long gzip_compress(char *dest, const char *source, unsigned long source_len) {
    if (dest == NULL || source == NULL || source_len == 0) {
        return 0;
    }

    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)source;

    // Ensure CRC table is initialized
    gzip_init();

    // Calculate CRC32 and length
    uint32_t crc = gzip_crc32(0, s, source_len);
    uint32_t len = source_len;

    // Gzip header (10 bytes)
    // Magic number (ID1, ID2)
    *d++ = 0x1f;
    *d++ = 0x8b;
    // Compression method (8 = deflate)
    *d++ = 8;
    // Flags (0 = no extra fields)
    *d++ = 0;
    // Modification time (4 bytes, set to 0)
    *d++ = 0;
    *d++ = 0;
    *d++ = 0;
    *d++ = 0;
    // Extra flags (2 = max compression)
    *d++ = 2;
    // Operating system (255 = unknown)
    *d++ = 255;

    // Store uncompressed data with deflate stored block header
    // In a real implementation, this is where deflate compressed data would go
    // For this simple implementation, we're storing uncompressed data

    // Add a stored block header
    // 1 byte: last block (1) + type (00 = stored)
    *d++ = 0x01;
    // 2 bytes: length (little-endian)
    *d++ = len & 0xff;
    *d++ = (len >> 8) & 0xff;
    // 2 bytes: one's complement of length
    *d++ = (~len) & 0xff;
    *d++ = (~len >> 8) & 0xff;

    // Copy the data
    memcpy(d, s, len);
    d += len;

    // Gzip footer (8 bytes)
    // CRC32 (4 bytes, little-endian)
    *d++ = crc & 0xff;
    *d++ = (crc >> 8) & 0xff;
    *d++ = (crc >> 16) & 0xff;
    *d++ = (crc >> 24) & 0xff;

    // Input size modulo 2^32 (4 bytes, little-endian)
    *d++ = len & 0xff;
    *d++ = (len >> 8) & 0xff;
    *d++ = (len >> 16) & 0xff;
    *d++ = (len >> 24) & 0xff;

    // Return total size
    return (d - (unsigned char *)dest);
}
