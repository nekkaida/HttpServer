#ifndef HTTP_SERVER_GZIP_H
#define HTTP_SERVER_GZIP_H

/**
 * Gzip Compression Module
 *
 * Provides simple gzip compression for HTTP responses.
 * Note: This is a minimal implementation using stored blocks (no compression).
 * For production, consider using zlib for actual compression.
 */

#include "../include/common.h"

// =============================================================================
// COMPRESSION FUNCTIONS
// =============================================================================

/**
 * Initialize the CRC32 table for gzip checksum calculation.
 * Must be called once before using gzip_compress().
 */
void gzip_init(void);

/**
 * Compress data using gzip format.
 *
 * Note: This implementation uses stored blocks (no actual compression).
 * The output may be larger than the input due to gzip headers.
 *
 * @param dest Destination buffer (must be at least source_len + 32 bytes)
 * @param source Source data to compress
 * @param source_len Length of source data
 * @return Size of compressed data, or 0 on error
 */
unsigned long gzip_compress(char *dest, const char *source, unsigned long source_len);

/**
 * Calculate CRC32 checksum for data.
 *
 * @param crc Initial CRC value (use 0 for new calculation)
 * @param buf Data buffer
 * @param len Length of data
 * @return CRC32 checksum
 */
uint32_t gzip_crc32(uint32_t crc, const unsigned char *buf, size_t len);

#endif // HTTP_SERVER_GZIP_H
