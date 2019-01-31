// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: MIT

#ifndef TL_ERROR_DETECTION_CODES_H
#define TL_ERROR_DETECTION_CODES_H

#include <stddef.h>
#include <stdint.h>

// sizes in bytes of the codes
#define TL_INET_CKSUM_SIZE 2
#define TL_CRC32_SIZE      4

// Incremental CRC32 computation (see crc32 comment below for how it's used)
static inline uint32_t tl_crc32_init(void);
static inline uint32_t tl_crc32_incremental(uint32_t crc, uint8_t byte);
static inline uint32_t tl_crc32_finalize(uint32_t crc);

#ifdef __cplusplus
extern "C" {
#endif

// Compute the internet checksum of a buffer. If size is odd, pads with zero.
uint16_t tl_inet_checksum(const void *buf, size_t len);

// Compute the CRC32 for a buffer. Equivalent to
//  uint32_t crc = crc32Init();
//  for (size_t i = 0; i < len; i++)
//    crc = crc32Incremental(crc, buf[i]);
//  return crc32Finalize(crc);
uint32_t tl_crc32(const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

extern const uint32_t __tl_crc32_lookup[256];

uint32_t tl_crc32_init(void)
{
  return 0xFFFFFFFF;
}

uint32_t tl_crc32_incremental(uint32_t crc, uint8_t byte)
{
  size_t offset = (crc ^ byte) & 0xFF;
  return __tl_crc32_lookup[offset] ^ (crc >> 8);
}

uint32_t tl_crc32_finalize(uint32_t crc)
{
  return ~crc;
}

#endif // TL_ERROR_DETECTION_CODES_H
