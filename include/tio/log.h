// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: MIT

// Structures, constants, and helpers for logging related packets.

#ifndef TL_LOG_H
#define TL_LOG_H

#include <tio/packet.h>
#include <stdarg.h>

typedef uint8_t tl_log_t;

#define TL_LOG_CRITICAL   0
#define TL_LOG_ERROR      1
#define TL_LOG_WARNING    2
#define TL_LOG_INFO       3
#define TL_LOG_DEBUG      4

struct tl_log_header {
  uint32_t data;
  tl_log_t level;
} __attribute__((__packed__));
typedef struct tl_log_header tl_log_header;

#define TL_LOG_MAX_MESSAGE_SIZE \
  (TL_PACKET_MAX_PAYLOAD_SIZE - sizeof(tl_log_header))

struct tl_log_packet {
  tl_packet_header hdr;
  tl_log_header    log;
  char message[TL_LOG_MAX_MESSAGE_SIZE];
  uint8_t __routing_reserved[TL_PACKET_MAX_ROUTING_SIZE];
} __attribute__((__packed__));
typedef struct tl_log_packet tl_log_packet;

static inline size_t tl_log_packet_message_size(const tl_log_packet *pkt);

#ifdef __cplusplus
extern "C" {
#endif

// snprintf-like method to format a log packet's message
int tl_log_packet_snprintf(tl_log_packet *lp, size_t size,
                           const char *fmt, ...)
  __attribute__((format(printf, 3, 4)));

// vsnprintf-like method to format a log packet's message
int tl_log_packet_vsnprintf(tl_log_packet *lp, size_t size,
                            const char *fmt, va_list ap);

#ifdef __cplusplus
}
#endif

//////////////////////////////////////
// Implementation of inline methods

static inline size_t tl_log_packet_message_size(const tl_log_packet *pkt)
{
  return pkt->hdr.payload_size - sizeof(tl_log_header);
}

#endif // TL_LOG_H
