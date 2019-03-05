// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: MIT

#ifndef TL_DATA_H
#define TL_DATA_H

#include <tio/packet.h>
#include <tio/rpc.h>

#define TL_DATA_TYPE_UINT8      0x10 // 16
#define TL_DATA_TYPE_INT8       0x11 // 17
#define TL_DATA_TYPE_UINT16     0x20 // 32
#define TL_DATA_TYPE_INT16      0x21 // 33
#define TL_DATA_TYPE_UINT24     0x30 // 48
#define TL_DATA_TYPE_INT24      0x31 // 49
#define TL_DATA_TYPE_UINT32     0x40 // 64
#define TL_DATA_TYPE_INT32      0x41 // 65
#define TL_DATA_TYPE_UINT64     0x80 // 128
#define TL_DATA_TYPE_INT64      0x81 // 129
#define TL_DATA_TYPE_FLOAT32    0x42 // 66
#define TL_DATA_TYPE_FLOAT64    0x82 // 130

static inline size_t tl_data_type_size(unsigned type);

#define TL_TIMEBASE_SRC_INVALID 0
#define TL_TIMEBASE_SRC_LOCAL   1
#define TL_TIMEBASE_SRC_GLOBAL  2

#define TL_TIMEBASE_EPOCH_INVALID 0
#define TL_TIMEBASE_EPOCH_START   1
#define TL_TIMEBASE_EPOCH_SYSTIME 2
#define TL_TIMEBASE_EPOCH_UNIX    3
#define TL_TIMEBASE_EPOCH_GPS     4

#define TL_TIMEBASE_VALID   1
#define TL_TIMEBASE_DELETED 2

struct tl_timebase_info {
  uint16_t id;
  uint8_t source;
  uint8_t epoch;
  uint64_t start_time;
  uint32_t period_num_us;
  uint32_t period_denom_us;
  uint32_t flags;
  float stability; // positive or nan
  uint8_t source_id[16];
} __attribute__((__packed__));
typedef struct tl_timebase_info tl_timebase_info;

// Sent out when a timebase changes, or by user request
struct tl_timebase_update_packet {
  tl_packet_header hdr;
  tl_timebase_info info;
} __attribute__((__packed__));
typedef struct tl_timebase_update_packet tl_timebase_update_packet;


#define TL_SOURCE_DELETED 1

struct tl_source_info {
  uint16_t id;
  uint16_t timebase_id;
  uint32_t period;
  uint32_t offset;
  int32_t fmt;
  uint16_t flags;
  uint16_t channels;
  uint8_t type;
} __attribute__((__packed__));
typedef struct tl_source_info tl_source_info;

#define TL_SOURCE_MAX_NAME_LEN \
  (TL_RPC_REPLY_MAX_PAYLOAD_SIZE - sizeof(tl_source_info))

// Sent out when a source is created or deleted, or by user request
struct tl_source_update_packet {
  tl_packet_header hdr;
  tl_source_info info;
  char name[TL_SOURCE_MAX_NAME_LEN]; // not null terminated
} __attribute__((__packed__));
typedef struct tl_source_update_packet tl_source_update_packet;


#define TL_STREAM_COMPONENT_RESAMPLED 0x1

struct tl_stream_component_info {
  uint16_t source_id;
  uint16_t flags;
  uint32_t period;
  uint32_t offset;
} __attribute__((__packed__));
typedef struct tl_stream_component_info tl_stream_component_info;

#define TL_STREAM_ACTIVE    0x1
#define TL_STREAM_ONLY_INFO 0x2
#define TL_STREAM_DELETED   0x4

struct tl_stream_info {
  uint16_t id;
  uint16_t timebase_id;
  uint32_t period;
  uint32_t offset;
  uint64_t sample_number; // 64 bit sample number
  uint16_t total_components;
  uint16_t flags;
} __attribute__((__packed__));
typedef struct tl_stream_info tl_stream_info;

#define TL_STREAM_MAX_ID 127
#define TL_STREAM_MAX_UPDATE_COMPONENTS 32

// Sent out when a stream changes, or by user request
struct tl_stream_update_packet {
  tl_packet_header hdr;
  tl_stream_info info;
  tl_stream_component_info component[TL_STREAM_MAX_UPDATE_COMPONENTS];
} __attribute__((__packed__));
typedef struct tl_stream_update_packet tl_stream_update_packet;

#define TL_DATA_STREAM_MAX_PAYLOAD_SIZE \
  (TL_PACKET_MAX_PAYLOAD_SIZE - sizeof(uint32_t))

struct tl_data_stream_packet {
  tl_packet_header hdr;
  uint32_t start_sample; // low 32 bit of sample counter
  uint8_t data[TL_DATA_STREAM_MAX_PAYLOAD_SIZE];
} __attribute__((__packed__));
typedef struct tl_data_stream_packet tl_data_stream_packet;

static inline size_t tl_data_type_size(unsigned type)
{
  return (type >> 4) & 0xF;
}

#endif // TL_DATA_H
