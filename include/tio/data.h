// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

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
  uint8_t src_param[16];
  uint32_t flags;
  uint32_t period_num_us;
  uint32_t period_denom_us;
  uint16_t stability_ppb; //0xFFFF = unspecified or >= 65.5 ppm
} __attribute__((__packed__));
typedef struct tl_timebase_info tl_timebase_info;


struct tl_timebase_update_packet {
  tl_packet_header hdr;
  tl_timebase_info info;
} __attribute__((__packed__));
typedef struct tl_timebase_update_packet tl_timebase_update_packet;


#define TL_PSTREAM_DELETED 1

struct tl_pstream_info {
  uint16_t id;
  uint16_t timebase_id;
  uint32_t period;
  uint32_t offset;
  int32_t fmt;
  uint16_t flags;
  uint16_t channels;
  uint8_t type;
} __attribute__((__packed__));
typedef struct tl_pstream_info tl_pstream_info;

#define TL_PSTREAM_MAX_NAME_LEN \
  (TL_RPC_REPLY_MAX_PAYLOAD_SIZE - sizeof(tl_pstream_info))

struct tl_pstream_update_packet {
  tl_packet_header hdr;
  tl_pstream_info info;
  char name[TL_PSTREAM_MAX_NAME_LEN]; // not null terminated
} __attribute__((__packed__));
typedef struct tl_pstream_update_packet tl_pstream_update_packet;


#define TL_DSTREAM_COMPONENT_RESAMPLED 0x1

struct tl_dstream_component_info {
  uint16_t pstream_id;
  uint16_t flags;
  uint32_t period;
  uint32_t offset;
} __attribute__((__packed__));
typedef struct tl_dstream_component_info tl_dstream_component_info;

struct tl_dstream_info {
  uint16_t id;
  uint16_t timebase_id;
  uint32_t period;
  uint32_t offset;
  uint16_t total_components;
  uint16_t cinfo_start;
  uint16_t cinfo_len;
  uint16_t flags;
} __attribute__((__packed__));
typedef struct tl_dstream_info tl_dstream_info;

#define TL_DSTREAM_MAX_ID 127
#define TL_DSTREAM_MAX_UPDATE_COMPONENTS 40

struct tl_dstream_update_packet {
  tl_packet_header hdr;
  tl_dstream_info info;
  tl_dstream_component_info component[TL_DSTREAM_MAX_UPDATE_COMPONENTS];
} __attribute__((__packed__));
typedef struct tl_dstream_update_packet tl_dstream_update_packet;

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
