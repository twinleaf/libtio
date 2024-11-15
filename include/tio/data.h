// Copyright: 2016-2024 Twinleaf LLC
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

struct tl_data_stream_sample {
  uint8_t sample_start_0;
  uint8_t sample_start_1;
  uint8_t sample_start_2;
  uint8_t segment_id;
} __attribute__((__packed__));

struct tl_data_stream_packet {
  tl_packet_header hdr;
  union {
    uint32_t start_sample; // low 32 bit of sample counter
    struct tl_data_stream_sample sample;
  };
  uint8_t data[TL_DATA_STREAM_MAX_PAYLOAD_SIZE];
} __attribute__((__packed__));
typedef struct tl_data_stream_packet tl_data_stream_packet;

static inline
uint32_t tl_data_stream_sample_number(const struct tl_data_stream_packet *pkt)
{
  if (pkt->hdr.type == TL_PTYPE_STREAMN(0)) {
    return pkt->start_sample;
  } else {
    return ((pkt->sample.sample_start_0) |
            (pkt->sample.sample_start_1 << 8) |
            (pkt->sample.sample_start_2 << 16));
  }
}

static inline size_t tl_data_type_size(unsigned type)
{
  return (type >> 4) & 0xF;
}

// Streams metadata structs.

struct tl_metadata_header {
  uint8_t type;
  uint8_t flags;
} __attribute__((__packed__));
typedef struct tl_metadata_header tl_metadata_header;

#define TL_METADATA_INVALID             0
#define TL_METADATA_DEVICE              1
#define TL_METADATA_STREAM              2
#define TL_METADATA_SEGMENT             3
#define TL_METADATA_COLUMN              4

#define TL_METADATA_PERIODIC            (1<<0)
#define TL_METADATA_UPDATE              (1<<1)
#define TL_METADATA_LAST                (1<<2)

#define TL_METADATA_MAX_PAYLOAD_SIZE                        \
  (TL_PACKET_MAX_PAYLOAD_SIZE - sizeof(tl_metadata_header))

struct tl_metadata_container {
  tl_packet_header hdr;
  tl_metadata_header mhdr;
  uint8_t payload[TL_METADATA_MAX_PAYLOAD_SIZE];
} __attribute__((__packed__));

struct tl_metadata_device {
  uint8_t fixed_len;
  uint8_t name_varlen;
  uint32_t session_id;
  uint8_t serial_varlen;
  uint8_t firmware_varlen;
  uint8_t n_streams;
} __attribute__((__packed__));

struct tl_metadata_stream {
  uint8_t fixed_len;
  uint8_t stream_id;
  uint8_t n_columns;
  uint8_t n_segments;
  uint16_t sample_size;
  uint16_t buf_samples;
  uint8_t name_varlen;
} __attribute__((__packed__));

#define TL_METADATA_EPOCH_INVALID 0
#define TL_METADATA_EPOCH_ZERO    1
#define TL_METADATA_EPOCH_SYSTIME 2
#define TL_METADATA_EPOCH_UNIX    3

#define TL_METADATA_FILTER_NONE          0
#define TL_METADATA_FILTER_IIR_SP_LPF1   1
#define TL_METADATA_FILTER_IIR_SP_LPF2   2

// If this flag is not set, the rest of the segment metadata should be ignored
// as it means it's not populated/incorrect/invalid at this time.
#define TL_METADATA_SEGMENT_VALID        1
// If this flag is set, this stream segment is active, i.e. new samples
// are being generated.
#define TL_METADATA_SEGMENT_ACTIVE       2

struct tl_metadata_segment {
  uint8_t fixed_len;
  uint8_t stream_id;
  uint8_t segment_id;
  uint8_t flags;
  uint8_t time_ref_epoch;
  uint8_t time_ref_serial_varlen;
  uint32_t time_ref_session_id;
  uint32_t start_time; // seconds after the epoch
  uint32_t sampling_rate;
  uint32_t decimation;
  float filter_cutoff;
  uint8_t filter_type;
} __attribute__((__packed__));

struct tl_metadata_column {
  uint8_t fixed_len;
  uint8_t stream_id;
  uint8_t index;
  uint8_t data_type;
  uint8_t name_varlen;
  uint8_t units_varlen;
  uint8_t description_varlen;
} __attribute__((__packed__));

#endif // TL_DATA_H
