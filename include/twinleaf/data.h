// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#ifndef TL_DATA_H
#define TL_DATA_H

#include <twinleaf/packet.h>

#define TL_DATA_TYPE_UINT8      0x10
#define TL_DATA_TYPE_INT8       0x11
#define TL_DATA_TYPE_UINT16     0x20
#define TL_DATA_TYPE_INT16      0x21
#define TL_DATA_TYPE_UINT24     0x30
#define TL_DATA_TYPE_INT24      0x31
#define TL_DATA_TYPE_UINT32     0x40
#define TL_DATA_TYPE_INT32      0x41
#define TL_DATA_TYPE_UINT64     0x80
#define TL_DATA_TYPE_INT64      0x81
#define TL_DATA_TYPE_FLOAT32    0x42
#define TL_DATA_TYPE_FLOAT64    0x82

static inline size_t tl_data_type_size(unsigned type);

struct tl_data_stream_desc_header {
  // Stream ID described by these parameters
  uint8_t stream_id;

  // Fundamental data type for the data (every channel in a sample has the
  // same type)
  uint8_t type;

  // Number of channels in a sample.
  uint8_t channels;

  // Arbitrary ID that should change when an acquisition is restarted
  uint8_t restart_id;

  // Sampling period, in us
  uint32_t period_numerator;
  uint32_t period_denominator;

  // High dword of internal 64 bit sample counter
  uint32_t samples_msd;

  // Start timestamp, in ns (epoch depends on data stream)
  uint64_t start_timestamp;
} __attribute__((__packed__));
typedef struct tl_data_stream_desc_header tl_data_stream_desc_header;

#define TL_DATA_STREAM_MAX_NAME_LEN \
  (TL_PACKET_MAX_PAYLOAD_SIZE - sizeof(tl_data_stream_desc_header))

struct tl_data_stream_desc_packet {
  tl_packet_header hdr;
  tl_data_stream_desc_header desc;
  char name[TL_DATA_STREAM_MAX_NAME_LEN]; // not null terminated
};
typedef struct tl_data_stream_desc_packet tl_data_stream_desc_packet;

#define TL_DATA_STREAM_MAX_PAYLOAD_SIZE \
  (TL_PACKET_MAX_PAYLOAD_SIZE - sizeof(uint32_t))

struct tl_data_stream_packet {
  tl_packet_header hdr;
  uint32_t start_sample; // low 32 bit of sample counter
  uint8_t data[TL_DATA_STREAM_MAX_PAYLOAD_SIZE];
};
typedef struct tl_data_stream_packet tl_data_stream_packet;


static inline size_t tl_data_type_size(unsigned type)
{
  return (type >> 4) & 0xF;
}

#endif // TL_DATA_H
