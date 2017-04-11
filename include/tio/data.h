// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#ifndef TL_DATA_H
#define TL_DATA_H

#include <tio/packet.h>

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

//////////////////////////////////////
// Data stream flags, timestamp types

// Desc sent out before first sample
#define TL_DATA_STREAM_FIRST        0x01
// This acquisition was completed (there will be no more data)
#define TL_DATA_STREAM_STOPPED      0x02


// Timestamp relative to the beginning of the data acquisition (always zero)
#define TL_DATA_STREAM_TSTAMP_ZERO      0
// Timestamp relative to device boot using device timebase
#define TL_DATA_STREAM_TSTAMP_DEV       1
// Timestamp is relative to a device upstream in the sensor tree
#define TL_DATA_STREAM_TSTAMP_UPSTREAM  2
// Timestamp is UNIX time (!= time since UNIX epoch. no leap seconds)
#define TL_DATA_STREAM_TSTAMP_UNIX      3

struct tl_data_stream_desc_header {
  // Version of the header packet (for backwards compatibility. now always 0)
  uint16_t version;

  // Stream ID described by these parameters
  uint16_t stream_id;

  // Start timestamp, in ns (epoch depends on flags)
  uint64_t start_timestamp;

  // Sample number of the last sample in the last packet sent,
  // or of the next packet if FIRST flag is set (in that case, it is
  // not guaranteed that it won't skip)
  uint64_t sample_counter;

  // Sampling period, in us
  uint32_t period_numerator;
  uint32_t period_denominator;

  // Flags first or stopped, defined above
  uint8_t flags;

  // Timestamp type, defined above
  uint8_t tstamp_type;

  // Arbitrary ID that changes when an acquisition is restarted for this stream
  uint16_t restart_id;

  // Size of a sample
  uint16_t sample_size;

  // Fundamental data type for the data (every channel in a sample has the
  // same type)
  uint8_t type;

  // Number of channels in a sample.
  uint8_t channels;
} __attribute__((__packed__));
typedef struct tl_data_stream_desc_header tl_data_stream_desc_header;

#define TL_DATA_STREAM_MAX_NAME_LEN \
  (TL_PACKET_MAX_PAYLOAD_SIZE - sizeof(tl_data_stream_desc_header))

struct tl_data_stream_desc_packet {
  tl_packet_header hdr;
  tl_data_stream_desc_header desc;
  char name[TL_DATA_STREAM_MAX_NAME_LEN]; // not null terminated
} __attribute__((__packed__));
typedef struct tl_data_stream_desc_packet tl_data_stream_desc_packet;

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
