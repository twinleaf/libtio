// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#ifndef TL_DATA_H
#define TL_DATA_H

#include <twinleaf/packet.h>

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

  // Sampling period, in ns
  uint32_t period;

  // High dword of internal 64 bit sample counter
  uint32_t samples_msd;

  // Start timestamp, in ns from start of sensor
  uint64_t start_ts;

  // Abs start timestamp, unix time in ns
  uint64_t abs_start_ts;
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

#endif // TL_DATA_H
