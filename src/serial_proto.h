// Copyright: 2016-2019 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: MIT

// Functions to serialize/deserialize packets using the twinleaf native
// serial link-layer protocol.
// This code knows only about the framing and error detection via CRC32,
// and nothing about the higher level data transported (there is nothing
// that prevents using it to serialize arbitrary data of arbitrary length).
// This is a straightforward implementation which works well in most cases,
// although it should probably be customized if running on a severly limited
// embedded system to perform the encoding/decoding as data is
// leaving/entering the serial port avoiding to take up extra memory.

#ifndef TL_SERIAL_PROTO_H
#define TL_SERIAL_PROTO_H

#include "error_detection.h"

#ifdef __cplusplus
extern "C" {
#endif

// Constants used for slip encoding
#define TL_SERIAL_SLIP_END     0xC0
#define TL_SERIAL_SLIP_ESC     0xDB
#define TL_SERIAL_SLIP_ESC_END 0xDC
#define TL_SERIAL_SLIP_ESC_ESC 0xDD

// Serialize a packet in buf, up to buf_size bytes. returns total size
// of serialized packet. The returned value can exceed buf_size if the
// latter is too small, but no serialized data will be written past the
// end of the buffer.
size_t tl_serial_serialize(const void *pkt, size_t pkt_size,
                           void *buf, size_t buf_size);

// Macro to get a buffer size for serialization guaranteed to fit an
// input packet of the given size
#define TL_SERIAL_MAX_SIZE(packet_size) (2*((packet_size)+TL_CRC32_SIZE)+1)

// Deserialization is fundamentally different from serialization in that
// the input arrives in a stream and is not guaranteed to contain a full
// packet, so state must be maintained for decoding. A deserializer is an
// opaque structure that maintains the necessary state.
struct tl_serial_deserializer;
typedef struct tl_serial_deserializer tl_serial_deserializer;

// Create a deserializer for packets up to a given size.
tl_serial_deserializer *tl_serial_create_deserializer(size_t max_packet_size);

// Destroy a deserializer. Any pointer to data received from a deserializer
// becomes invalid.
void tl_serial_destroy_deserializer(tl_serial_deserializer *des);

// Deserialization errors

// Packet is empty or does not have a complete CRC32
#define TL_SERIAL_ERROR_SHORT           0x01
// Packet ended while in escape mode
#define TL_SERIAL_ERROR_DANGLING_ESC    0x02
// Invalid value after escape
#define TL_SERIAL_ERROR_ESC_CODE        0x04
// CRC32 mismatch
#define TL_SERIAL_ERROR_CRC             0x08
// The deserialized size exceed the configured size for this deserializer
#define TL_SERIAL_ERROR_TOOBIG          0x10
// The deserialized data appears to be text
#define TL_SERIAL_ERROR_TEXT            0x20


// Running the deserializer over some data returns a tl_serial_deserializer_ret
// structure. If valid is nonzero, then something is returned, otherwise
// not enough data was received to return a complete packet.
// If the returned data is valid, error == 0 means that the packet at 'data'
// of size 'size' is a packet to be processed.
// Otherwise, error is a mask of the error values above, and data/size still
// point to what there is about the failed packet, if needed for further
// debugging.
struct tl_serial_deserializer_ret {
  int valid;
  int error;
  const uint8_t *data;
  size_t size;
};
typedef struct tl_serial_deserializer_ret tl_serial_deserializer_ret;

// To deserialize a buffer of data, create a pointer to the beginning and
// end of the buffer (end = start + length), and call this function as long
// as start != end. Note that a pointer to start is passed, and this function
// updates it as it processes the data in the buffer.
tl_serial_deserializer_ret tl_serial_deserialize(tl_serial_deserializer *des,
                                                 const uint8_t **start_ptr,
                                                 const uint8_t *end);

#ifdef __cplusplus
}
#endif

#endif // TL_SERIAL_PROTO_H
