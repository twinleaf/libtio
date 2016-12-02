// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include "serial_proto.h"
#include <stdlib.h>
#include <string.h>

static inline void checked_store(void *buf, size_t buf_size, size_t offset,
                                 uint8_t value)
{
  if (offset < buf_size)
    ((uint8_t*)buf)[offset] = value;
}

static inline size_t checked_slip_store(void *buf, size_t buf_size,
                                        size_t offset, uint8_t value)
{
  if (value == TL_SERIAL_SLIP_END) {
    checked_store(buf, buf_size, offset++, TL_SERIAL_SLIP_ESC);
    checked_store(buf, buf_size, offset++, TL_SERIAL_SLIP_ESC_END);
  } else {
    checked_store(buf, buf_size, offset++, value);
    if (value == TL_SERIAL_SLIP_ESC) {
      checked_store(buf, buf_size, offset++, TL_SERIAL_SLIP_ESC_ESC);
    }
  }
  return offset;
}

size_t tl_serial_serialize(const void *pkt, size_t pkt_size,
                           void *buf, size_t buf_size)
{
  uint32_t crc = tl_crc32(pkt, pkt_size);

  uint8_t *pbuf = (uint8_t*) pkt; // pointer to packet data as array of bytes
  size_t ssize = 0; // size of serialized packet

  for (size_t i = 0; i < pkt_size; i++)
    ssize = checked_slip_store(buf, buf_size, ssize, pbuf[i]);
  for (size_t i = 0; i < 4; i++)
    ssize = checked_slip_store(buf, buf_size, ssize, (crc >> (i*8)) & 0xFF);

  checked_store(buf, buf_size, ssize++, TL_SERIAL_SLIP_END);

  return ssize;
}

struct tl_serial_deserializer {
  uint8_t *buf;
  size_t buf_size;
  size_t offset;
  int error;
  int esc;
};

// This is the first packet being parsed
#define TL_SERIAL_FIRST 0x800000

tl_serial_deserializer *tl_serial_create_deserializer(size_t max_packet_size)
{
  tl_serial_deserializer *ret =
    (tl_serial_deserializer*) malloc(sizeof(tl_serial_deserializer));
  if (!ret)
    return NULL;

  ret->buf_size = max_packet_size + TL_CRC32_SIZE;
  ret->buf = (uint8_t*) malloc(ret->buf_size);
  if (!ret->buf) {
    free(ret);
    return NULL;
  }

  ret->offset = 0;
  ret->error = TL_SERIAL_FIRST;
  ret->esc = 0;

  return ret;
}

void tl_serial_destroy_deserializer(tl_serial_deserializer *des)
{
  if (des) {
    free(des->buf);
    des->buf = NULL; // unneeded, but make it segfault if reused
    free(des);
  }
}

tl_serial_deserializer_ret tl_serial_deserialize(tl_serial_deserializer *des,
                                                 const uint8_t **start_ptr,
                                                 const uint8_t *end)
{
  tl_serial_deserializer_ret ret;
  // will set valid = 0.could do before returning, but on some compilers
  // it causes warnings for using uninitialized values.
  memset(&ret, 0, sizeof(ret));

  while (*start_ptr < end) {
    uint8_t c = *((*start_ptr)++);

    if (c == TL_SERIAL_SLIP_END) {
      // end of packet delimiter.
      ret.valid = 1;
      ret.error = des->error & ~TL_SERIAL_FIRST;
      ret.data = des->buf;
      ret.size = des->offset;

      if (des->esc)
        ret.error |= TL_SERIAL_ERROR_DANGLING_ESC;

      des->offset = 0;
      des->error = 0;
      des->esc = 0;

      if (ret.size < TL_CRC32_SIZE)
        ret.error |= TL_SERIAL_ERROR_SHORT;
      else {
        uint32_t data_crc = tl_crc32(ret.data, ret.size - TL_CRC32_SIZE);
        uint32_t pkt_crc = *(uint32_t*)&ret.data[ret.size - TL_CRC32_SIZE];
        if (data_crc != pkt_crc)
          ret.error |= TL_SERIAL_ERROR_CRC;

        if (!ret.error)
          ret.size -= TL_CRC32_SIZE;
        return ret;
      }
    }

    if (!des->esc && (c == TL_SERIAL_SLIP_ESC)) {
      des->esc = 1;
      continue;
    }

    if (des->esc) {
      // in escape mode
      if (c == TL_SERIAL_SLIP_ESC_END)
        c = TL_SERIAL_SLIP_END;
      else if (c == TL_SERIAL_SLIP_ESC_ESC)
        c = TL_SERIAL_SLIP_ESC;
      else {
        // don't translate but set error bit
        des->error |= TL_SERIAL_ERROR_ESC_CODE;
      }
      des->esc = 0;
    }

    if (des->offset < des->buf_size) {
      // At least in linux, the FTDI driver some times dumps a bunch of zeroes
      // before the first data that is received. Not sure why, but since packet
      // type zero is invalid, this is a workaround.
      if (des->offset || c || !(des->error & TL_SERIAL_FIRST))
        des->buf[des->offset++] = c;
    } else {
      des->error |= TL_SERIAL_ERROR_TOOBIG;
    }
  }

  // if we got here, the input data is over before finishing a packet
  return ret;
}
