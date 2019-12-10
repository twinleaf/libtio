// Copyright: 2016-2019 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: MIT

#include "serial_proto.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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

      if (des->offset == 0) {
        // ignore completely empty packet. This is written out as a precaution
        // at the beginning and when switching between text->binary protocol,
        // and can be safely ignored
        continue;
      }

      ret.valid = 1;
      ret.error = des->error & ~TL_SERIAL_FIRST;
      ret.data = des->buf;
      ret.size = des->offset;

      if (des->esc)
        ret.error |= TL_SERIAL_ERROR_DANGLING_ESC;

      des->offset = 0;
      des->error = 0;
      des->esc = 0;

      if (ret.size < TL_CRC32_SIZE) {
        ret.error |= TL_SERIAL_ERROR_SHORT;
      } else {
        uint32_t data_crc = tl_crc32(ret.data, ret.size - TL_CRC32_SIZE);
        uint32_t pkt_crc = *(uint32_t*)&ret.data[ret.size - TL_CRC32_SIZE];
        if (data_crc != pkt_crc)
          ret.error |= TL_SERIAL_ERROR_CRC;

        if (!ret.error)
          ret.size -= TL_CRC32_SIZE;
      }
      return ret;
    }

    if ((c == '\n') || (c == '\r')) {
      // Attempt to detect text mode packets. Valid packets cannot contain
      // \t, \n, \r, or printable ascii characters in the first three bytes
      // of the header (by protocol design), whereas text mode packets contain
      // zero or more printable characters or tabs followed by a \r\n.
      // Just in case some serial translation occurs, just one of \r or \n
      // will suffice for parsing.
      int valid_text = 1;
      for (size_t i = 0; i < des->offset; i++) {
        if (!isprint(des->buf[i]) && (des->buf[i] != '\t')) {
          valid_text = 0;
          break;
        }
      }
      if (valid_text) {
        if (des->offset == 0) // ignore empty line or \r\n
          continue;
        ret.error = (des->error | TL_SERIAL_ERROR_TEXT) & ~TL_SERIAL_FIRST;
        ret.size = des->offset;
        ret.valid = 1;
        ret.data = des->buf;

        des->offset = 0;
        des->error = 0;
        des->esc = 0; // just in case

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
      // restart the parser and signal that the packet is too long.
      // this helps avoiding an infinite loop edge condition, where if a
      // device restarts mid packet and starts up in text mode, the
      // heuristic expects to be in binary mode, but will loop inifinitely
      // waiting for a SLIP_END (which will never happen in text).
      ret.valid = 1;
      ret.error = (des->error | TL_SERIAL_ERROR_TOOBIG) & ~TL_SERIAL_FIRST;
      ret.data = des->buf;
      ret.size = des->offset;
      des->offset = 0;
      // preserve the fact that this is still the first packet,
      // and also maintain escaping state for the next character.
      des->error &= TL_SERIAL_FIRST;
      return ret;
    }
  }

  // if we got here, the input data is over before finishing a packet
  return ret;
}
