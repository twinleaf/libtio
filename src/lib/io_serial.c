// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include <twinleaf/packet.h>
#include "io_vtable.h"
#include "serial.h"

#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>

#if defined (__linux__)
#include <linux/serial.h>
#include <sys/ioctl.h>
#endif


#define DEFAULT_BITRATE 115200
#define MAX_FRACTIONAL_RATE_DEVIATION 0.02 // 2 percent
#define DESERIALIZER_BUF_SIZE TL_PACKET_MAX_SIZE
#define SERIAL_READ_BUF_SIZE 1024

struct serial_state {
  size_t tx_buf_size;

  uint8_t *buf;
  size_t buf_size;

  tl_serial_deserializer *des;
  const uint8_t *start;
  const uint8_t *end;
};
typedef struct serial_state serial_state;

static int io_serial_open(const char *location, int flags)
{
  size_t port_len = 0;
  uint32_t bitrate = DEFAULT_BITRATE;

  // break out location
  for (; location[port_len]; port_len++) {
    if (location[port_len] == ':') {
      // this means that we have the bitrate specified. otherwise the loop
      // will just terminate, and we'll keep the whole location as port and
      // the default bitrate
      char *endptr;
      long value = strtol(location + port_len + 1, &endptr, 10);
      if (*endptr || (value <= 0) || (value >= 0x7FFFFFFF)) {
        errno = EINVAL;
        return -1;
      }
      bitrate = value;
      break;
    }
  }

  char dev[5 + port_len + 1];
  memcpy(dev, "/dev/", 5);
  memcpy(dev+5, location, port_len);
  dev[5+port_len] = '\0';

  int fd = open(dev, O_RDWR | O_NOCTTY | O_SYNC | (flags & ~O_NONBLOCK));
  if (fd < 0)
    return -1;

  speed_t speed = B0;
#if defined (__linux__)
  // In Linux, speed_t is an enum, limited to certain values. If the speed
  // does not match one of the enums, it's necessary to use the serial API
  // directly. The API seems to be intelligent enough to convert a custom
  // speed close enough to a predefined mode, so simply always use the
  // serial API.
  struct serial_struct ss;
  if (ioctl(fd, TIOCGSERIAL, &ss) < 0)
    goto close_and_error;
  speed = B38400;
  ss.flags = (ss.flags & ~ASYNC_SPD_MASK) | ASYNC_SPD_CUST;
  ss.custom_divisor = (ss.baud_base + (bitrate / 2)) / bitrate;
  if (ss.custom_divisor < 1) {
    errno = EINVAL;
    goto close_and_error;
  }
  double actual_bitrate = ((double)ss.baud_base) / ss.custom_divisor;
  double fractional = (actual_bitrate - bitrate)/bitrate;
  if (fractional < 0.0) fractional = -fractional;
  if (fractional > MAX_FRACTIONAL_RATE_DEVIATION) {
    errno = EINVAL;
    goto close_and_error;
  }
  if (ioctl(fd, TIOCSSERIAL, &ss) < 0)
    goto close_and_error;
#elif defined(__FreeBSD__) || defined(__APPLE__)
  // In BSD, the speed is arbitrary and simple to configure
  speed = bitrate;
#else
#error Your environment is not supported
#endif

  struct termios tios;
  __builtin_memset(&tios, 0, sizeof(tios));
  tios.c_cflag = CS8|CREAD|CLOCAL;
  if (!(flags & O_NONBLOCK))
    tios.c_cc[VMIN] = 1;
  if (cfsetispeed(&tios, speed) != 0)
    goto close_and_error;
  if (cfsetospeed(&tios, speed) != 0)
    goto close_and_error;
  if (tcsetattr(fd, TCSANOW, &tios) != 0)
    goto close_and_error;

  // TODO: add exclusive access ??

  return fd;

close_and_error:
  {
    int saved_errno = errno; // just in case something's funky with close
    close(fd);
    errno = saved_errno;
  }
  return -1;
}

static int io_serial_fdopen(fd_overlay_t *fdo, int fd)
{
  serial_state *state = (serial_state*) malloc(sizeof(serial_state));

  if (state) {
    state->des = tl_serial_create_deserializer(DESERIALIZER_BUF_SIZE, 0);

    if (state->des) {
      state->buf_size = SERIAL_READ_BUF_SIZE;
      state->buf = (uint8_t*) malloc(state->buf_size);

      if (state->buf) {
        state->start = state->end = state->buf;
        fdo->state = state;
        return fd;
      } else {
        errno = ENOMEM;
      }

      tl_serial_destroy_deserializer(state->des);
    }

    free(state);
  } else {
    errno = ENOMEM;
  }

  return -1;
}

static int io_serial_close(void *_state, int fd)
{
  serial_state *state = (serial_state*) _state;
  free(state->buf);
  tl_serial_destroy_deserializer(state->des);
  free(state);

  return fd;
}

static int io_serial_recv(void *_state, int fd, void *packet_buffer,
                          size_t bufsize)
{
  serial_state *state = (serial_state*) _state;

  for (;;) {
    if (state->start == state->end) {
      // out of data in the buffer, refill buffer and process data
      errno = 0;
      int ret = read(fd, state->buf, state->buf_size);
      if (ret < 0)
        return -1;
      if (ret == 0) {
        // on linux this is the nonblocking read
        errno = EAGAIN;
        return -1;
      }
      state->start = state->buf;
      state->end = state->start + ret;
    }

    tl_serial_deserializer_ret ret =
      tl_serial_deserialize(state->des, &state->start,
                            state->end);

    if (ret.valid) {
      if (ret.error || (ret.size > TL_PACKET_MAX_SIZE)) {
        // error. TODO: debug options to write out error in more detail??
        errno = EPROTO;
        return -1;
      }
      // we've successfully deserialized a link-layer packet, but still
      // need to validate that it matches the header for size
      const tl_packet_header *hdr = (const tl_packet_header*) ret.data;
      if ((ret.size != tl_packet_total_size(hdr)) ||
          (hdr->routing_size > TL_PACKET_MAX_ROUTING_SIZE)) {
        errno = EPROTO;
        return -1;
      }

      if (ret.size > bufsize) {
        errno = ENOMEM;
        return -1;
      }

      memcpy(packet_buffer, ret.data, ret.size);
      return 0;
    }
  }
}

static int io_serial_send(void *_state, int fd, const void *packet,
                          size_t pktsize)
{
  (void) _state;

  size_t sbuf_size = TL_SERIAL_MAX_SIZE(pktsize);
  uint8_t sbuf[sbuf_size];
  size_t ser_size = tl_serial_serialize(packet, pktsize, sbuf, sbuf_size);

  // this should never happen!
  if (ser_size > sbuf_size) {
    errno = EPROTO;
    return -1;
  }

  // send the serialized packet to the device
  // TODO: ATOMIC /usr/include/linux/serial.h
  ssize_t ret = write(fd, sbuf, ser_size);
  if (ret < 0)
    return -1;

  if (((size_t) ret) != ser_size) {
    // partial writes will leave the descriptor in a bad state. TODO
    exit(1);
  }

  return 0;
}

io_vtable io_serial_vtable = {
  io_serial_open,
  io_serial_fdopen,
  io_serial_close,
  io_serial_recv,
  io_serial_send
};
