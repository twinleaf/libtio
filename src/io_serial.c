// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: MIT

#include <tio/packet.h>
#include "io_internal.h"
#include "serial_proto.h"

#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>

#if defined (__linux__)
#include <linux/serial.h>
#endif


#define MAX_FRACTIONAL_RATE_DEVIATION 0.02 // 2 percent
#define DESERIALIZER_BUF_SIZE TL_PACKET_MAX_SIZE
#define SERIAL_READ_BUF_SIZE 1024

#define MAKE_TERMIOS_RATE_(n) B##n
#define MAKE_TERMIOS_RATE(n) MAKE_TERMIOS_RATE_(n)

struct serial_state {
  int parsed_first_packet;

  uint8_t *buf;
  size_t buf_size;

  tl_serial_deserializer *des;
  const uint8_t *start;
  const uint8_t *end;
};
typedef struct serial_state serial_state;

static int io_serial_open(const char *location, int flags, tlio_logger *logger)
{
  (void) logger;
  size_t port_len = 0;
  uint32_t bitrate = TL_SERIAL_DEFAULT_BITRATE;

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

  int fd = open(dev, O_RDWR | O_NOCTTY | flags | O_NONBLOCK);
  if (fd < 0)
    return -1;

  speed_t speed = B0;

#if defined (__linux__)
  // In Linux, speed_t is an enum, limited to certain values. If the speed
  // does not match one of the enums, it's necessary to use the serial API
  // directly. The API seems to be intelligent enough to convert a custom
  // speed close enough to a predefined mode, so simply always use the
  // serial API, except for the default bitrate. The reason to hardcode
  // the latter is that WSL on Windows does not support the serial
  // API at this time.
  if (bitrate == TL_SERIAL_DEFAULT_BITRATE) {
    speed = MAKE_TERMIOS_RATE(TL_SERIAL_DEFAULT_BITRATE);
  } else {
    struct serial_struct ss;
    if (ioctl(fd, TIOCGSERIAL, &ss) < 0) {
      tlio_logf(logger, fd, "io_serial: serial API failed. If on Windows, "
                "only default bitrate is supported.");
      goto close_and_error;
    }
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
  }
#elif defined(__FreeBSD__) || defined(__APPLE__)
  // In BSD, the speed is arbitrary and simple to configure
  speed = bitrate;
#else
#error Your environment is not supported
#endif

  struct termios tios;
  __builtin_memset(&tios, 0, sizeof(tios));
  tios.c_cflag = CS8|CREAD|CLOCAL;
  if (cfsetispeed(&tios, speed) != 0)
    goto close_and_error;
  if (cfsetospeed(&tios, speed) != 0)
    goto close_and_error;
  if (tcsetattr(fd, TCSANOW, &tios) != 0)
    goto close_and_error;

  // Set exclusive access, so that someone does not accidentally open
  // the same serial port twice. Does not work in WSL.
  if (ioctl(fd, TIOCEXCL, NULL) != 0) {
    tlio_logf(logger, fd, "io_serial: failed to set exclusive access to port. "
              "Continuing. Not suported in Windows.");
//    goto close_and_error;
  }

  // Write a terminator character just in case there was a partial packet
  // buffered on the other side.
  unsigned char terminator = TL_SERIAL_SLIP_END;
  write(fd, &terminator, 1);

  // Up to here, the terminal is in nonblocking mode. Clear up any pending
  // data that is probably junk (partial packets, missing escapes or
  // terminators). At least on linux, tcdrain does not actually do anything
  // about the data in the device's buffer, so we must read.
  {
    uint8_t drain_buf[128];
    while (read(fd, drain_buf, sizeof(drain_buf)) > 0) {
    }
  }

  // Now set the terminal to blocking mode if needed
  if (!(flags & O_NONBLOCK)) {
    tios.c_cc[VMIN] = 1;
    if (tcsetattr(fd, TCSANOW, &tios) != 0)
      goto close_and_error;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
      goto close_and_error;
    if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1)
      goto close_and_error;
  }

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
    state->parsed_first_packet = 0;
    state->des = tl_serial_create_deserializer(DESERIALIZER_BUF_SIZE);

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

static int io_serial_close(fd_overlay_t *fdo, int fd)
{
  serial_state *state = (serial_state*) fdo->state;
  free(state->buf);
  tl_serial_destroy_deserializer(state->des);
  free(state);

  return fd;
}

static inline char hexdigit(int n)
{
  n &= 0xF;
  return (n < 10) ? (n + '0') : (n - 10 + 'a');
}

static int io_serial_recv(fd_overlay_t *fdo, int fd, void *packet_buffer,
                          size_t bufsize)
{
  serial_state *state = (serial_state*) fdo->state;
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

    int first = !state->parsed_first_packet;
    state->parsed_first_packet = 1;

    if (ret.valid) {
      // Often time, the first packet will start mid-stream or have other
      // artifacts due to buffering conditions, so if there is an error
      // that is not purely in the SLIP encoding, ignore it and try to
      // get the next packet.
      if (ret.error && first &&
          ((ret.error & (TL_SERIAL_ERROR_DANGLING_ESC |
                         TL_SERIAL_ERROR_ESC_CODE)) == 0))
          continue;

      if (ret.error || (ret.size > TL_PACKET_MAX_SIZE)) {
        if (ret.error & TL_SERIAL_ERROR_SHORT)
          tlio_logf(fdo->logger, fd, "io_serial: short packet");
        if (ret.error & TL_SERIAL_ERROR_DANGLING_ESC)
          tlio_logf(fdo->logger, fd, "io_serial: dangling SLIP escape");
        if (ret.error & TL_SERIAL_ERROR_ESC_CODE)
          tlio_logf(fdo->logger, fd, "io_serial: invalid SLIP escape code");
        if (ret.error & TL_SERIAL_ERROR_CRC)
          tlio_logf(fdo->logger, fd, "io_serial: CRC failed");
        if ((ret.error & TL_SERIAL_ERROR_TOOBIG) ||
            (ret.size > TL_PACKET_MAX_SIZE)) {
          // We give a buffer big enough for the largest valid packet
          tlio_logf(fdo->logger, fd, "io_serial: packet size bigger than "
                    "allowed by protocol");
        }

        if (ret.data && ret.error && fdo->logger) {
          // To better identify what happened, do a hexdump of the partial
          // data returned by the deserializer.
          // for each character, 2 hex digits + space/newline
          char hexdump[ret.size*3+1];
          hexdump[0] = '\0';
          for (size_t i = 0; i < ret.size; i++) {
            hexdump[i*3+0] = hexdigit(ret.data[i] >> 4);
            hexdump[i*3+1] = hexdigit(ret.data[i] & 0x0F);
            hexdump[i*3+2] = (((i & 0xF) == 0xF) || (i == (ret.size - 1))) ?
              '\n' : ' ';
            hexdump[i*3+3] = '\0';
          }
          tlio_logf(fdo->logger, fd, "Error when receiving serial data:\n"
                    "BEGIN HEX DUMP\n%sEND HEX DUMP", hexdump);
        }
        errno = EPROTO;
        return -1;
      }
      // we've successfully deserialized a link-layer packet, but still
      // need to validate that it matches the header for size
      const tl_packet_header *hdr = (const tl_packet_header*) ret.data;
      if ((ret.size != tl_packet_total_size(hdr)) ||
          (tl_packet_routing_size(hdr) > TL_PACKET_MAX_ROUTING_SIZE)) {
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

static int io_serial_send(fd_overlay_t *fdo, int fd, const void *packet,
                          size_t pktsize)
{
  size_t sbuf_size = TL_SERIAL_MAX_SIZE(pktsize);
  uint8_t sbuf[sbuf_size];
  size_t ser_size = tl_serial_serialize(packet, pktsize, sbuf, sbuf_size);

  // this should never happen!
  if (ser_size > sbuf_size) {
    errno = EPROTO;
    return -1;
  }

  // send the serialized packet to the device
  ssize_t ret = write(fd, sbuf, ser_size);
  if (ret < 0)
    return -1;

  if (((size_t) ret) != ser_size) {
    // Partial write. We could just ignore and send back EAGAIN since SLIP
    // allows us to recover from partial writes, but the recovery comes
    // at the cost of the current and next packet both being not received
    // by the other side, while taking up all the wire time for the
    // partial write + next packet, which could be problematic on slower
    // rate links. Since we have the machinery to do this right, let's use it.
    size_t remaining = ser_size - ret;
    fdo->write_buf = malloc(remaining);
    if (!fdo->write_buf) {
      errno = ENOMEM;
      return -1;
    }
    memcpy(fdo->write_buf, sbuf + ret, remaining);
    fdo->to_send = remaining;
  }

  return 0;
}

static int io_serial_drain(fd_overlay_t *fdo, int fd)
{
  if (!fdo->write_buf)
    return 0;

  ssize_t ret = write(fd, fdo->write_buf, fdo->to_send);
  if (ret < 0) {
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
      ret = 0;
    else
      return -1;
  }

  if ((size_t)ret == fdo->to_send) {
    free(fdo->write_buf);
    fdo->write_buf = NULL;
    fdo->to_send = 0;
  } else if (ret > 0) {
    fdo->to_send -= ret;
    memmove(fdo->write_buf, ((uint8_t*)fdo->write_buf)+ret, fdo->to_send);
  }

  return 0;
}

io_vtable tl_io_serial_vtable = {
  io_serial_open,
  io_serial_fdopen,
  io_serial_close,
  io_serial_recv,
  io_serial_send,
  io_serial_drain
};
