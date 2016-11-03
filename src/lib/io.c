// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include <twinleaf/io.h>
#include <twinleaf/packet.h>
#include "serial.h"

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct fd_overlay {
  size_t vtable_id;
  void *state;
  // TODO: routing
};
typedef struct fd_overlay fd_overlay;

typedef int io_open_t(const char *location, int flags);

typedef int io_fdopen_t(fd_overlay *fdo, int fd);

typedef int io_close_t(void *state, int fd);

typedef int io_recv_t(void *state, int fd, void *packet_buffer,
                      size_t bufsize);

typedef int io_send_t(void *state, int fd, const void *packet,
                      size_t pktsize);

struct io_vtable {
  io_open_t   *io_open;
  io_fdopen_t *io_fdopen;
  io_close_t  *io_close;
  io_recv_t   *io_recv;
  io_send_t   *io_send;
};
typedef struct io_vtable io_vtable;

struct serial_state {
  uint8_t *buf;
  size_t buf_size;

  tl_serial_deserializer *des;
  uint8_t *start;
  uint8_t *end;
};
typedef struct serial_state serial_state;

static int io_serial_open(const char *location, int flags)
{
  size_t port_len = 0;
  uint32_t bitrate = 115200;

  // break out location
  for (; location[port_len]; port_len++) {
    if (location[port_len] == ':') {
      // this means that we have the bitrate specified. otherwise the loop
      // will just terminate, and we'll keep the whole location as port and
      // the default bitrate
      char *endptr;
      long value = strtol(location + port_len + 1, &endptr, 10);
      if (*endptr || (value <= 0) || (value >= 0x7FFFFFFF)) {
        assert(0);
        // parse error
      }
      bitrate = value;
      break;
    }
  }

  char dev[5 + port_len + 1];
  memcpy(dev, "/dev/", 5);
  memcpy(dev+5, location, port_len);
  dev[5+port_len] = '\0';

  if (bitrate != 115200) {
    // TODO
    assert(0);
  }

  // TODO: add exclusive access, use serial api to
  // get arbitrary speed. store configuration to restore at the end??
  int fd = open(dev, O_RDWR | O_NOCTTY | O_SYNC | (flags & O_CLOEXEC));
  struct termios tios;
  __builtin_memset(&tios, 0, sizeof(tios));
  tios.c_cflag = CS8|CREAD|CLOCAL;
  if (!(flags & O_NONBLOCK))
    tios.c_cc[VMIN] = 1;
  if (cfsetispeed(&tios, B115200) != 0)
    return -1;
  if (cfsetospeed(&tios, B115200) != 0)
    return -1;
  if (tcsetattr(fd, TCSANOW, &tios) != 0)
    return -1;

  return fd;
}

static int io_serial_fdopen(fd_overlay *fdo, int fd)
{
  // TODO: handle failures
  serial_state *state = malloc(sizeof(serial_state));
  state->des = tl_serial_create_deserializer(1000, 0);
  state->buf = (uint8_t*) malloc(1024);
  state->buf_size = 1024;
  state->start = state->end = state->buf;

  fdo->state = state;

  return 0;
}

static int io_serial_close(void *_state, int fd)
{
  serial_state *state = (serial_state*) _state;
  free(state->buf);
  tl_serial_destroy_deserializer(state->des);
  free(state);

  return 0;
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
        // error. TODO: debug options to write out error in more detail
        errno = EBADMSG;
        return -1;
      }
      // we've successfully deserialized a link-layer packet, but still
      // need to validate that it matches the header for size
      const tl_packet_header *hdr = (const tl_packet_header*) ret.data;
      if (ret.size != tl_packet_total_size(hdr)) {
        errno = EBADMSG;
        return -1;
      }

      size_t copy_size = ret.size;
      if (ret.size < bufsize)
        copy_size = bufsize;

      memcpy(packet_buffer, ret.data, copy_size);
      return copy_size;
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
  assert(ser_size <= sbuf_size);

  // send the serialized packet to the device
  // TODO: ATOMIC /usr/include/linux/serial.h
  ssize_t ret = write(fd, sbuf, ser_size);
  if (ret < 0)
    return ret;

  if (((size_t) ret) != ser_size) {
    // partial writes will leave the descriptor in a bad state. TODO
    assert(0);
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

extern struct io_vtable io_serial_vtable;

static struct {
  const char *protocol;
  io_vtable *vtable;
} io_vtables[] = {
  {"serial", &io_serial_vtable},
  {NULL, NULL}
};

static fd_overlay *overlay;
static size_t overlay_size;
static size_t overlay_count;

// OVERLAY: TODO
static fd_overlay *get_overlay(int fd)
{
  return &overlay[fd];
}

static fd_overlay *alloc_overlay(int fd)
{
  if (!overlay)
    overlay = malloc(1000 * sizeof(fd_overlay));
  return &overlay[fd];
}

static void release_overlay(int fd)
{
}

int tlopen(const char *url, int flags)
{
  // parse protocol, location, and path
  size_t proto_delim = 0; // number of characters of proto, or offset of ':'
  size_t loc_delim = 0; // location of '/' at end of location
  for (; url[proto_delim] != ':'; ++proto_delim) {
    if (url[proto_delim] == '\0') {
      // url ended without ':'
      errno = EINVAL;
      return -1;
    }
  }

  if ((url[proto_delim + 1] != '/') || (url[proto_delim + 2] != '/')) {
    errno = EINVAL;
    return -1;
  }

  for (loc_delim = proto_delim + 3; (url[loc_delim] != '/') &&
         (url[loc_delim] != '/'); ++loc_delim) {
  }

  // break out routing prefix, will look something like "/1/2/3/"
  const char *routing = NULL;
  if ((url[loc_delim] == '/') && (url[loc_delim + 1] != '\0'))
    routing = url + loc_delim;

  // break out location. will require new buffer
  size_t location_len = loc_delim - proto_delim - 3;
  char location[location_len+1];
  memcpy(location, url + proto_delim + 3, location_len);
  location[location_len] = '\0';

  // Open the descriptor according to the protocol
  flags &= O_NONBLOCK | O_CLOEXEC;

  for (size_t id = 0; io_vtables[id].protocol != NULL; id++) {
    size_t len = strlen(io_vtables[id].protocol);
    if ((len == proto_delim) &&
        (memcmp(url, io_vtables[id].protocol, len) == 0)) {
      // we found the protocol
      io_vtable *vt = io_vtables[id].vtable;
      int fd = vt->io_open(location, flags);
      if (fd < 0)  // an error occurred, leave errno to whatever it was set to
        return -1;
      fd_overlay *fdo = alloc_overlay(fd);
      if (!fdo) {
        assert(0); //TODO
      }
      fdo->vtable_id = id;
      if (vt->io_fdopen(fdo, fd) != 0) {
        release_overlay(fd);
        close(fd);
        return -1;
      }
      return fd;
    }
  }

  errno = EINVAL;
  return -1;
}

int tlfdopen(int fd, const char *protocol, const char *routing)
{
  return 0;
}

int tlclose(int fd)
{
  fd_overlay *fdo = get_overlay(fd);
  if (!fdo) {
    errno = EINVAL;
    return -1;
  }
  io_vtable *vt = io_vtables[fdo->vtable_id].vtable;
  vt->io_close(fdo->state, fd); // TODO: error handling
  close(fd);
  return 0;
}

int tlsend(int fd, const void *_packet)
{
  tl_packet_header *packet = (tl_packet_header*) _packet;
  // TODO: validate packet size
//  if (pk > TL_PACKET_MAX_SIZE) {
//    errno = EBADMSG;
//    return -1;
//  }
  fd_overlay *fdo = get_overlay(fd);
  if (!fdo) {
    errno = EINVAL;
    return -1;
  }
  io_vtable *vt = io_vtables[fdo->vtable_id].vtable;
  return vt->io_send(fdo->state, fd, packet, tl_packet_total_size(packet));
}

int tlrecv(int fd, void *packet, size_t bufsize)
{
  fd_overlay *fdo = get_overlay(fd);
  if (!fdo) {
    errno = EINVAL;
    return -1;
  }
  io_vtable *vt = io_vtables[fdo->vtable_id].vtable;
  return vt->io_recv(fdo->state, fd, packet, bufsize);
}
