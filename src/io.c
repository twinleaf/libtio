// Copyright: 2016-2018 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: MIT

#include <tio/packet.h>
#include <tio/io.h>
#include "io_internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

extern struct io_vtable tl_io_serial_vtable;
extern struct io_vtable tl_io_tcp_vtable;
extern struct io_vtable tl_io_udp_vtable;

static struct {
  const char *protocol;
  io_vtable *vtable;
} io_vtables[] = {
  {"serial", &tl_io_serial_vtable},
  {"tcp", &tl_io_tcp_vtable},
  {"udp", &tl_io_udp_vtable},
  {NULL, NULL}
};

void tlio_logf(tlio_logger *logger, int fd, const char *fmt, ...)
{
  if (!logger)
    return;
  va_list ap;
  va_start(ap, fmt);
  int len = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (len < 0) {
    logger(fd, "Error while formatting log message!");
  } else if (len > 0) {
    char buf[len+1];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    logger(fd, buf);
  }
}

static fd_overlay_t *overlay;
static size_t overlay_size;
static size_t overlay_count;
static size_t invalid_vtable;

static fd_overlay_t *get_overlay(int fd)
{
  if ((fd >= 0) && overlay && (overlay_size > (size_t)fd)) {
    fd_overlay_t *ret = &overlay[fd];
    if (ret->vtable_id < invalid_vtable)
      return ret;
  }
  errno = EBADF;
  return NULL;
}

static fd_overlay_t *alloc_overlay(int fd)
{
  if (fd < 0) {
    errno = EBADF;
    return NULL;
  }

  if (!overlay) {
    while (io_vtables[invalid_vtable].protocol != NULL)
      ++invalid_vtable;

    overlay_size = fd+1;
    overlay = (fd_overlay_t*) calloc(overlay_size, sizeof(fd_overlay_t));
    if (!overlay) {
      overlay_size = 0;
      errno = ENOMEM;
      return NULL;
    }
    for (size_t i = 0; i < overlay_size; i++)
      overlay[i].vtable_id = invalid_vtable;
  }

  // if we get here, overlay is non-null
  if (overlay_size <= (size_t)fd) {
    // must resize the overlay table
    size_t new_size = fd+1;
    overlay = (fd_overlay_t*) realloc(overlay,
                                      new_size * sizeof(fd_overlay_t));
    if (!overlay) {
      errno = ENOMEM;
      return NULL;
    }
    memset(&overlay[overlay_size], 0,
           (new_size-overlay_size) * sizeof(fd_overlay_t));
    for (; overlay_size < new_size; overlay_size++)
      overlay[overlay_size].vtable_id = invalid_vtable;
  }

  // if we get here, overlay is always big enough. Make sure we are not
  // allocating for a descriptor that was already allocated for
  fd_overlay_t *ret = &overlay[fd];
  if (ret->vtable_id == invalid_vtable) {
    overlay_count++;
    return ret;
  }

  if (overlay_count == 0) {
    free(overlay);
    overlay = NULL;
    overlay_size = 0;
  }

  errno = EBADF;
  return NULL;
}

static int release_overlay(int fd)
{
  fd_overlay_t *fdo = get_overlay(fd);
  if (!fdo) {
    errno = EBADF;
    return -1;
  }

  memset(fdo, 0, sizeof(*fdo));
  fdo->vtable_id = invalid_vtable;
  --overlay_count;

  if (overlay_count == 0) {
    free(overlay);
    overlay = NULL;
    overlay_size = 0;
  }

  return 0;
}

int tlopen(const char *url, int flags, tlio_logger *logger)
{
  // In general, urls are of the form proto://location/routing,
  // but serial ports can optionally be given by the path of the
  // serial port. Here we cheat a little to keep it simple and
  // force the path to be of the form /dev/port_file[:speed]/routing.
  // That won't work for character devices in arbitrary places,
  // in which case this needs to be made a little more sophisticated.
  const char *proto_name = "serial";
  size_t proto_len = 6;
  const char *location_start = url + 5;

  if (url[0] == '/') {
    // Special syntax for serial communication
    if (strncmp(url, "/dev/", 5) != 0) {
      errno = EINVAL;
      return -1;
    }
    // else the default values above are initialized correctly
  } else {
    // Regular URL
    for (proto_len = 0; url[proto_len] != ':'; ++proto_len) {
      if (url[proto_len] == '\0') {
        // url ended without ':'
        errno = EINVAL;
        return -1;
      }
    }

    if ((url[proto_len + 1] != '/') || (url[proto_len + 2] != '/')) {
      errno = EINVAL;
      return -1;
    }

    proto_name = url;
    location_start = url + proto_len + 3;
  }

  // Find the end of the location.
  size_t location_len = 0; // location of '/' or '\0' at end of location_start
  while ((location_start[location_len] != '/') &&
         (location_start[location_len] != '\0'))
    ++location_len;

  // break out routing prefix, will look something like "/1/2/3/"
  const char *routing = NULL;
  if ((location_start[location_len] == '/') &&
      (location_start[location_len + 1] != '\0'))
    routing = location_start + location_len;

  uint8_t routing_prefix[TL_PACKET_MAX_ROUTING_SIZE];
  size_t routing_len = 0;
  if (routing) {
    ssize_t ret = tl_parse_routing(routing_prefix, routing);
    if (ret < 0) {
      errno = EINVAL;
      return -1;
    }
    routing_len = ret;
  }

  // break out location. will require new buffer
  char location[location_len+1];
  memcpy(location, location_start, location_len);
  location[location_len] = '\0';

  // Open the descriptor according to the protocol
  flags &= O_NONBLOCK | O_CLOEXEC;

  for (size_t id = 0; io_vtables[id].protocol != NULL; id++) {
    size_t len = strlen(io_vtables[id].protocol);
    if ((len == proto_len) &&
        (memcmp(proto_name, io_vtables[id].protocol, len) == 0)) {
      // we found the protocol
      io_vtable *vt = io_vtables[id].vtable;
      int fd = vt->io_open(location, flags, logger);
      if (fd < 0)  // an error occurred, leave errno to whatever it was set to
        return -1;
      fd_overlay_t *fdo = alloc_overlay(fd);
      if (!fdo) {
        close(fd);
        return -1;
      }
      fdo->vtable_id = id;
      fdo->logger = logger;
      if (vt->io_fdopen(fdo, fd) < 0) {
        release_overlay(fd);
        close(fd);
        return -1;
      }
      fdo->routing_size = routing_len;
      memcpy(fdo->routing, routing_prefix, routing_len);
      return fd;
    }
  }

  errno = EINVAL;
  return -1;
}

int tlfdopen(int fd, const char *protocol, const char *routing,
             tlio_logger *logger)
{
  uint8_t routing_prefix[TL_PACKET_MAX_ROUTING_SIZE];
  size_t routing_len = 0;
  if (routing) {
    ssize_t ret = tl_parse_routing(routing_prefix, routing);
    if (ret < 0) {
      errno = EINVAL;
      return -1;
    }
    routing_len = ret;
  }

  if (fd < 0) {
    errno = EBADF;
    return -1;
  }

  for (size_t id = 0; io_vtables[id].protocol != NULL; id++) {
    if (strcmp(protocol, io_vtables[id].protocol) == 0) {
      // we found the protocol
      io_vtable *vt = io_vtables[id].vtable;
      fd_overlay_t *fdo = alloc_overlay(fd);
      if (!fdo) {
        return -1;
      }
      fdo->vtable_id = id;
      fdo->logger = logger;
      if (vt->io_fdopen(fdo, fd) < 0) {
        release_overlay(fd);
        return -1;
      }
      fdo->routing_size = routing_len;
      memcpy(fdo->routing, routing_prefix, routing_len);
      return fd;
    }
  }

  errno = EINVAL;
  return -1;
}

int tlclose(int fd)
{
  fd_overlay_t *fdo = get_overlay(fd);
  if (!fdo) {
    errno = EINVAL;
    return -1;
  }
  io_vtable *vt = io_vtables[fdo->vtable_id].vtable;

  errno = 0;
  int closeme = vt->io_close(fdo, fd);

  release_overlay(fd);
  if (closeme >= 0)
    close(closeme);

  return errno ? -1 : 0;
}

int tlsend(int fd, const void *_packet)
{
  fd_overlay_t *fdo = get_overlay(fd);
  if (!fdo) {
    errno = EINVAL;
    return -1;
  }
  io_vtable *vt = io_vtables[fdo->vtable_id].vtable;

  if (fdo->write_buf) {
    if (vt->io_drain(fdo, fd) == -1)
      return -1;
    if (fdo->write_buf) {
      errno = ENOTEMPTY;
      return -1;
    }
  }

  const tl_packet_header *packet = (const tl_packet_header*) _packet;
  if (!packet)
    return 0;

  if (((tl_packet_routing_size(packet) + fdo->routing_size) >
       TL_PACKET_MAX_ROUTING_SIZE) ||
      (packet->payload_size > TL_PACKET_MAX_PAYLOAD_SIZE)) {
    errno = EBADMSG;
    return -1;
  }

  uint8_t prefix_tmp_buf[TL_PACKET_MAX_SIZE];

  if (fdo->routing_size) {
    // must append routing prefix to the end.
    size_t sz = tl_packet_total_size(packet);
    memcpy(prefix_tmp_buf, packet, sz);
    memcpy(prefix_tmp_buf + sz, fdo->routing, fdo->routing_size);
    packet = (const tl_packet_header*) prefix_tmp_buf;
    tl_packet_set_routing_size((tl_packet_header*)packet,
                               tl_packet_routing_size(packet) +
                               fdo->routing_size);
  }

  int ret = vt->io_send(fdo, fd, packet, tl_packet_total_size(packet));

  if (ret < 0)
    return -1;

  if (fdo->write_buf) {
    errno = EOVERFLOW;
    return -1;
  }

  return 0;
}

int tlrecv(int fd, void *packet, size_t bufsize)
{
  fd_overlay_t *fdo = get_overlay(fd);
  if (!fdo) {
    errno = EINVAL;
    return -1;
  }
  io_vtable *vt = io_vtables[fdo->vtable_id].vtable;

  for (;;) {
    int ret = vt->io_recv(fdo, fd, packet, bufsize);
    if (ret < 0)
      return -1;
    if (fdo->routing_size) {
      // verify that if we had a prefix this message belongs to the right
      // sensor subtree, otherwise skip this packet.
      tl_packet_header *hdr = (tl_packet_header*) packet;
      size_t routing_size = tl_packet_routing_size(hdr);
      if (routing_size < fdo->routing_size)
        continue;
      uint8_t *subtree = tl_packet_routing_data(hdr) +
        routing_size - fdo->routing_size;
      if (memcmp(subtree, fdo->routing, fdo->routing_size) != 0)
        continue;
      else
        tl_packet_set_routing_size(hdr, routing_size - fdo->routing_size);
    }
    return 0;
  }
}
