// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include <twinleaf/packet.h>
#include <twinleaf/io.h>
#include "io_vtable.h"

#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

extern struct io_vtable io_serial_vtable;
extern struct io_vtable io_tcp_vtable;

static struct {
  const char *protocol;
  io_vtable *vtable;
} io_vtables[] = {
  {"serial", &io_serial_vtable},
  {"tcp", &io_tcp_vtable},
  {NULL, NULL}
};

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
  // TODO: routing
  (void) routing;

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
      fd_overlay_t *fdo = alloc_overlay(fd);
      if (!fdo) {
        close(fd);
        return -1;
      }
      fdo->vtable_id = id;
      if (vt->io_fdopen(fdo, fd) < 0) {
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
  // TODO: routing
  (void) routing;

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
      if (vt->io_fdopen(fdo, fd) < 0) {
        release_overlay(fd);
        return -1;
      }
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
  fd_overlay_t *fdo = get_overlay(fd);
  if (!fdo) {
    errno = EINVAL;
    return -1;
  }
  io_vtable *vt = io_vtables[fdo->vtable_id].vtable;
  return vt->io_send(fdo->state, fd, packet, tl_packet_total_size(packet));
}

int tlrecv(int fd, void *packet, size_t bufsize)
{
  fd_overlay_t *fdo = get_overlay(fd);
  if (!fdo) {
    errno = EINVAL;
    return -1;
  }
  io_vtable *vt = io_vtables[fdo->vtable_id].vtable;
  return vt->io_recv(fdo->state, fd, packet, bufsize);
}
