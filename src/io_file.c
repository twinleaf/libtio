// Copyright: 2020 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: MIT

#include <tio/packet.h>
#include "io_internal.h"

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int io_file_open(const char *location, int flags, tlio_logger *logger)
{
  flags &= O_CLOEXEC;
  int fd = open(location, O_RDONLY | flags);

  if (fd < 0) {
    tlio_logf(logger, -1, "io_file: Failed to open '%s' %s",
              location, strerror(errno));
    return -1;
  }

  return fd;
}

static int io_file_fdopen(fd_overlay_t *fdo, int fd)
{
  fdo->state = NULL;
  return fd;
}

static int io_file_close(fd_overlay_t *fdo, int fd)
{
  (void) fdo;
  return fd;
}

static int io_file_recv(fd_overlay_t *fdo, int fd, void *packet_buffer,
                        size_t bufsize)
{
  (void) fdo;

  // Note: this is the simplest way to fit into the framework, but not
  // the most efficient due to two syscalls per packet. So far the
  // files are small enough to not be much of a problem.

  tl_packet_header pkt;

  errno = 0;
  ssize_t ret = read(fd, &pkt, sizeof(tl_packet_header));
  if (ret <= 0)
    return -1;
  if ((size_t)ret < sizeof(tl_packet_header)) {
    errno = EPROTO;
    return -1;
  }

  size_t pktsz = tl_packet_total_size(&pkt);
  if (pktsz > TL_PACKET_MAX_SIZE) {
    errno = EPROTO;
    return -1;
  }

  if (bufsize < pktsz) {
    errno = ENOMEM;
    return -1;
  }

  uint8_t *databuf = (uint8_t*) packet_buffer;
  memcpy(databuf, &pkt, sizeof(tl_packet_header));

  errno = 0;
  ret = read(fd, databuf + sizeof(tl_packet_header),
             pktsz - sizeof(tl_packet_header));
  if (ret < 0)
    return ret;
  if ((size_t)ret < (pktsz - sizeof(tl_packet_header))) {
    errno = EPROTO;
    return -1;
  }

  return 0;
}

static int io_file_send(fd_overlay_t *fdo, int fd, const void *packet,
                        size_t pktsize)
{
  (void) packet;
  (void) pktsize;

  tlio_logf(fdo->logger, fd, "io_file: packet send ignored (read only)");

  return 0;
}

static int io_file_drain(fd_overlay_t *fdo, int fd)
{
  (void) fdo;
  (void) fd;
  return 0;
}

io_vtable tl_io_file_vtable = {
  io_file_open,
  io_file_fdopen,
  io_file_close,
  io_file_recv,
  io_file_send,
  io_file_drain
};
