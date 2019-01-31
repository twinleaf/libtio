// Copyright: 2018 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: MIT

#include <tio/packet.h>
#include "io_internal.h"

#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#ifndef MSG_NOSIGNAL
#ifdef __APPLE__
// Sadly, OS X does not implement POSIX.1-2008's MSG_NOSIGNAL at this time,
// so define it manually as zero and set SO_NOSIGPIPE in fdopen. Note:
// it's not present in linux, so there is no way to use this way for both.
#define MSG_NOSIGNAL 0
#define SET_NOSIGPIPE_SOCK_OPTION 1
#else
#error MSG_NOSIGNAL is missing
#endif
#endif

#define QUOTE(str) #str
#define EXPAND_AND_QUOTE(str) QUOTE(str)

static int io_udp_open(const char *location, int flags, tlio_logger *logger)
{
  ssize_t separator = -1;
  // break out name and service
  for (size_t i = 0; location[i]; i++) {
    if (location[i] == ':') {
      separator = i;
      break;
    }
  }

  char name_buf[((separator > 0) ? separator : 0) + 1];
  const char *name = location;
  const char *service = EXPAND_AND_QUOTE(TL_UDP_DEFAULT_PORT);
  if (separator >= 0) {
    // service port was given explicitly
    memcpy(name_buf, location, separator);
    name_buf[separator] = '\0';
    name = name_buf;
    service = location+separator+1;
  }

  struct addrinfo ai;
  memset(&ai, 0, sizeof(ai));
  ai.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
  ai.ai_socktype = SOCK_DGRAM;
  ai.ai_protocol = IPPROTO_UDP;
  struct addrinfo *result;
  {
    int ret = getaddrinfo(name, service, &ai, &result);
    if (ret != 0) {
      tlio_logf(logger, -1, "io_udp: Failed to resolve '%s': %s [%s]",
                location, gai_strerror(ret), strerror(errno));
      return -1;
    }
    if (!result) {
      tlio_logf(logger, -1, "io_udp: No results resolving '%s'", location);
      return -1;
    }
  }

  // To simplify error handling, copy relevant information on the stack and
  // free the result list memory.
  ai = *result;
  uint8_t addr_buf[ai.ai_addrlen];
  memcpy(addr_buf, ai.ai_addr, ai.ai_addrlen);
  ai.ai_addr = (struct sockaddr*) addr_buf;
  freeaddrinfo(result);

  int sock = socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol);
  if (!sock)
    return -1;

  // We could open the socket with these flags already set in linux, but not
  // on other systems, so do it the portable way.
  if (flags & O_NONBLOCK) {
    int sflags = fcntl(sock, F_GETFL);
    if (sflags == -1)
      return -1;
    if (fcntl(sock, F_SETFL, sflags | O_NONBLOCK) == -1)
      return -1;
  }

  if (flags & O_CLOEXEC) {
    if (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1)
      return -1;
  }

  // Allow broadcast.
  int one = 1;
  setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));

  // connect (i.e. set the remote address to the desired one and bind
  // to an arbitrary port)
  if (connect(sock, ai.ai_addr, ai.ai_addrlen) == -1) {
    if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
      close(sock);
      return -1;
    }
  }

  return sock;
}

static int io_udp_fdopen(fd_overlay_t *fdo, int fd)
{
#if SET_NOSIGPIPE_SOCK_OPTION
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
  fdo->state = NULL;
  return fd;
}

static int io_udp_close(fd_overlay_t *fdo, int fd)
{
  (void) fdo;
  return fd;
}

static int io_udp_recv(fd_overlay_t *fdo, int fd, void *packet_buffer,
                       size_t bufsize)
{
  (void) fdo;

  errno = 0;
  ssize_t ret = recv(fd, packet_buffer, bufsize, MSG_TRUNC);
  if (ret <= 0)
    return ret;

  tl_packet_header *hdr = (tl_packet_header*) packet_buffer;
  size_t psize = tl_packet_total_size(hdr);
  if ((psize > TL_PACKET_MAX_SIZE) ||
      (tl_packet_routing_size(hdr) > TL_PACKET_MAX_ROUTING_SIZE) ||
      (psize != (size_t)ret)) {
    errno = EPROTO;
    return -1;
  }

  // user buffer is too small for packet
  if ((size_t)ret > bufsize) {
    errno = ENOMEM;
    return -1;
  }

  return 0;
}

static int io_udp_send(fd_overlay_t *fdo, int fd, const void *packet,
                       size_t pktsize)
{
  (void) fdo;

  // There appears to be edge cases where you can get a SIGPIPE on a UDP
  // socket, so suppress that just in case.
  ssize_t ret = send(fd, packet, pktsize, MSG_NOSIGNAL);
  if (ret < 0)
    return -1;

  return 0;
}

static int io_udp_drain(fd_overlay_t *fdo, int fd)
{
  (void) fdo;
  (void) fd;
  return 0;
}

io_vtable tl_io_udp_vtable = {
  io_udp_open,
  io_udp_fdopen,
  io_udp_close,
  io_udp_recv,
  io_udp_send,
  io_udp_drain
};
