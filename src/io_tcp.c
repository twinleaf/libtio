// Copyright: 2016-2021 Twinleaf LLC
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

struct tcp_state {
  uint8_t rx_buf[TL_PACKET_MAX_SIZE+8]; // allow for header+mask for websockets
  size_t in_buf;
};
typedef struct tcp_state tcp_state;

static int io_tcp_open(const char *location, int flags, tlio_logger *logger)
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
  const char *service = EXPAND_AND_QUOTE(TL_TCP_DEFAULT_PORT);
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
  ai.ai_socktype = SOCK_STREAM;
  ai.ai_protocol = IPPROTO_TCP;
  struct addrinfo *result;
  {
    int ret = getaddrinfo(name, service, &ai, &result);
    if (ret != 0) {
      tlio_logf(logger, -1, "io_tcp: Failed to resolve '%s': %s [%s]",
                location, gai_strerror(ret), strerror(errno));
      return -1;
    }
    if (!result) {
      tlio_logf(logger, -1, "io_tcp: No results resolving '%s'", location);
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

  // connect
  if (connect(sock, ai.ai_addr, ai.ai_addrlen) == -1) {
    if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
      close(sock);
      return -1;
    }
  }

  return sock;
}

static int io_tcp_fdopen(fd_overlay_t *fdo, int fd)
{
#if SET_NOSIGPIPE_SOCK_OPTION
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
  tcp_state *state = (tcp_state*) malloc(sizeof(tcp_state));
  if (!state) {
    errno = ENOMEM;
    return -1;
  }

  memset(state, 0, sizeof(*state));
  fdo->state = state;
  return fd;
}

static int io_tcp_close(fd_overlay_t *fdo, int fd)
{
  tcp_state *state = (tcp_state*) fdo->state;
  free(state);

  return fd;
}

static int io_tcp_recv(fd_overlay_t *fdo, int fd, void *packet_buffer,
                       size_t bufsize)
{
  tcp_state *state = (tcp_state*) fdo->state;

  while (state->in_buf < sizeof(tl_packet_header)) {
    // must read up a full packet header to know how much
    // data is in the packet
    errno = 0;
    ssize_t ret = read(fd, state->rx_buf + state->in_buf,
                       sizeof(tl_packet_header) - state->in_buf);

    if (ret <= 0)
      return -1;
    else
      state->in_buf += ret;
  }

  tl_packet_header *hdr = (tl_packet_header*) state->rx_buf;
  size_t psize = tl_packet_total_size(hdr);
  if ((psize > TL_PACKET_MAX_SIZE) ||
      (tl_packet_routing_size(hdr) > TL_PACKET_MAX_ROUTING_SIZE)) {
    state->in_buf = 0;
    errno = EPROTO;
    return -1;
  }

  while (state->in_buf < psize) {
    ssize_t ret = read(fd, state->rx_buf + state->in_buf,
                       psize - state->in_buf);

    if (ret <= 0)
      return ret;
    else
      state->in_buf += ret;
  }

  // If we got here, we got the full packet. Copy to the user

  state->in_buf = 0;

  if (psize > bufsize) {
    errno = ENOMEM;
    return -1;
  }

  memcpy(packet_buffer, state->rx_buf, psize);

  return 0;
}

static int io_tcp_send(fd_overlay_t *fdo, int fd, const void *packet,
                       size_t pktsize)
{
  ssize_t ret = send(fd, packet, pktsize, MSG_NOSIGNAL);
  if (ret < 0)
    return -1;

  if (ret != (ssize_t)pktsize) {
    size_t remaining = pktsize - ret;
    fdo->write_buf = malloc(remaining);
    if (!fdo->write_buf) {
      errno = ENOMEM;
      return -1;
    }
    memcpy(fdo->write_buf, ((const uint8_t*)packet) + ret, remaining);
    fdo->to_send = remaining;
  }

  return 0;
}

static int io_tcp_drain(fd_overlay_t *fdo, int fd)
{
  if (!fdo->write_buf)
    return 0;

  ssize_t ret = send(fd, fdo->write_buf, fdo->to_send, MSG_NOSIGNAL);
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

io_vtable tl_io_tcp_vtable = {
  io_tcp_open,
  io_tcp_fdopen,
  io_tcp_close,
  io_tcp_recv,
  io_tcp_send,
  io_tcp_drain
};

////////////////////////////////////////////////////////
// Minimal WebSocket server side implementation.

static int io_ws_recv(fd_overlay_t *fdo, int fd, void *packet_buffer,
                      size_t bufsize)
{
  tcp_state *state = (tcp_state*) fdo->state;

  while (state->in_buf < 4) {
    // Technically most frames have a 2 byte header, but it could be up to
    // 4, and there is always a tio packet following, so require 4 bytes
    // to proceed.
    errno = 0;
    ssize_t ret = read(fd, state->rx_buf + state->in_buf, 4 - state->in_buf);

    if (ret <= 0)
      return -1;
    else
      state->in_buf += ret;
  }

  // Basic checks
  size_t psize = state->rx_buf[1] & 0x7F; // preliminary payload size
  if ((state->rx_buf[0] != 0x82) || // must be binary, single frame
      !(state->rx_buf[1] & 0x80) || // must be masked
      (psize == 127) || // no support for 64 bit frames
      (psize > TL_PACKET_MAX_SIZE)) {
    state->in_buf = 0;
    errno = EPROTO;
    return -1;
  }

  // Determine header & payload size
  size_t hsize = 2;
  if (psize > 125) {
    hsize = 4;
    psize = state->rx_buf[3] | (state->rx_buf[2] << 8);
  }

  // need header + mask + payload
  while (state->in_buf < (hsize + 4 + psize)) {
    ssize_t ret = read(fd, state->rx_buf + state->in_buf,
                       hsize + 4 + psize - state->in_buf);

    if (ret <= 0)
      return ret;
    else
      state->in_buf += ret;
  }

  // Undo masking for header, and sanity check.
  uint8_t *mask = state->rx_buf + hsize;
  uint8_t *mpacket = mask + 4;

  union {
    uint8_t bytes[4];
    tl_packet_header hdr;
  } tmp;
  for (size_t i = 0; i < 4; i++)
    tmp.bytes[i] = mpacket[i] ^ mask[i];

  if ((psize != tl_packet_total_size(&tmp.hdr)) ||
      (tl_packet_routing_size(&tmp.hdr) > TL_PACKET_MAX_ROUTING_SIZE)) {
    state->in_buf = 0;
    errno = EPROTO;
    return -1;
  }

  //Copy to the user
  state->in_buf = 0;

  if (psize > bufsize) {
    errno = ENOMEM;
    return -1;
  }

  uint8_t *dest = (uint8_t*) packet_buffer;
  for (size_t i = 0; i < psize; i++)
    dest[i] = mpacket[i] ^ mask[i&3];

  return 0;
}

static int io_ws_send(fd_overlay_t *fdo, int fd, const void *packet,
                      size_t pktsize)
{
  uint8_t buf[pktsize+4];
  size_t frame_len = 2;
  buf[0] = 0x82; // binary frame, unmasked, final
  if (pktsize <= 125) {
    buf[1] = pktsize;
  } else {
    buf[1] = 126;
    buf[2] = pktsize >> 8;
    buf[3] = pktsize & 0xFF;
    frame_len = 4;
  }
  memcpy(buf + frame_len, packet, pktsize);
  frame_len += pktsize;

  return io_tcp_send(fdo, fd, buf, frame_len);
}

io_vtable tl_io_ws_vtable = {
  NULL,
  io_tcp_fdopen,
  io_tcp_close,
  io_ws_recv,
  io_ws_send,
  io_tcp_drain
};
