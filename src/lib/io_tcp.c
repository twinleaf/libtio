// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include <twinleaf/packet.h>
#include "io_vtable.h"

#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

struct tcp_state {
  uint8_t rx_buf[TL_PACKET_MAX_SIZE];
  size_t in_buf;
};
typedef struct tcp_state tcp_state;

static int io_tcp_open(const char *location, int flags)
{
  struct addrinfo ai;
  memset(&ai, 0, sizeof(ai));
  ai.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
  ai.ai_socktype = SOCK_STREAM;
  ai.ai_protocol = IPPROTO_TCP;
  struct addrinfo *result;
  if (getaddrinfo(location, NULL, &ai, &result) != 0) {
    // TODO: write out error
    return -1;
  }
  if (!result)
    return -1;
  // TODO: deal with multiple resolutions??

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
  tcp_state *state = (tcp_state*) malloc(sizeof(tcp_state));
  if (!state) {
    errno = ENOMEM;
    return -1;
  }

  memset(state, 0, sizeof(*state));
  fdo->state = state;
  return fd;
}

static int io_tcp_close(void *_state, int fd)
{
  tcp_state *state = (tcp_state*) _state;
  free(state);

  return fd;
}

static int io_tcp_recv(void *_state, int fd, void *packet_buffer,
                       size_t bufsize)
{
  tcp_state *state = (tcp_state*) _state;

  while (state->in_buf < sizeof(tl_packet_header)) {
    // must read up a full packet header to know how much
    // data is in the packet
    ssize_t ret = read(fd, state->rx_buf + state->in_buf,
                       sizeof(tl_packet_header) - state->in_buf);

    if (ret <= 0)
      return ret;
    else
      state->in_buf += ret;
  }

  tl_packet_header *hdr = (tl_packet_header*) state->rx_buf;
  size_t psize = tl_packet_total_size(hdr);
  if ((psize > TL_PACKET_MAX_SIZE) ||
      (hdr->routing_size > TL_PACKET_MAX_ROUTING_SIZE)) {
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

static int io_tcp_send(void *_state, int fd, const void *packet,
                       size_t pktsize)
{
  (void) _state;

  // TODO: atomic
  ssize_t ret = write(fd, packet, pktsize);
  if (ret <= 0)
    return -1;

  if (ret != (ssize_t)pktsize) {
    // partial writes will leave the descriptor in a bad state. TODO
    exit(1);
  }

  return 0;
}

io_vtable io_tcp_vtable = {
  io_tcp_open,
  io_tcp_fdopen,
  io_tcp_close,
  io_tcp_recv,
  io_tcp_send
};
