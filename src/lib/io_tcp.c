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
  ssize_t separator = -1;
  // break out name and service
  for (size_t i = 0; location[i]; i++) {
    if (location[i] == ':') {
      separator = i;
      break;
    }
  }

  char name[separator+1];
  memcpy(name, location, separator);
  name[separator] = '\0';
  const char *service = location+separator+1;

  struct addrinfo ai;
  memset(&ai, 0, sizeof(ai));
  ai.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
  ai.ai_socktype = SOCK_STREAM;
  ai.ai_protocol = IPPROTO_TCP;
  struct addrinfo *result;
  if (getaddrinfo(name, service, &ai, &result) != 0) {
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
