// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include <twinleaf/io.h>
#include <twinleaf/packet.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>

int main(int argc, char *argv[])
{
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <TCP service port> <sensor URL>\n", argv[0]);
    return 1;
  }

  struct addrinfo ai;
  memset(&ai, 0, sizeof(ai));
  ai.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_PASSIVE;
  ai.ai_socktype = SOCK_STREAM;
  ai.ai_protocol = IPPROTO_TCP;
  struct addrinfo *result;
  if (getaddrinfo(NULL, argv[1], &ai, &result) != 0) {
    // TODO: write out error
    return 1;
  }
  size_t listen_sockets = 0;
  for (struct addrinfo *i = result; i; i = i->ai_next)
    listen_sockets++;

  if (!listen_sockets)
    return 1;

  printf("listen sockets: %zd\n", listen_sockets);
  int lsock[listen_sockets];
  struct pollfd poll_array[listen_sockets+2];

  {
    size_t s = 0;
    for (struct addrinfo *i = result; i; i = i->ai_next, s++) {
      lsock[s] = socket(i->ai_family, i->ai_socktype, i->ai_protocol);
      int on = 1;
      setsockopt(lsock[s], SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
      bind(lsock[s], i->ai_addr, i->ai_addrlen);
      listen(lsock[s], 32);
      if (fcntl(lsock[s], F_SETFL, fcntl(lsock[s], F_GETFL) | O_NONBLOCK) == -1)
        return -1;
      poll_array[s].fd = lsock[s];
      poll_array[s].events = POLLIN;
    }
  }

  freeaddrinfo(result);

  int fd = tlopen(argv[2], O_NONBLOCK | O_CLOEXEC);
  poll_array[listen_sockets].fd = fd;
  poll_array[listen_sockets].events = POLLIN;;

  uint8_t recv_buf[TL_PACKET_MAX_SIZE];

  for (;;) {
    int ret = poll(poll_array, listen_sockets+1, -1);
    if (ret < 1)
      return 1;
    size_t first = 0;
    for (; first <= listen_sockets + 1; first++) {
      if (poll_array[first].revents & POLLIN)
        break;
    }
    if (first > listen_sockets)
      return 1;

    if (first == listen_sockets) {
      // had data from the sensor, but nobody is connected. discard
      tlrecv(fd, recv_buf, sizeof(recv_buf));
      continue;
    }
    // otherwise we have an incoming connection
    int client = accept(poll_array[first].fd, NULL, NULL);
    if (client < 0)
      continue;

    fcntl(client, F_SETFL, fcntl(client, F_GETFL) | O_NONBLOCK);
    tlfdopen(client, "tcp", NULL);

    poll_array[listen_sockets+1].fd = client;
    poll_array[listen_sockets+1].events = POLLIN;

    // One client at a time main loop. Exchange messages between client and
    // sensor.
    for (;;) {
      poll(poll_array+listen_sockets, 2, -1);
      if (poll_array[listen_sockets].revents) {
        if (poll_array[listen_sockets].revents == POLLIN) {
          // message from the sensor
          if (tlrecv(fd, recv_buf, sizeof(recv_buf)) == 0)
            tlsend(client, recv_buf);
          else if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
            return 1;
        } else {
          // error. since it's on the sensor, might as well quit
          return 1;
        }
      }
      if (poll_array[listen_sockets+1].revents) {
        if (poll_array[listen_sockets+1].revents == POLLIN) {
          // message from the client
          if (tlrecv(client, recv_buf, sizeof(recv_buf)) == 0)
            tlsend(fd, recv_buf);
          else if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
            close(client);
            break;
          }
        } else {
          // connection was terminated, or an error happened. close the socket
          // and break out of the loop to accept the next one
          close(client);
          break;
        }
      }
    }
  }

  // actually as it is now, unreachable. must work out signal logic
  tlclose(fd);
  for (size_t i = 0; i < listen_sockets; i++)
    close(lsock[i]);

  return 0;
}
