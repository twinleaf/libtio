// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include <tio/packet.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

static_assert(sizeof(tl_packet) == TL_PACKET_MAX_SIZE, "packet size mismatch");

int tl_parse_routing(uint8_t *routing, const char *routing_path)
{
  size_t n = 0;
  uint8_t reverse[TL_PACKET_MAX_ROUTING_SIZE];

  for (const char *s = routing_path; *s; s++) {
    if (*s == '/')
      continue;
    if (n >= sizeof(reverse))
      return -1;
    char *end;
    long k = strtol(s, &end, 10);
    s = end;
    if ((*s != '/') && (*s != '\0'))
      return -1;
    if ((k < 0) || (k > 255))
      return -1;
    reverse[n++] = k;
    if (*s == '\0')
      break;
  }

  for (size_t i = 0; i < n; i++)
    routing[i] = reverse[n - i - 1];

  return n;
}

int tl_format_routing(uint8_t *routing, size_t routing_size,
                      char *buf, size_t buf_size, int root_slash)
{
  if (routing_size > TL_PACKET_MAX_ROUTING_SIZE)
    return -1;
  int slash = !root_slash;
  while ((routing_size > 0) && (buf_size > 0)) {
    unsigned n = routing[--routing_size];
    int ret = snprintf(buf, buf_size, "/%u", n);
    if (ret < 0)
      return -1;
    if (buf_size < ((size_t)ret + 1))
      ret = buf_size - 1; // ret now is the number of non-null chars written
    buf += ret;
    buf_size -= ret;
    slash = 1;
  }
  if (!slash && (buf_size >= 2)) {
    *(buf++) = '/';
    buf_size--;
  }
  if (buf_size >= 1) {
    *buf = '\0';
  }
  return 0;
}
