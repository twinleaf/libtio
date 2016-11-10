// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include <twinleaf/packet.h>
#include <stdlib.h>
#include <assert.h>

static_assert(sizeof(tl_packet) == TL_PACKET_MAX_SIZE, "packet size mismatch");

int tl_parse_routing(uint8_t *routing_prefix, const char *routing_path)
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
    routing_prefix[i] = reverse[n - i - 1];

  return n;
}
