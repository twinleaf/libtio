// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include <tio/log.h>
#include <stdio.h>
#include <assert.h>

static_assert(sizeof(tl_log_packet) == TL_PACKET_MAX_SIZE,
              "tl_log_packet size mismatch");

int tl_log_packet_snprintf(tl_log_packet *lp, size_t size,
                           const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  int ret = vsnprintf(lp->message, size, fmt, ap);
  va_end(ap);

  return ret;
}

int tl_log_packet_vsnprintf(tl_log_packet *lp, size_t size,
                            const char *fmt, va_list ap)
{
  return vsnprintf(lp->message, size, fmt, ap);
}

