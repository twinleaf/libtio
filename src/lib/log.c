// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include <twinleaf/log.h>
#include <assert.h>

static_assert(sizeof(tl_log_packet) == TL_PACKET_MAX_SIZE,
              "tl_log_packet size mismatch");
