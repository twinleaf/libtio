// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

// Example program to interface to vm4

#include <tio/rpc.h>
#include <tio/io.h>
#include <tio/data.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

int main(int argc, char *argv[])
{
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <sensor URL> sampling_period\n", argv[0]);
    return 1;
  }

  int fd = tlopen(argv[1], 0, NULL);
  if (fd < 0) {
    fprintf(stderr, "Failed to open %s: %s\n", argv[1], strerror(errno));
    return 1;
  }

  tl_rpc_reply_packet rep;
  uint32_t period = atoi(argv[2]);
  tl_simple_rpc(fd, "period", 0, &period, sizeof(period), &rep, NULL);
  tl_simple_rpc(fd, "start", 0, NULL, 0, &rep, NULL);

  for (int i = 0; i < 100; i++) {
    tlrecv(fd, &rep, sizeof(rep));
    printf("%d %d\n", rep.hdr.type, rep.hdr.payload_size);
    if (rep.hdr.stream_id() == 0) {
      tl_data_stream_packet *data = (tl_data_stream_packet*) &rep;
      int32_t *samples = (int32_t*) data->data;
      printf("STREAM: %u   %d %d %d\n", data->start_sample, samples[0],
             samples[1], samples[2]);
    }
  }

  tl_simple_rpc(fd, "stop", 0, NULL, 0, &rep, NULL);

  tlclose(fd);

  return 0;
}
