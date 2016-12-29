// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

// Small program that sends an RPC request and interprets the returned value.
// Example:
// rpc_req serial://ttyUSB0:115200/ period u32:100

#include <tio/rpc.h>
#include <tio/io.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>

int main(int argc, char *argv[])
{
  if ((argc < 3) || (argc > 4)) {
    fprintf(stderr, "Usage: %s <sensor URL> <rpc name> "
            "[arg type:value]\n", argv[0]);
    return 1;
  }

  size_t arg_size = 0;
  void *arg = NULL;
  uint8_t arg_buf[8];

  // parse rpc argument

  if (argc >= 4) {
    if ((strncmp(argv[3], "u8:", 2) == 0) ||
        (strncmp(argv[3], "u16:", 2) == 0) ||
        (strncmp(argv[3], "u32:", 2) == 0) ||
        (strncmp(argv[3], "u64:", 2) == 0)) {
      // unsigned integer
      char *end;
      unsigned long val = strtoul(argv[3] + ((argv[3][1] == '8') ? 3 : 4),
                                  &end, 0);
      if (*end) {
        fprintf(stderr, "argument parse error\n");
        return 1;
      }
      *(unsigned long*)arg_buf = val;
      arg = arg_buf;
      switch (argv[3][1]) {
       case '8': arg_size = 1; break;
       case '1': arg_size = 2; break;
       case '3': arg_size = 4; break;
       case '6': arg_size = 8; break;
      }
    } else if ((strncmp(argv[3], "i8:", 2) == 0) ||
               (strncmp(argv[3], "i16:", 2) == 0) ||
               (strncmp(argv[3], "i32:", 2) == 0) ||
               (strncmp(argv[3], "i64:", 2) == 0)) {
      // signed integer
      char *end;
      long val = strtol(argv[3] + ((argv[3][1] == '8') ? 3 : 4), &end, 0);
      if (*end) {
        fprintf(stderr, "argument parse error\n");
        return 1;
      }
      *(long*)arg_buf = val;
      arg = arg_buf;
      switch (argv[3][1]) {
       case '8': arg_size = 1; break;
       case '1': arg_size = 2; break;
       case '3': arg_size = 4; break;
       case '6': arg_size = 8; break;
      }
    } else if ((strncmp(argv[3], "f32:", 2) == 0) ||
               (strncmp(argv[3], "f64:", 2) == 0)) {
      // floating point
      char *end;
      double val = strtod(argv[3] + 4, &end);
      if (*end) {
        fprintf(stderr, "argument parse error\n");
        return 1;
      }
      arg = arg_buf;
      switch (argv[3][1]) {
       case '3':
        *(float*)arg_buf = val;
        arg_size = 4;
        break;
       case '6':
        *(double*)arg_buf = val;
        arg_size = 8;
        break;
      }
    } else {
      // string argument
      arg_size = strlen(argv[3]);
      if (strncmp(argv[3], "s:", 2) == 0) {
        arg_size -= 2;
        arg = argv[3] + 2;
      } else {
        arg = argv[3];
      }
    }
  }

  int fd = tlopen(argv[1], 0, NULL);
  if (fd < 0) {
    fprintf(stderr, "Failed to open %s: %s\n", argv[1], strerror(errno));
    return 1;
  }

  tl_rpc_reply_packet rep;
  int ret = tl_simple_rpc(fd, argv[2], 0, arg, arg_size, &rep, NULL);
  if (ret < 0)
    fprintf(stderr, "RPC failed: %s\n", strerror(errno));
  if (ret > 0)
    fprintf(stderr, "RPC failed: %s\n", tl_rpc_strerror(ret));
  if (ret != 0)
    return 1;

  tlclose(fd);

  size_t rep_size = tl_rpc_reply_payload_size(&rep);

  int print = 1;
  for(size_t i = 0; i < rep_size; i++) {
    printf("%02x ", rep.payload[i]);
    if ((i & 0xF) == 0xF)
      putchar('\n');
    if (!isprint(rep.payload[i]))
      print = 0;
  }
  if (rep_size & 0xF)
    putchar('\n');

  if (print) {
    putchar('"');
    for(size_t i = 0; i < rep_size; i++)
      putchar(rep.payload[i]);
    puts("\"");
  }

  if (rep_size == 1) {
    int8_t s = *(int8_t*)rep.payload;
    uint8_t u = *(uint8_t*)rep.payload;
    printf("u8: 0x%02"PRIx8" %"PRIu8"\ns8:%"PRId8"\n", u, u, s);
  } else  if (rep_size == 2) {
    int16_t s = *(int16_t*)rep.payload;
    uint16_t u = *(uint16_t*)rep.payload;
    printf("u16: 0x%04"PRIx16" %"PRIu16"\ns16:%"PRId16"\n", u, u, s);
  } else  if (rep_size == 4) {
    int32_t s = *(int32_t*)rep.payload;
    uint32_t u = *(uint32_t*)rep.payload;
    float f = *(float*)rep.payload;
    printf("u32: 0x%08"PRIx32" %"PRIu32"\ns32: %"PRId32"\nf32: %f\n",
           u, u, s, f);
  } else  if (rep_size == 8) {
    int64_t s = *(int64_t*)rep.payload;
    uint64_t u = *(uint64_t*)rep.payload;
    double f = *(double*)rep.payload;
    printf("u64: 0x%016"PRIx64" %"PRIu64"\ns64: %"PRId64"\nf64:%lf\n",
           u, u, s, f);
  }

  return 0;
}
