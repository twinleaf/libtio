// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

// Example  of issuing an RPC request with no arguments, and printing the
// return value as a string.

// TEMP: minimal implementation of RPC. This will be in the library and
// done much better soon. look at main()

#include <twinleaf/packet.h>

struct tl_rpc_request_header {
  uint16_t id;
  uint16_t method_id;
} __attribute__((__packed__));
typedef struct tl_rpc_request_header tl_rpc_request_header;

#define TL_RPC_REQ_BY_NAME 0x8000
#define TL_RPC_REQ_MAX_PAYLOAD_SIZE \
  (TL_PACKET_MAX_PAYLOAD_SIZE - sizeof(tl_rpc_request_header))

struct tl_rpc_request_packet {
  tl_packet_header      hdr;
  tl_rpc_request_header req;
  uint8_t payload[TL_RPC_REQ_MAX_PAYLOAD_SIZE];
} __attribute__((__packed__));
typedef struct tl_rpc_request_packet tl_rpc_request_packet;

int tl_rpc_request_by_name(tl_rpc_request_packet *pkt, uint16_t req_id,
                           const char *method, void *arg, size_t arg_size);
int tl_rpc_request_by_id(tl_rpc_request_packet *pkt, uint16_t req_id,
                       unsigned int method, void *arg, size_t arg_size);

struct tl_rpc_reply_packet {
  tl_packet_header      hdr;
  uint16_t req_id;
  uint8_t payload[TL_PACKET_MAX_PAYLOAD_SIZE-sizeof(uint16_t)];
} __attribute__((__packed__));
typedef struct tl_rpc_reply_packet tl_rpc_reply_packet;

#include <errno.h>
#include <string.h>

int tl_rpc_request_by_name(tl_rpc_request_packet *pkt, uint16_t req_id,
                           const char *method, void *arg, size_t arg_size)
{
  size_t name_len = strlen(method);
  if ((name_len + arg_size) > TL_RPC_REQ_MAX_PAYLOAD_SIZE) {
    errno = E2BIG;
    return -1;
  }
  pkt->hdr.type = TL_PTYPE_RPC_REQ;
  pkt->hdr.routing_size = 0;
  pkt->hdr.payload_size = sizeof(tl_rpc_request_header) + name_len + arg_size;
  pkt->req.id = req_id;
  // TODO: flip meaning of bit in tl-chibi
  pkt->req.method_id = /*TL_RPC_REQ_BY_NAME |*/ name_len;
  memcpy(pkt->payload, method, name_len);
  memcpy(pkt->payload + name_len, arg, arg_size);

  return 0;
}


#include <fcntl.h>
#include <stdio.h>
#include <twinleaf/io.h>
#include <ctype.h>

int main(int argc, char *argv[])
{
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <sensor URL> <rpc name>\n", argv[0]);
    return 1;
  }

  int fd = tlopen(argv[1], /*O_NONBLOCK |*/ O_CLOEXEC);

  tl_rpc_request_packet req;
  tl_rpc_request_by_name(&req, 0, argv[2], NULL, 0);
  tlsend(fd, &req);
  tl_rpc_reply_packet rep;
  tlrecv(fd, &rep, sizeof(req));

  tlclose(fd);

  size_t rep_size = rep.hdr.payload_size - 2;

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

  if (rep_size == 2) {
    int16_t s = *(int16_t*)rep.payload;
    uint16_t u = *(uint16_t*)rep.payload;
    printf("0x%04hX %hu %hd\n", u, u, s);
  } else  if (rep_size == 4) {
    int32_t s = *(int32_t*)rep.payload;
    uint32_t u = *(uint32_t*)rep.payload;
    float f = *(float*)rep.payload;
    printf("0x%08X %u %d %f\n", u, u, s, f);
  } else  if (rep_size == 4) {
    int32_t s = *(int32_t*)rep.payload;
    uint32_t u = *(uint32_t*)rep.payload;
    float f = *(float*)rep.payload;
    printf("0x%08X %u %d %f\n", u, u, s, f);
  } else  if (rep_size == 8) {
    int64_t s = *(int64_t*)rep.payload;
    uint64_t u = *(uint64_t*)rep.payload;
    double f = *(double*)rep.payload;
    printf("0x%016lX %lu %ld %lf\n", u, u, s, f);
  }

  return 0;
}
