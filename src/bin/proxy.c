// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include <twinleaf/packet.h>

// TEMP: minimal implementation of RPC
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

int main(int argc, char *argv[])
{
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <sensor URL>\n", argv[0]);
    return 1;
  }

  int fd = tlopen(argv[1], /*O_NONBLOCK |*/ O_CLOEXEC);

  tl_rpc_request_packet req;
  tl_rpc_request_by_name(&req, 0, "mcu.desc", NULL, 0);
  tlsend(fd, &req);
  tl_packet_header *rep =(tl_packet_header*) &req;
  tlrecv(fd, rep, sizeof(req));

  printf("mcu.desc: ");
  for(size_t i = 6; i < tl_packet_total_size(rep); i++)
    putchar(((char*)rep)[i]);
  putchar('\n');

  tlclose(fd);

  return 0;
}
