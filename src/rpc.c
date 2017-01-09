// Copyright: 2016-2017 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

#include <tio/rpc.h>
#include <tio/io.h>

#include <errno.h>
#include <string.h>


#include <assert.h>

#define TL_RPC_PACKET_VERIFY_SIZE(type)                         \
  static_assert(sizeof(type) == TL_PACKET_MAX_SIZE,             \
              #type " size mismatch")

TL_RPC_PACKET_VERIFY_SIZE(tl_rpc_request_packet);
TL_RPC_PACKET_VERIFY_SIZE(tl_rpc_reply_packet);
TL_RPC_PACKET_VERIFY_SIZE(tl_rpc_error_packet);


const char *tl_rpc_strerror(rpc_error_t err_code)
{
  switch (err_code) {
   case TL_RPC_ERROR_NONE:
    return "No error";
   case TL_RPC_ERROR_UNDEFINED:
    return "Generic error";
   case TL_RPC_ERROR_NOTFOUND:
    return "Method not found";
   case TL_RPC_ERROR_MALFORMED:
    return "Malformed request";
   case TL_RPC_ERROR_ARGS_SIZE:
    return "Arguments wrong size";
   case TL_RPC_ERROR_INVALID:
    return "Invalid arguments";
   case TL_RPC_ERROR_READ_ONLY:
    return "Attempted to assign read-only value";
   case TL_RPC_ERROR_WRITE_ONLY:
    return "Attempted to read write-only value";
   case TL_RPC_ERROR_TIMEOUT:
    return "Internal timeout";
   case TL_RPC_ERROR_BUSY:
    return "Unable to fulfill request at the time -- try again later.";
   case TL_RPC_ERROR_STATE:
    return "Device state incompatible with requested action";
   case TL_RPC_ERROR_LOAD:
    return "Error when reading configuration from EEPROM";
   case TL_RPC_ERROR_LOAD_RPC:
    return "Error applying configuration from EEPROM";
   case TL_RPC_ERROR_SAVE:
    return "Error when serializing persistent configuration";
   case TL_RPC_ERROR_SAVE_WR:
    return "Error when writing configuration to EEPROM";
   case TL_RPC_ERROR_INTERNAL:
    return "Internal firmware error";
   case TL_RPC_ERROR_NOBUFS:
    return "Unable to allocate buffers needed to perform operation";
   default:
    return "User defined error";
  }
}

int tl_rpc_request_by_name(tl_rpc_request_packet *pkt, uint16_t req_id,
                           const char *method,
                           const void *arg, size_t arg_size)
{
  size_t name_len = strlen(method);
  if ((name_len + arg_size) > TL_RPC_REQUEST_MAX_PAYLOAD_SIZE) {
    errno = E2BIG;
    return -1;
  }
  pkt->hdr.type = TL_PTYPE_RPC_REQ;
  pkt->hdr.routing_size = 0;
  pkt->hdr.payload_size = sizeof(tl_rpc_request_header) + name_len + arg_size;
  pkt->req.id = req_id;
  pkt->req.method_id = TL_RPC_REQUEST_BY_NAME | name_len;
  memcpy(pkt->payload, method, name_len);
  memcpy(pkt->payload + name_len, arg, arg_size);

  return 0;
}

int tl_rpc_request_by_id(tl_rpc_request_packet *pkt, uint16_t req_id,
                         uint16_t method, const void *arg, size_t arg_size)
{
  if (arg_size > TL_RPC_REQUEST_MAX_PAYLOAD_SIZE) {
    errno = E2BIG;
    return -1;
  }
  pkt->hdr.type = TL_PTYPE_RPC_REQ;
  pkt->hdr.routing_size = 0;
  pkt->hdr.payload_size = sizeof(tl_rpc_request_header) + arg_size;
  pkt->req.id = req_id;
  pkt->req.method_id = method;
  memcpy(pkt->payload, arg, arg_size);

  return 0;
}

int tl_simple_rpc(int fd, const char *method, uint16_t req_id,
                  const void *arg, size_t arg_size, tl_rpc_reply_packet *rep,
                  const uint8_t *routing, size_t routing_len,
                  tl_simple_rpc_other_packets_cb *cb)
{
  tl_rpc_request_packet req;

  tl_rpc_request_by_name(&req, req_id, method, arg, arg_size);
  memcpy(tl_packet_routing_data(&req.hdr), routing, routing_len);
  req.hdr.routing_size += routing_len;

  if (tlsend(fd, &req) != 0)
    return -1;
  for (;;) {
    if (tlrecv(fd, rep, sizeof(*rep)) != 0)
      return -1;
    if ((rep->hdr.type == TL_PTYPE_RPC_REP) && (rep->rep.req_id == req_id)) {
      // this is the reply we were waiting for
      return 0;
    }
    if (rep->hdr.type == TL_PTYPE_RPC_ERROR) {
      tl_rpc_error_packet *err = (tl_rpc_error_packet*) rep;
      if (err->err.req_id == req_id) {
        // there was an error with this callback
        // set errno to a sensible value
        switch (err->err.code) {
         case TL_RPC_ERROR_NOTFOUND:
          errno = ENOSYS;
          break;
         case TL_RPC_ERROR_MALFORMED:
          errno = EPROTO;
          break;
         case TL_RPC_ERROR_ARGS_SIZE:
         case TL_RPC_ERROR_INVALID:
          errno = EINVAL;
          break;
         case TL_RPC_ERROR_READ_ONLY:
         case TL_RPC_ERROR_WRITE_ONLY:
          errno = EPERM;
          break;
         case TL_RPC_ERROR_BUSY:
          errno = EAGAIN;
          break;
         case TL_RPC_ERROR_LOAD:
         case TL_RPC_ERROR_LOAD_RPC:
         case TL_RPC_ERROR_SAVE:
         case TL_RPC_ERROR_SAVE_WR:
          errno = EIO;
          break;
         case TL_RPC_ERROR_NOBUFS:
          errno = ENOBUFS;
          break;
         default:
          errno = ENOENT;
          break;
        }
        return err->err.code;
      }
    }
    if (cb) {
      if (cb(&rep->hdr) != 0)
        return -1;
    }
  }
}

int tl_simple_rpc_fixed_size(int fd, const char *method, uint16_t req_id,
                             const void *arg, size_t arg_size,
                             void *ret, size_t ret_size,
                             const uint8_t *routing, size_t routing_len,
                             tl_simple_rpc_other_packets_cb *cb)
{
  tl_rpc_reply_packet rep;
  int rpcret = tl_simple_rpc(fd, method, req_id, arg, arg_size, &rep,
                             routing, routing_len, cb);
  if (rpcret != 0)
    return rpcret;
  if (tl_rpc_reply_payload_size(&rep) != ret_size) {
    errno = EINVAL;
    return TL_RPC_ERROR_UNDEFINED;
  }
  memcpy(ret, rep.payload, ret_size);
  return 0;
}

