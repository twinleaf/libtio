// Copyright: 2016-2017 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

// Structures, constants, and helpers for RPC related packets.

#ifndef TL_RPC_H
#define TL_RPC_H

#include <tio/packet.h>

struct tl_rpc_request_header {
  uint16_t id;
  uint16_t method_id;
} __attribute__((__packed__));
typedef struct tl_rpc_request_header tl_rpc_request_header;

#define TL_RPC_REQUEST_BY_NAME 0x8000
#define TL_RPC_REQUEST_NAMELEN_MASK 0x7FFF
#define TL_RPC_REQUEST_MAX_PAYLOAD_SIZE \
  (TL_PACKET_MAX_PAYLOAD_SIZE - sizeof(tl_rpc_request_header))

struct tl_rpc_request_packet {
  tl_packet_header      hdr;
  tl_rpc_request_header req;
  uint8_t payload[TL_RPC_REQUEST_MAX_PAYLOAD_SIZE];
  uint8_t routing[TL_PACKET_MAX_ROUTING_SIZE];

#ifdef __cplusplus
  template<typename T> inline T *payload_start();
  template<typename T> inline const T *payload_start() const;
  inline size_t payload_size() const;
  inline size_t method_size() const;
#endif
} __attribute__((__packed__));
typedef struct tl_rpc_request_packet tl_rpc_request_packet;

static inline void *tl_rpc_request_payload_start(tl_rpc_request_packet *req);
static inline
size_t tl_rpc_request_payload_size(const tl_rpc_request_packet *req);
static inline
size_t tl_rpc_request_method_size(const tl_rpc_request_packet *req);

struct tl_rpc_reply_header {
  uint16_t req_id;
} __attribute__((__packed__));
typedef struct tl_rpc_reply_header tl_rpc_reply_header;

#define TL_RPC_REPLY_MAX_PAYLOAD_SIZE \
  (TL_PACKET_MAX_PAYLOAD_SIZE - sizeof(tl_rpc_reply_header))

struct tl_rpc_reply_packet {
  tl_packet_header      hdr;
  tl_rpc_reply_header   rep;
  uint8_t payload[TL_RPC_REPLY_MAX_PAYLOAD_SIZE];
  uint8_t routing[TL_PACKET_MAX_ROUTING_SIZE];

#ifdef __cplusplus
  template<typename T> inline T *payload_start();
  template<typename T> inline const T *payload_start() const;
  inline size_t payload_size() const;
#endif
} __attribute__((__packed__));
typedef struct tl_rpc_reply_packet tl_rpc_reply_packet;

static inline tl_rpc_reply_packet *tl_rpc_make_reply(tl_rpc_request_packet *r);
static inline size_t tl_rpc_reply_payload_size(const tl_rpc_reply_packet *rep);

// RPC Errors
typedef uint16_t rpc_error_t;
#define TL_RPC_ERROR_NONE       0 // No error condition
#define TL_RPC_ERROR_UNDEFINED  1 // No error code for this error, check message
#define TL_RPC_ERROR_NOTFOUND   2 // Call to a nonexistent (or disabled) RPC
#define TL_RPC_ERROR_MALFORMED  3 // Malformed req packet
#define TL_RPC_ERROR_ARGS_SIZE  4 // Arguments have the wrong size
#define TL_RPC_ERROR_INVALID    5 // Arguments values invalid
#define TL_RPC_ERROR_READ_ONLY  6 // Attempted to assign a value to RO variable
#define TL_RPC_ERROR_WRITE_ONLY 7 // Attempted to read WO variable
#define TL_RPC_ERROR_TIMEOUT    8 // Internal timeout condition
#define TL_RPC_ERROR_BUSY       9 // Busy to perform this operation. try again
#define TL_RPC_ERROR_STATE     10 // Wrong state to perform this operation.
#define TL_RPC_ERROR_LOAD      11 // Error loading conf.
#define TL_RPC_ERROR_LOAD_RPC  12 // Error auto RPCs after load.
#define TL_RPC_ERROR_SAVE      13 // Error preparing conf to save.
#define TL_RPC_ERROR_SAVE_WR   14 // Error saving conf to eeprom
#define TL_RPC_ERROR_INTERNAL  15 // Firmware internal error.
#define TL_RPC_ERROR_NOBUFS    16 // No buffers available to complete operation
#define TL_RPC_ERROR_RANGE     17 // Value outside allowed range
#define TL_RPC_ERROR_USER      18 // Start value to define per-RPC error codes

struct tl_rpc_error_header {
  uint16_t req_id;
  rpc_error_t code;
} __attribute__((__packed__));
typedef struct tl_rpc_error_header tl_rpc_error_header;

#define TL_RPC_ERROR_MAX_PAYLOAD_SIZE \
  (TL_PACKET_MAX_PAYLOAD_SIZE - sizeof(tl_rpc_error_header))

struct tl_rpc_error_packet {
  tl_packet_header      hdr;
  tl_rpc_error_header   err;
  uint8_t payload[TL_RPC_ERROR_MAX_PAYLOAD_SIZE];
  uint8_t routing[TL_PACKET_MAX_ROUTING_SIZE];

#ifdef __cplusplus
  template<typename T> inline T *payload_start();
  template<typename T> inline const T *payload_start() const;
  inline size_t payload_size() const;
#endif
} __attribute__((__packed__));
typedef struct tl_rpc_error_packet tl_rpc_error_packet;

static inline tl_rpc_error_packet *tl_rpc_make_error(tl_rpc_request_packet *r,
                                                     rpc_error_t code);
static inline size_t tl_rpc_error_payload_size(const tl_rpc_error_packet *err);

#ifdef __cplusplus
extern "C" {
#endif

const char *tl_rpc_strerror(rpc_error_t err_code);

int tl_rpc_request_by_name(tl_rpc_request_packet *pkt, uint16_t req_id,
                           const char *method,
                           const void *arg, size_t arg_size);
int tl_rpc_request_by_id(tl_rpc_request_packet *pkt, uint16_t req_id,
                         uint16_t method, const void *arg, size_t arg_size);

typedef int tl_simple_rpc_other_packets_cb(const tl_packet_header *hdr);

int tl_simple_rpc(int fd, const char *method, uint16_t req_id,
                  const void *arg, size_t arg_size, tl_rpc_reply_packet *rep,
                  const uint8_t *routing, size_t routing_len,
                  tl_simple_rpc_other_packets_cb *cb);

int tl_simple_rpc_fixed_size(int fd, const char *method, uint16_t req_id,
                             const void *arg, size_t arg_size,
                             void *ret, size_t ret_size,
                             const uint8_t *routing, size_t routing_len,
                             tl_simple_rpc_other_packets_cb *cb);

#ifdef __cplusplus
}
#endif

//////////////////////////////////////
// Implementation of inline methods

static inline void *tl_rpc_request_payload_start(tl_rpc_request_packet *req)
{
  return &(req->payload[tl_rpc_request_method_size(req)]);
}

static inline
size_t tl_rpc_request_payload_size(const tl_rpc_request_packet *req)
{
  return (req->hdr.payload_size - sizeof(tl_rpc_request_header) -
          tl_rpc_request_method_size(req));
}

static inline
size_t tl_rpc_request_method_size(const tl_rpc_request_packet *req)
{
  return (req->req.method_id & TL_RPC_REQUEST_BY_NAME) ?
    (req->req.method_id & TL_RPC_REQUEST_NAMELEN_MASK) : 0;
}

static inline tl_rpc_reply_packet *tl_rpc_make_reply(tl_rpc_request_packet *r)
{
  tl_rpc_reply_packet *rep = (tl_rpc_reply_packet*) r;
  rep->hdr.type = TL_PTYPE_RPC_REP;
  rep->hdr.routing_size_and_ttl = 0;
  rep->hdr.payload_size = sizeof(tl_rpc_reply_header);
  return rep;
}

static inline size_t tl_rpc_reply_payload_size(const tl_rpc_reply_packet *rep)
{
  return rep->hdr.payload_size - sizeof(tl_rpc_reply_header);
}

static inline tl_rpc_error_packet *tl_rpc_make_error(tl_rpc_request_packet *r,
                                                     rpc_error_t code)
{
  tl_rpc_error_packet *err = (tl_rpc_error_packet*) r;
  err->hdr.type = TL_PTYPE_RPC_ERROR;
  err->hdr.routing_size_and_ttl = 0;
  err->hdr.payload_size = sizeof(tl_rpc_error_header);
  err->err.code = code;
  return err;
}

static inline size_t tl_rpc_error_payload_size(const tl_rpc_error_packet *err)
{
  return err->hdr.payload_size - sizeof(tl_rpc_error_header);
}

#ifdef __cplusplus

template<typename T> inline T *tl_rpc_request_packet::payload_start()
{
  return reinterpret_cast<T*>(&payload[method_size()]);
}

template<typename T> inline const T *
tl_rpc_request_packet::payload_start() const
{
  return reinterpret_cast<const T*>(&payload[method_size()]);
}

inline size_t tl_rpc_request_packet::payload_size() const
{
  return hdr.payload_size - sizeof(tl_rpc_request_header) - method_size();
}

inline size_t tl_rpc_request_packet::method_size() const
{
  return (req.method_id & TL_RPC_REQUEST_BY_NAME) ?
    (req.method_id & TL_RPC_REQUEST_NAMELEN_MASK) : 0;
}

template<typename T> inline T *tl_rpc_reply_packet::payload_start()
{
  return reinterpret_cast<T*>(&payload[0]);
}

template<typename T> inline const T *tl_rpc_reply_packet::payload_start() const
{
  return reinterpret_cast<const T*>(&payload[0]);
}

inline size_t tl_rpc_reply_packet::payload_size() const
{
  return hdr.payload_size - sizeof(tl_rpc_reply_header);
}

template<typename T> inline T *tl_rpc_error_packet::payload_start()
{
  return reinterpret_cast<T*>(&payload[0]);
}

template<typename T> inline const T *tl_rpc_error_packet::payload_start() const
{
  return reinterpret_cast<const T*>(&payload[0]);
}

inline size_t tl_rpc_error_packet::payload_size() const
{
  return hdr.payload_size - sizeof(tl_rpc_error_header);
}

#endif

#endif // TL_RPC_H
