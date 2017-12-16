// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

// Platform-independent packet-related structures and constants for native
// packets in TL firmwares. Packets are comprised of a header, followed
// by a payload, followed by optional routing information (used to dispatch
// messages to/from a network of sensors).
// The header conveys the packet type and the sizes of the two following
// sections.

#ifndef TL_PACKET_H
#define TL_PACKET_H

#include <stddef.h>
#include <stdint.h>

struct tl_packet_header {
  uint8_t type;
  uint8_t routing_size_and_ttl;
  uint16_t payload_size;

#ifdef __cplusplus
  inline size_t total_size() const;
  inline size_t routing_size() const;
  inline void set_routing_size(size_t s);
  inline unsigned ttl() const;
  inline uint8_t *payload_data();
  inline const uint8_t *payload_data() const;
  inline uint8_t *routing_data();
  inline const uint8_t *routing_data() const;
  inline int stream_id() const;
#endif

} __attribute__((__packed__));
typedef struct tl_packet_header tl_packet_header;

// Max size of a complete packet
#define TL_PACKET_MAX_SIZE 512

// Size at the end reserved for routing information
#define TL_PACKET_MAX_ROUTING_SIZE   8

// Max finite TTL value. Note: zero == immortal packet
#define TL_PACKET_MAX_TTL 15

// Maximum payload length (inferred)
#define TL_PACKET_MAX_PAYLOAD_SIZE \
  (TL_PACKET_MAX_SIZE - sizeof(tl_packet_header) - TL_PACKET_MAX_ROUTING_SIZE)

struct tl_packet {
  // Packet header
  tl_packet_header hdr;
  // Payload
  uint8_t payload[TL_PACKET_MAX_PAYLOAD_SIZE];
  // Reserved space for routing. Note: use tl_packet_routing_data() to get
  // a pointer to the routing data, since it will be at the end of the payload
  // and not at a fixed offset.
  uint8_t routing[TL_PACKET_MAX_ROUTING_SIZE];
};
typedef struct tl_packet tl_packet;

// Packet types
#define TL_PTYPE_INVALID     0
#define TL_PTYPE_LOG         1 // Log messages
#define TL_PTYPE_RPC_REQ     2 // RPC request
#define TL_PTYPE_RPC_REP     3 // RPC reply
#define TL_PTYPE_RPC_ERROR   4 // RPC error
#define TL_PTYPE_HEARTBEAT   5 // NOP/discover heartbeat
#define TL_PTYPE_TIMEBASE    6 // Update to a timebase's parameters
#define TL_PTYPE_PSTREAM     7 // Update to a pstream's parameters
#define TL_PTYPE_DSTREAM     8 // Update to a dstream's parameters
#define TL_PTYPE_USER       64

#define TL_PTYPE_STREAM0   128 // First data stream
#define TL_PTYPE_STREAM(N) (TL_PTYPE_STREAM0 + (N))

// Return the total packet size given a valid header.
static inline size_t tl_packet_total_size(const tl_packet_header *pkt);

// Return the number of hops in the routing section.
static inline size_t tl_packet_routing_size(const tl_packet_header *pkt);

// Return packet's TTL.
static inline size_t tl_packet_ttl(const tl_packet_header *pkt);

// Return a pointer to the start of the payload
static inline uint8_t *tl_packet_payload_data(tl_packet_header *pkt);

// Return a pointer to the start of the routing data
static inline uint8_t *tl_packet_routing_data(tl_packet_header *pkt);

// Set routing size.
static inline void tl_packet_set_routing_size(tl_packet_header *pkt,
                                              size_t size);

// Return the next hop for a packet, removing it from the routing data.
// Returns >= 0 on success, with the hop ID, otherwise -1 and pkt unchanged.
static inline int tl_packet_pop_hop(tl_packet_header *pkt);

// Append a hop to the routing data.
// Returns 0 on success, otherwise -1 and pkt unchanged.
static inline int tl_packet_push_hop(tl_packet_header *pkt, uint8_t hop);

// Set packet's TTL
static inline void tl_packet_set_ttl(tl_packet_header *pkt, unsigned ttl);

// Return the stream ID from the packet type, or -1 if the packet type
// is not that of a stream data packet
static inline int tl_packet_stream_id(const tl_packet_header *pkt);

// Parse a null terminated string of the form "/3/1/" into a binary routing
// encoding (which can be written directly to the routing data of a packet).
// Leading and trailing '/' optional. routing must point to at least
// TL_PACKET_MAX_ROUTING_SIZE bytes. Returns the number of hops that were
// parsed, or -1 in case of failure.
int tl_parse_routing(uint8_t *routing, const char *routing_path);

#define TL_ROUTING_FMT_BUF_SIZE (TL_PACKET_MAX_ROUTING_SIZE * 4 + 2)
int tl_format_routing(uint8_t *routing, size_t routing_size,
                      char *buf, size_t buf_size, int root_slash);

//////////////////////////////////////
// Implementation of inline methods

static inline size_t tl_packet_total_size(const tl_packet_header *pkt)
{
  return sizeof(*pkt) + pkt->payload_size + tl_packet_routing_size(pkt);
}

static inline size_t tl_packet_routing_size(const tl_packet_header *pkt)
{
  return (pkt->routing_size_and_ttl & 0x0F);
}

static inline size_t tl_packet_ttl(const tl_packet_header *pkt)
{
  return ((pkt->routing_size_and_ttl >> 4) & 0x0F);
}

static inline uint8_t *tl_packet_payload_data(tl_packet_header *pkt)
{
  return ((uint8_t*) pkt) + sizeof(*pkt);
}

static inline uint8_t *tl_packet_routing_data(tl_packet_header *pkt)
{
  return ((uint8_t*) pkt) + sizeof(*pkt) + pkt->payload_size;
}

static inline void tl_packet_set_routing_size(tl_packet_header *pkt,
                                              size_t size)
{
  pkt->routing_size_and_ttl =
    (pkt->routing_size_and_ttl & 0xF0) | (size & 0x0F);
}

static inline int tl_packet_pop_hop(tl_packet_header *pkt)
{
  size_t routing_size = tl_packet_routing_size(pkt);
  if (routing_size == 0)
    return -1;
  tl_packet_set_routing_size(pkt, --routing_size);
  return tl_packet_routing_data(pkt)[routing_size];
}

static inline int tl_packet_push_hop(tl_packet_header *pkt, uint8_t hop)
{
  size_t routing_size = tl_packet_routing_size(pkt);
  if (routing_size >= TL_PACKET_MAX_ROUTING_SIZE)
    return -1;
  tl_packet_routing_data(pkt)[routing_size++] = hop;
  tl_packet_set_routing_size(pkt, routing_size);
  return 0;
}

static inline void tl_packet_set_ttl(tl_packet_header *pkt, unsigned ttl)
{
  pkt->routing_size_and_ttl =
    tl_packet_routing_size(pkt) | ((ttl & 0xF) << 4);
}

static inline int tl_packet_stream_id(const tl_packet_header *pkt)
{
  return (pkt->type >= TL_PTYPE_STREAM0) ? (pkt->type - TL_PTYPE_STREAM0) : -1;
}

#ifdef __cplusplus

inline size_t tl_packet_header::total_size() const
{
  return tl_packet_total_size(this);
}

inline size_t tl_packet_header::routing_size() const
{
  return tl_packet_routing_size(this);
}

inline void tl_packet_header::set_routing_size(size_t s)
{
  tl_packet_set_routing_size(this, s);
}

inline unsigned tl_packet_header::ttl() const
{
  return tl_packet_ttl(this);
}

inline uint8_t *tl_packet_header::payload_data()
{
  return reinterpret_cast<uint8_t*>(this) + sizeof(*this);
}

inline const uint8_t *tl_packet_header::payload_data() const
{
  return reinterpret_cast<const uint8_t*>(this) + sizeof(*this);
}

inline uint8_t *tl_packet_header::routing_data()
{
  return reinterpret_cast<uint8_t*>(this) + sizeof(*this) + payload_size;
}

inline const uint8_t *tl_packet_header::routing_data() const
{
  return reinterpret_cast<const uint8_t*>(this) + sizeof(*this) + payload_size;
}

inline int tl_packet_header::stream_id() const
{
  return tl_packet_stream_id(this);
}

#endif

#endif // TL_PACKET_H
