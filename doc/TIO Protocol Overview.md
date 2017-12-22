# Twinleaf I/O (TIO) Protocol

This document is intended to be an overview of the TIO protocol. At the moment, the libtio C library shall be the reference implementation.

## Overview

Communication with Twinleaf sensors and other devices occurs by exchanging
packets using the protocol outlined below.
Devices are connected topologically in a tree structure. Hubs are nodes of
the tree that support additional devices to be connected under them.
Let's use this topology as an example

```
  PROXY
    |
    +- TIM (0)
    |     |
    |     +- VMR (0)
    |     |
    |     +- [Nothing connected]
    |     |
    |     +- VMR (2)
    |
    +- VMR (1)
```

A user communicates directly only with the root of the sensor tree, but can
reach any device in the tree by routing a packet to a specific device.
Routing is specified as a path using numerical IDs to reach a particular node.
In the example above, these are all the devices and their routing paths:

Device  | Routing Path 
--------|--------------
PROXY   | /            
TIM     | /0/          
VMR     | /0/0/        
VMR     | /0/2/        
VMR     | /1/          

Any packet that needs to be sent to the second VMR connected to the TIM for
example, will need to be routed to /0/2/, and likewise any packet coming
from that sensor will have routing path set to /0/2.

A node can have at most 256 branches below, and the maximum depth of a device
is 8 levels below the root.

## Communication patterns

There are only a handful of ways in which communication with devices occurs.
In all cases, there is no direct communication between devices, only between
an endpoint talking to the root and devices on the tree. An endpoint will
send packets down the tree to a specific device, while devices will send
packets up the tree for the endpoint(s) to consume.

*Logging*: When a device needs to log an event, it will send a packet up
containing the message and some numerical data.

*RPC*: An endpoint initiates an RPC by sending a request packet down to a
specific device. The device will try to perform the desired opertaion and
send back up either a reply packet (if it succeeded) or an error packet
(if it failed). Requests have an arbitrary ID, which is returned in the
reply or error, to allow having multiple RPCs in flight and determine which
request resulted in a given response.

*Data*: Each device can send out up to 128 separate data streams. A packet
for a data stream identifies the stream and the sample number of the first
sample in the packet, and then just contains raw data. It is necessary to
know some static information about the stream to interpret this data
(like data type, channels, sampling period, etc), and that information is
sent out before the stream starts in a stream description packet.

## Packet format

### Header and routing

```
 0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      | Routing Size R|        Payload Length P       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                            Payload                            |
  =                           (P bytes)                           =
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                       Routing (R bytes)                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

A packet consists of a 4 byte header, followed by the payload, followed by
the routing information. The header gives the packet type, the size of the
payload, and the size of the routing data.

Payload can be anywhere between 0 and 500 bytes in length, while routing can
take up between 0 and 8 bytes.

Payload length, and any of the multi-byte quantities in the packets'
payloads are little endian, which is the native endianness of the STM32
microcontrollers and of x86-64.

NOTE: Neither Payload nor Routing are restricted to have size to be a
multiple of 4 (as the diagram above might suggest).

Routing contains the routing path in reverse order, where each branch is
selected by one byte. For example, to send a packet to VM4 /0/2/ above,
R will be 2, and routing will consist of two bytes, 0x02 0x00.

The reason why the path is reversed is due to how the routing works within
the device tree:

- when a device receives a packet from its parent node, it will look at R and
  - if R=0 process the packet
  - if R>0 remove the last byte of routing data, decrement R, and send that packet down the tree on the port specified by the removed byte.
- when a device receives a packet from one if its children, it will append the port to which that child is connected, and increment R before sending it to its parent.

Routing behavior is the same regardless of the packet type or payload, so
below only the payload section is described.

The types are:

Packet Type         | byte  
--------------------|----
TL_PTYPE_NONE       | 0
TL_PTYPE_INVALID    | 0
TL_PTYPE_LOG        | 1
TL_PTYPE_RPC_REQ    | 2
TL_PTYPE_RPC_REP    | 3
TL_PTYPE_RPC_ERROR  | 4
TL_PTYPE_STREAMDESC | 5
TL_PTYPE_USER       | 6
TL_PTYPE_STREAM0    | 128

### LogMessages

Log messages use type TL_PTYPE_LOG, and the packet is defined
in twinleaf/log.h as tl_log_packet.

```
 0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                             log.data                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  log.type     |         message (null terminated)             |
  +-+-+-+-+-+-+-+-+                                               |
  |                                                               |
  =                      (until end of payload)                   =
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

log.data is some arbitrary numerical data in 32 bit unsigned format.
log.type is one of the constants from log.h detailing what kind of message
is being sent out (debug, info, warning, error).

### RPC request

RPC requests use type TL_PTYPE_RPC_REQ (2), and the packet is defined
in twinleaf/rpc.h as tl_rpc_request_packet.

```
 0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Request ID           |        Method ID/Length M   |N|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        [Named Method]                         |
  =                 (M bytes if N, otherwise 0)                   =
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        [RPC Payload]                          |
  =                         (0+ bytes)                            =
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Request ID is a randomly assigned 2-byte value returned with the corresponding
reply (allowing for asynchronous RPCs).
Method ID/Length: 2 bytes
  - if the high bit N is not set, the field represents an ID for some methods that are identified by a number for fast lookup and smaller packets
  - if the high bit N is set, the number indicates the length of the method name, which will be used to look up the method. The name does not need to be null terminated. XXXX: Does it need to be padded to byte align?
RPC Payload (optional): Comes after the name, if any, or the method ID. This would generally be used to set a value. If blank, this would represent an action for action RPCs, or a read request.

### RPC reply

RPC replies use type TL_PTYPE_RPC_REP (3), and the packet is defined
in twinleaf/rpc.h as tl_rpc_reply_packet.

```
 0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Request ID           |                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
  |                        [Reply Payload]                        |
  =                         (0+ bytes)                            =
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Request ID matches the one from the request. Payload depends on the specific
RPC that was called. Receiving this packet implies the RPC was successful.

### RPC error

RPC requests use type TL_PTYPE_RPC_ERROR, and the packet is defined
in twinleaf/rpc.h as tl_rpc_error_packet.

```
 0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Request ID           |        Error code             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      [Error Payload]                          |
  =                         (0+ bytes)                            =
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Request ID matches the one from the request. Receving this packet means the
RPC failed. See error codes in rpc.h. Payload depends on the specific error,
and most of the time is either empty or a more detailed error string.

### Published data

*TODO: Describe streaming changes in v3.*

Uses types TL_PTYPE_STREAM(N), for 0 <= N < 128, and the packet is defined
in twinleaf/data.h as tl_data_stream_packet.

```
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+} {-+
  | Sample #  |           Data                 |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+} {-+
```

Sample #: This is the low 32 bit of the sample number of the first sample
in the packet (so the sample number wraps to zero after sample 2^32-1).
The particular data format of a sample is communicated via the stream
description packet. A data packet is guaranteed to contain an integer number
of samples, with sample numbers that are contiguous.

### Stream Description

Uses type TL_PTYPE_STREAMDESC, and the packet is defined
in twinleaf/data.h as tl_data_stream_desc_packet.

Payload consists of this struct (TODO: diagram):

```
struct tl_data_stream_desc_header {
  // Stream ID described by these parameters
  uint8_t stream_id;

  // Fundamental data type for the data (every channel in a sample has the
  // same type)
  uint8_t type;

  // Number of channels in a sample.
  uint8_t channels;

  // Arbitrary ID that should change when an acquisition is restarted
  uint8_t restart_id;

  // Start timestamp, in ns (epoch depends on flags)
  uint64_t start_timestamp;

  // Sample number of the first sample in the last packet sent,
  // or of the next packet if FIRST flag is set (in that case, it is
  // not guaranteed that it won't skip)
  uint64_t sample_counter;

  // Sampling period, in us, where 
  // period_seconds = 1e-6 * period_numerator / period_denominator
  uint32_t period_numerator;
  uint32_t period_denominator;

  // Flags and timestamp type
  uint8_t flags;
  uint8_t tstamp_type;
} __attribute__((__packed__));
```

followed by a textual name for the stream (not null terminated).


## Protocol specific encoding

Remember: all multibyte fields are serialized in little endian.
On a BE machine, byte order must be reversed.

When sending over TCP, the packets are sent exactly how they are laid out
in memory since the stream is reliable and the header has enough information
to deserialize the stream at packet boundaries.

When sending over serial, compute the CRC32 of the packet and append it to it,
then SLIP encode the whole thing, and send it on the wire.

```
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+} {-+-+-+-+-//-+-+-+-+-+-+
  |SLIP_END |    SLIP encoded packet           | CRC32    |SLIP_END |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+} {-+-+-+-+-//-+-+-+-+-+-+
```

SLIP ENCODING wraps packets on the serial line. SLIP is defined in RFC 1055. In summary, SLIP means that binary or ASCII data is sent raw over the wire in blocks seperated by SLIP_END bytes. When the SLIP_END byte occurs in the raw message, it is escaped using SLIP_ESC and SLIP_ESC_END; likewise for SLIP_ESC and SLIP_ESC_ESC. The process is reversed at the receiving end. The SLIP ASCII codes (in hex) are:

Control Code   | hex
---------------|-----
SLIP_END       | 0xC0
SLIP_ESC       | 0xDB
SLIP_ESC_END   | 0xDC
SLIP_ESC_ESC   | 0xDD

Preceeding an END byte just before every message is optional; zero-length messages should be ignored.

The CRC32 is calculated on the unencoded packet, and is itself SLIP encoded (could be 4-8 bytes).
