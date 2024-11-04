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
in tio/rpc.h as tl_rpc_request_packet.

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
in tio/rpc.h as tl_rpc_reply_packet.

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
in tio/rpc.h as tl_rpc_error_packet.

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

### RPC setting

Some device properties which can be read or changed via RPC will also
generate a packet with type TL_PTYPE_RPC_SETTING when they change, which
is defined in tio/rpc.h as tl_rpc_setting_packet. These are broadcast
to every client when using the proxy, and are used to keep concurrent
clients in the right state when one of them makes changes via RPCs.

```
 0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Name Length  |     Flags     |                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
  |                      [RPC/setting name]                       |
  =                    (`Name length` bytes)                      =
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  =                    [Setting value] (1+ bytes)                 =
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Receiving this packet indicates that the named setting has changed to
the value contained.

### Published data

Uses types TL_PTYPE_STREAMN(N), for 0 <= N < 128, and the packet is defined
in tio/data.h as tl_data_stream_packet.

If N is 0 this is a legacy stream, and the pyaload starts with the low
32 bits of the sample number, followed by the sample data.

```
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+} {-+
  | Sample #  |           Data                 |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+} {-+
```

The field is called `start_sample` for historical reasons, but there will be
only one sample per packet.

If  1 <= N < 128, the packet is as follows:

```
 0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Sample# L   |   Sample# M   |   Sample# H   |    Segment    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        [Sample data]                          |
  =                         (1+ bytes)                            =
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

In place of the low 32 bits of a 64 bit sample number, here we have a 24 bit
sample number (sample_start = L + (M<<8) + (H<<16)) plus a segment ID.

Here the sample number is a starting number, and the sample data can
potentially contain multiple samples (note: unlike for legacy streams, here
all samples have the same size).

Sample numbers here are not truncated and do not roll over: each stream will
send out data in "segments", which represent a contiguous acquisition with
all the same parameters (data rate, filtering, etc) for all samples. One of
the segment parameters is the start time, so if no other change occurs before
a rollover, data will automatically start to be sent out on the next segment,
bumping the start time and resetting the sample number.

### Stream Description

The meaning of the data in the streams is described either in packets of
type TL_PTYPE_METADATA (which are broadcast by default), or can be queried
via RPCs. These packets (tl_metadata_container in tio/data.h) are just
containers for specific metadata structures:

- tl_metadata_device: general information about the device
- tl_metadata_stream: static information about a stream
- tl_metadata_column: static information about a column (component) in a stream
- tl_metadata_segment: information about a stream segment

Here, only the segment metadata regularly changes. Stream and column metadata
for a given device can only changes as a result of a firmware upgrade, which
is also true for device-level metadata except for the session id (which will
reset to a random value every time the device boots).

A stream has a number of segments. It is possible to query their metadata
arbitrarily via RPC, however only the metadata for the current segment is
broadcast.

A metadata packet looks as follows:

```
 0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      |     Flags     |   Fixed Len   |               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
  |              [Fixed length fields for this type]              |
  =                      (`Fixed len` bytes)                      =
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  =              [Variable length fields] (0+ bytes)              =
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Here, the container specifies the type of the contained metadata:
- TL_METADATA_DEVICE
- TL_METADATA_STREAM
- TL_METADATA_CURRENT_SEGMENT
- TL_METADATA_COLUMN
and these flags:
- TL_METADATA_PERIODIC: automatically generated periodic broadcast.
- TL_METADATA_UPDATE: automatically generated update due to change, can only
  be set for TL_METADATA_CURRENT_SEGMENT.
- TL_METADATA_LAST: indicates this is the last metadata packet. For periodic
  broadcasts, it indicates the last packet before starting all over. For
  updates, it indicates the last packet in an update (updades with multiple
  packets can happen if e.g. two streams are linked and changing a setting
  changes both at the same time).

The rest is simply the specific metadata structure, which is also used in RPCs.
These all share the same high level structure: they start with a byte
indicating the length of the fixed-sized fields (including the length itself),
followed by the content of each variable length field. A variable length field
has a one byte size in the fixed part of the struc, which indicates how many
bytes the variable length data takes up, after the end of the fixed struct.

Specifying the total length of the fixed fields allows for backwards and
forwards compatibility: it allows older code to skip over newly added fields
(knowing where to look for for the start of varlen data), and newer code to
detect whether some new fields are not present in the metadata and should be
default-initialized.

For a contrived example, this

```
struct metadata_example {
  uint8_t fixed_len;
  uint8_t name_varlen;
  uint8_t units_varlen;
  uint8_t value;
};
```

for name = "field", units = "nT", and value = 123 would be serialized as

```
[4, 5, 2, 123, 'f', 'i', 'e', 'l', 'd', 'n', 'T']
```

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
