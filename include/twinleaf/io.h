// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

// API providing send/recv interface to communicate with sensors seamlessly
// over all the supported protocols.
// NOTE: this API is non-reentrant and must be explicitly serialized if there
// will be concurrent calls. Never call from a signal handler.

#ifndef TL_SENSOR_IO_H
#define TL_SENSOR_IO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Open a descriptor to communicate with a sensor. Flags are restricted to
// O_NONBLOCK and O_CLOEXEC, and sensors are always opened for read/write.
// Returns a valid descriptor (>=0) on success, otherwise -1 and errno is set.
// The descriptor returned is a valid system descriptor, and can be used for
// polling and other reasons (e.g. setting/clearing nonblocking I/O flag).
// However, reading and writing to the descriptor should be done via tlrecv
// and tlsend, since reading or writing arbitrary data can put the system
// in a bad state.
// The URL format is 'protocol://location/routing/routing/...', where location
// depends on the protocol and routing allows to connect to a sensor deep in
// the sensor tree as if it was the root (ignoring any input from outside that
// subtree, and implicitly prepending that routing data on every output packet).
//
// The 'serial' protocol communicates to a sensor connected via the serial
// port, and its location is 'port_name:bitrate', for example
//    serial://ttyUSB0:115200/1/
//
// The 'tcp' protocol communicates via TCP/IP and location is an address:port,
//    tcp://host.twinleaf.com:12345/
//
int tlopen(const char *url, int flags);

// Use a descriptor already opened for I/O with a twinleaf sensor. Note that
// you still need to specify a valid protocol as in tlopen(). Returns fd, or -1
// in case of error.
int tlfdopen(int fd, const char *protocol, const char *routing);

// Close a descriptor opened with tlopen/tlfdopen. Calls close() after
// libtwinleaf specific cleanup. Returns 0 on success, -1 on failure
// (in which case fd was not closed).
int tlclose(int fd);

// Receive a packet. Returns 0 if successful, -1 in case of error.
int tlrecv(int fd, void *packet_buffer, size_t bufsize);

// Send a packet. Returns 0 if successful, -1 in case of error.
int tlsend(int fd, const void *packet);

#ifdef __cplusplus
}
#endif

#endif // TL_SENSOR_IO_H
