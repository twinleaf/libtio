// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: Proprietary

// Vtable for sensor I/O. Implementing I/O for a different protocol
// requires exporting a vtable for it (e.g see io_serial.c), and linking
// to it from io.c's vtable directory.

#ifndef TL_IO_VTABLE_H
#define TL_IO_VTABLE_H

#include <stddef.h>

// Structure associated with descriptors registered with the I/O API,
// which specifies a vtable and a protocol-dependent state.
struct fd_overlay_t {
  size_t vtable_id;
  void *state;
  // TODO: routing
};
typedef struct fd_overlay_t fd_overlay_t;

// This function opens a descriptor to the desired location and returns it.
// In case of failure, return -1 and set errno.
typedef int io_open_t(const char *location, int flags);

// Register an already opened descriptor with the I/O API. Return fd on
// success, -1 on failure. This function must allocate and initialize any
// protocol specific state in fdo->state.
typedef int io_fdopen_t(fd_overlay_t *fdo, int fd);

// Perform cleanup for the specified descriptor (any work required for
// clean disconnection, deallocation of state). Return fd to actually call
// close() on it, -1 if the descriptor does not need to be closed.
// In case of error, set errno != 0, but still use the same return values.
typedef int io_close_t(void *state, int fd);

// Receive a valid packet in packet_buffer. Return 0 on success, -1 on
// failure with errno
// = ENOMEM if the packet size exceeds the buffer size
// = EPROTO for protocol errors.
typedef int io_recv_t(void *state, int fd, void *packet_buffer,
                      size_t bufsize);

// Send a packet. The send must be atomic. Return 0 on success, -1 on failure.
typedef int io_send_t(void *state, int fd, const void *packet,
                      size_t pktsize);

struct io_vtable {
  io_open_t   *io_open;
  io_fdopen_t *io_fdopen;
  io_close_t  *io_close;
  io_recv_t   *io_recv;
  io_send_t   *io_send;
};
typedef struct io_vtable io_vtable;

#endif // TL_IO_VTABLE_H
