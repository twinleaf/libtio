// Copyright: 2016 Twinleaf LLC
// Author: gilberto@tersatech.com
// License: MIT

// Internal I/O declarations.
// Convenient logging method.
// Overlay struct, containing additional information that we need to associate
// with each tracked descriptor.
// Vtable for sensor I/O. Implementing I/O for a different protocol
// requires exporting a vtable for it (e.g see io_serial.c), and linking
// to it from io.c's vtable directory.

#ifndef TL_IO_INTERNAL_H
#define TL_IO_INTERNAL_H

#include <tio/io.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Write formatted message to a logger. Nop if logger == NULL
void tlio_logf(tlio_logger *logger, int fd, const char *fmt, ...)
  __attribute__((format(printf, 3, 4)));;

#ifdef __cplusplus
}
#endif

// Structure associated with descriptors registered with the I/O API,
// which specifies a vtable and a protocol-dependent state.
struct fd_overlay_t {
  size_t vtable_id;
  void *state;

  const char *url; // Url associated with this descriptor
  tlio_logger *logger; // Logger (optional)

  // Routing prefix that restricts the I/O to a specific
  // subtree of the sensor topology.
  size_t routing_size;
  uint8_t routing[TL_PACKET_MAX_ROUTING_SIZE];

  // When a packet write is incomplete, and either the underlying
  // communication method is such that an incomplete packet would mess up
  // framing, or that it would have serious performance implications
  // (e.g. slow serial link), the send function can place the leftover
  // portion of the packet in this buffer, and the system will take care
  // of sending it when possible.
  // Note: the reason to delegate it to the particular send function is that
  // in some cases one packet byte could be translated to multiple protocol
  // bytes in output, and the send could send only part of the multi-byte
  // translation.
  size_t to_send;
  void *write_buf;
};
typedef struct fd_overlay_t fd_overlay_t;

// This function opens a descriptor to the desired location and returns it.
// In case of failure, return -1 and set errno.
typedef int io_open_t(const char *location, int flags, tlio_logger *logger);

// Register an already opened descriptor with the I/O API. Return fd on
// success, -1 on failure. This function must allocate and initialize any
// protocol specific state in fdo->state.
typedef int io_fdopen_t(fd_overlay_t *fdo, int fd);

// Perform cleanup for the specified descriptor (any work required for
// clean disconnection, deallocation of state). Return fd to actually call
// close() on it, -1 if the descriptor does not need to be closed.
// In case of error, set errno != 0, but still use the same return values.
// Must clear out write_buf if non-null, after possibly attempting to
// send it without blocking.
typedef int io_close_t(fd_overlay_t *fdo, int fd);

// Receive a valid packet in packet_buffer. Return 0 on success, -1 on
// failure with errno
// = ENOMEM if the packet size exceeds the buffer size
// = EPROTO for protocol errors.
// = E???? errors from failed calls specific to the IO method.
typedef int io_recv_t(fd_overlay_t *fdo, int fd, void *packet_buffer,
                      size_t bufsize);

// Send a packet. Returns 0 in case of success, -1 in case of failure. If the
// failure is because fd is set up for nonblocking-IO, and a short write
// occurred, you should write the remaining data in fdo->write_buf and set
// to_send to the number of bytes left, returning 0. Note that this function
// will never be called when write_buf != NULL. If partial writes are not a
// problem, you may choose to just return an error on that condition.
typedef int io_send_t(fd_overlay_t *fdo, int fd, const void *packet,
                      size_t pktsize);

// Called when write_buf != NULL to write it out. Returns 0 on success,
// -1 on failure. If another short write occurs, the remaining data should
// be put in write_buf before returning 0, just like for the send method.
// If no write occurred because EAGAIN/EWOULDBLOCK, return 0 and leave
// the buffer unchanged.
typedef int io_drain_t(fd_overlay_t *fdo, int fd);

struct io_vtable {
  io_open_t   *io_open;
  io_fdopen_t *io_fdopen;
  io_close_t  *io_close;
  io_recv_t   *io_recv;
  io_send_t   *io_send;
  io_drain_t  *io_drain;
};
typedef struct io_vtable io_vtable;

#endif // TL_IO_INTERNAL_H
