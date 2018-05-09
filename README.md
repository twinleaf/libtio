# libtio

This library implements a communications protocol in python to work with [Twinleaf sensors](http://www.twinleaf.com) using [Twinleaf I/O (TIO)](https://github.com/twinleaf/libtio/blob/master/doc/TIO%20Protocol%20Overview.md) as the communications layer. Data from the sensors is received via PUB messages and sensor parameters may be changed using REQ/REP messages. 

The repository also contains a reference document for the [TIO Protocol](https://github.com/twinleaf/libtio/blob/master/doc/TIO%20Protocol%20Overview.md).

## Prerequisites

The library compiles with no dependencies on standard POSIX systems:

  - Linux
  - macOS
  - Windows subsystem for linux

## Programming

A sockets interface to the sensors is provided. Please review examples in [TIO Protocol](https://github.com/twinleaf/tio-tools) to understand its use.
