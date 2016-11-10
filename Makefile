# Copyright: 2016 Twinleaf LLC
# Author: gilberto@tersatech.com
# License: Proprietary

CC = gcc
CCFLAGS = -g -Wall -Wextra -Iinclude/ -std=gnu11
CXXFLAGS = -g -Wall -Wextra -Iinclude/

.DEFAULT_GOAL = all
.SECONDARY:

LIB_HEADERS = $(wildcard include/twinleaf/*.h) $(wildcard src/lib/*.h)
LIB_SOURCES = $(wildcard src/lib/*.c)
LIB_OBJS = $(patsubst src/%.c,obj/%.o,$(LIB_SOURCES))

BIN_HEADERS = $(LIB_HEADERS) $(wildcard src/bin/*.h)
BIN_SOURCES = $(wildcard src/bin/*.c)
BIN_OBJS = $(patsubst src/%.c,obj/%.o,$(BIN_SOURCES))
BIN_BINS = $(patsubst src/%.c,%,$(BIN_SOURCES))

$(LIB_OBJS): | obj/lib

obj/lib obj/bin lib bin:
	@mkdir -p $@

obj/lib/%.o: src/lib/%.c $(LIB_HEADERS)
	@$(CC) $(CCFLAGS) -c $< -o $@

lib/libtwinleaf.a: $(LIB_OBJS) | lib
	@ar rcs $@ $(LIB_OBJS)

obj/bin/%.o: src/bin/%.c $(BIN_HEADERS) | obj/bin
	@$(CC) $(CCFLAGS) -c $< -o $@

bin/%: obj/bin/%.o lib/libtwinleaf.a | bin
	@$(CC) -Llib -o $@ $< -ltwinleaf

bin/vm4: src/bin/vm4.cpp $(BIN_HEADERS) | bin
	@g++ -Llib $(CXXFLAGS) -o $@ $< -ltwinleaf

binaries: $(BIN_BINS) bin/vm4

all: lib/libtwinleaf.a binaries

clean:
	@rm -rf obj lib bin
