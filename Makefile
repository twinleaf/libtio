# Copyright: 2016 Twinleaf LLC
# Author: gilberto@tersatech.com
# License: Proprietary

CC = gcc
CCFLAGS = -g -Wall -Wextra -Iinclude/

.DEFAULT_GOAL = all

LIB_HEADERS = $(wildcard include/twinleaf/*.h) $(wildcard src/lib/*.h)
LIB_SOURCES = $(wildcard src/lib/*.c)
LIB_OBJS = $(patsubst src/%.c,obj/%.o,$(LIB_SOURCES))

PROXY_HEADERS = $(LIB_HEADERS)
PROXY_SOURCES = src/bin/proxy.c
PROXY_OBJS = $(patsubst src/%.c,obj/%.o,$(PROXY_SOURCES))

$(LIB_OBJS): | obj/lib

obj/lib obj/bin lib bin:
	@mkdir -p $@

obj/lib/%.o: src/lib/%.c $(LIB_HEADERS)
	@$(CC) $(CCFLAGS) $(LIB_INCLUDE_FLAGS) -c $< -o $@

lib/libtwinleaf.a: $(LIB_OBJS) | lib
	@ar rcs $@ $(LIB_OBJS)

obj/bin/proxy.o: src/bin/proxy.c $(PROXY_HEADERS) | obj/bin
	@$(CC) $(CCFLAGS) $(PROXY_INCLUDE_FLAGS) -c $< -o $@

bin/proxy: $(PROXY_OBJS) lib/libtwinleaf.a | bin
	@$(CC) -Llib -o $@ $(PROXY_OBJS) -ltwinleaf

all: lib/libtwinleaf.a bin/proxy

clean:
	@rm -rf obj lib bin
