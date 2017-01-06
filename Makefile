# Copyright: 2016 Twinleaf LLC
# Author: gilberto@tersatech.com
# License: Proprietary

CCFLAGS = -g -Wall -Wextra -Iinclude/ -std=gnu11

.DEFAULT_GOAL = all
.SECONDARY:

LIB_HEADERS = $(wildcard include/tio/*.h) $(wildcard src/*.h)
LIB_SOURCES = $(wildcard src/*.c)
LIB_OBJS = $(patsubst src/%.c,obj/%.o,$(LIB_SOURCES))

$(LIB_OBJS): | obj

obj lib:
	@mkdir -p $@

obj/%.o: src/%.c $(LIB_HEADERS)
	@$(CC) $(CCFLAGS) -c $< -o $@

lib/libtio.a: $(LIB_OBJS) | lib
	@ar rcs $@ $(LIB_OBJS)

all: lib/libtio.a

clean:
	@rm -rf obj lib
