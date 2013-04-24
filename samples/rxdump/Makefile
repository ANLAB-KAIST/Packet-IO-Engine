LIBS := -lpsio
LIB_DIR := -L../../lib
INC := -I../../include
CFLAGS := -O2 -g -Wall $(INC)
ifdef EPOLL
CFLAGS := $(CFLAGS) -DUSE_EPOLL
endif

.PHONY: clean

all: rxdump

rxdump: rxdump.c
	gcc $(CFLAGS) -o rxdump rxdump.c $(LIB_DIR) $(LIBS)

clean:
	rm -f rxdump
