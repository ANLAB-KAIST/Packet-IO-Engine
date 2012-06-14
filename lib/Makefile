CFLAGS=-O2 -g -Wall -I../include

.PHONY: clean

all: pslib.a

pslib.a: pslib.c
	gcc $(CFLAGS) -c -o pslib.o pslib.c
	ar rcs libps.a pslib.o

clean:
	rm -f *.o *.a
