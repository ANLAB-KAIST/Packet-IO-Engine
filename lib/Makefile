CFLAGS=-O2 -g -Wall -I../include

.PHONY: clean

static: psio.c
	rm -f psio.o
	gcc $(CFLAGS) -c -o psio.o psio.c
	ar rcs libpsio.a psio.o

shared: psio.c
	rm -f psio.o
	gcc $(CFLAGS) -fPIC -c -o psio.o psio.c
	gcc -shared -Wl,-soname,libpsio.so.1 \
	    -o libpsio.so.1.0.0 psio.o

clean:
	rm -f *.o *.a *.so.*
