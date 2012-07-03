LIBS = -lpsio -lnuma
LIB_DIR = -L../../lib
INC = -I../../include
CFLAGS = -O2 -g -Wall $(INC)

.PHONY: clean

all: packet_generator pspgen

pspgen: pspgen.c
	gcc $(CFLAGS) -o pspgen pspgen.c $(LIB_DIR) $(LIBS) -lpthread

packet_generator: packet_generator.c
	gcc $(CFLAGS) -o packet_generator packet_generator.c $(LIB_DIR) $(LIBS)

clean:
	rm -f packet_generator pspgen *.o
