LIBS = -lps -lnuma
LIB_DIR = -L../../lib
INC = -I../../include
CFLAGS = -O2 -g -Wall $(INC)

.PHONY: clean

all: packet_generator

packet_generator: packet_generator.c
	gcc $(CFLAGS) -o packet_generator packet_generator.c $(LIB_DIR) $(LIBS)

clean:
	rm -f packet_generator
