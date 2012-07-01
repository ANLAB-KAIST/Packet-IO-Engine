LIBS = -lpsio
LIB_DIR = -L../../lib
INC = -I../../include
CFLAGS = $(INC) -O2 -g -Wall

.PHONY: clean

all: list_devices

list_devices: list_devices.c
	gcc $(CFLAGS) -o list_devices list_devices.c $(LIB_DIR) $(LIBS)

clean:
	rm -f list_devices
