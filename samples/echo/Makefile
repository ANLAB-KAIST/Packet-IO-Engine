LIBS = -lpsio -lnuma
LIB_DIR = -L../../lib
INC = -I../../include
CFLAGS = $(INC) -O2 -g -Wall

.PHONY: clean

all: echo

echo: echo.c
	gcc $(CFLAGS) -o echo echo.c $(LIB_DIR) $(LIBS)

clean:
	rm -f echo
