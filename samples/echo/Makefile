LIBS = -lps -lnuma
LIB_DIR = -L../../lib

.PHONY: clean

all: echo

echo: echo.c
	gcc -O2 -g -Wall -o echo echo.c $(LIB_DIR) $(LIBS)

clean:
	rm -f echo
