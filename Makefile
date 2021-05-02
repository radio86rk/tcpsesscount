CC = gcc
CFLAGS  = -Wall -DDEBUG_MODE

all: tcpsesscount
 
tcpsesscount: src/tcpsesscount.c
	$(CC) $(CFLAGS) -o tcpsesscount src/tcpsesscount.c -lpcap

clean:
	rm -rf tcpsesscount
