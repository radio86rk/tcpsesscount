CC = gcc
CFLAGS  = -Wall -lpcap -DDEBUG_MODE

all: tcpsesscount
 
tcpsesscount: src/tcpsesscount.c
	$(CC) $(CFLAGS) -o tcpsesscount src/tcpsesscount.c

clean:
	rm -rf tcpsesscount
