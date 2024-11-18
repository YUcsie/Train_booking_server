# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2

all: read_server write_server

read_server: server.c server.h
	$(CC) $(CFLAGS) -D READ_SERVER server.c -o read_server

write_server: server.c server.h
	$(CC) $(CFLAGS) -D WRITE_SERVER server.c -o write_server

clean:
	rm -f read_server write_server *.o
