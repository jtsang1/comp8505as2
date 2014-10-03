# Makefile for backdoor assignment

# Configuration
CC=gcc
CFLAGS=-Wall
MAIN=backdoor



# Main program
$(MAIN):bd.o chksum.o
	$(CC) $(CFLAGS) -o $(MAIN)  bd.o chksum.o

bd.o:bd.c
	$(CC) $(CFLAGS) -c bd.c

chksum.o:chksum.c
	$(CC) $(CFLAGS) -c chksum.c

clean:
	rm *.o $(MAIN)
