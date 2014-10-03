# Makefile for backdoor assignment

# Configuration
CC=gcc
CFLAGS=-Wall
MAIN=backdoor



# Main program
$(MAIN):bd.o
	$(CC) $(CFLAGS) -o $(MAIN)  bd.o

bd.o:bd.c
	$(CC) $(CFLAGS) -c bd.c

clean:
	rm *.o $(MAIN)
