# Makefile for backdoor assignment
CC=gcc
CFLAGS=-Wall

backdoor:bd.c
    $(CC) $(CFLAGS) bd.c -o backdoor

