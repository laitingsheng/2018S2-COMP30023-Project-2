################################################################################
# Makefile for the project
# Create by Tingsheng Lai (tingshengl, 781319)
################################################################################

CC      = gcc
CFLAGS  = -O3 -std=c99 -Wall -Wextra -Wpedantic
EXE     = certcheck
OBJ     = bin/main.o

$(EXE): mkdir $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) -lssl -lcrypto
bin/main.o: src/main.c
	$(CC) $(CFLAGS) -c -o $@ $^ -lssl -lcrypto

mkdir:
	mkdir -p bin

.PHONY: clean

clean:
	rm -rf bin
	rm -f server
