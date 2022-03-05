LOGIN=xkeszi00
CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -pedantic -pthread
SOURCE=hinfosvc.c
BIN=hinfosvc
ALLFILES=$(SOURCE) makefile README.md

all :
	$(CC) $(CFLAGS) $(SOURCE) -o $(BIN)

zip:
	zip $(LOGIN).zip $(ALLFILES)

clean :
	rm -f *.o $(BIN) $(LOGIN).zip

run :
	./hinfosvc 8080
