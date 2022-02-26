CFLAGS=-std=gnu99 -Wall -Wextra -pedantic -pthread -g
FILES=hinfosvc.c
PROJ=hinfosvc

all : $(PROJ)

$(PROJ) : $(FILES)
		gcc $(CFLAGS) -o $(PROJ) $(FILES)

clean :
	rm -f *.o $(PROJ)

run :
	./hinfosvc 8000