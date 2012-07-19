CFLAGS=-Wall -Wno-pointer-sign -Werror
LDFLAGS=-lvzctl2 -lyajl -lrt
OBJS = main.o parser.o

all: pcompact

pcompact: ${OBJS}
	$(CC) $(LDFLAGS) $^ -o $@

parser: parser.c
	$(CC) $(LDFLAGS) $(CFLAGS) -DMAIN parser.c -o parser

clean:
	rm -f pcompact parser ${OBJS}
