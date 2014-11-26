all: main

CFLAGS = -I../include -g -O0

OBJS = arraylist.o \
	debug.o \
	json_c_version.o \
	json_object.o \
	json_object_iterator.o \
	json_tokener.o \
	json_util.o \
	libjson.o \
	linkhash.o \
	printbuf.o

main: main.o $(OBJS)
	$(CC) $< $(OBJS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@


clean:
	rm -f *.o main
