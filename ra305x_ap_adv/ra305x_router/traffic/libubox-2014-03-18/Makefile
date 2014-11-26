all: main

CFLAGS = -I../include -I../include/libubox 
LDFLAGS = -lrt -g -O0 #for clock_gettime

JSON_OBJS = \
	../json-c-0.11/arraylist.o \
	../json-c-0.11/debug.o \
	../json-c-0.11/json_c_version.o \
	../json-c-0.11/json_object.o \
	../json-c-0.11/json_object_iterator.o \
	../json-c-0.11/json_tokener.o \
	../json-c-0.11/json_util.o \
	../json-c-0.11/libjson.o \
	../json-c-0.11/linkhash.o \
	../json-c-0.11/printbuf.o


OBJS = avl.o \
	avl-cmp.o \
	blob.o \
	blobmsg.o \
	blobmsg_json.o \
	json_script.o \
	md5.o \
	runqueue.o \
	safe_list.o \
	uloop.o \
	usock.o \
	ustream.o \
	ustream-fd.o \
	utils.o \
	vlist.o

main: main.o $(OBJS)
	$(CC) $< $(OBJS) $(JSON_OBJS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@


clean:
	rm -f *.o main
