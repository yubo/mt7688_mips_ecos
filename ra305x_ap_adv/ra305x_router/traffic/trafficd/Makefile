all: main

CFLAGS = -I../include -DUBUS_MAX_MSGLEN=1048576 -DDEBUG -g -O0
LDFLAGS = -lrt  #for clock_gettime

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


UBOX_OBJS = \
	../libubox-2014-03-18/avl.o \
	../libubox-2014-03-18/avl-cmp.o \
	../libubox-2014-03-18/blob.o \
	../libubox-2014-03-18/blobmsg.o \
	../libubox-2014-03-18/blobmsg_json.o \
	../libubox-2014-03-18/json_script.o \
	../libubox-2014-03-18/md5.o \
	../libubox-2014-03-18/runqueue.o \
	../libubox-2014-03-18/safe_list.o \
	../libubox-2014-03-18/uloop.o \
	../libubox-2014-03-18/usock.o \
	../libubox-2014-03-18/ustream.o \
	../libubox-2014-03-18/ustream-fd.o \
	../libubox-2014-03-18/utils.o \
	../libubox-2014-03-18/vlist.o

OBJS = \
	bridge.o \
	config.o \
	hw.o \
	ip.o \
	main.o \
	system_ecos.o \
	tbus.o \
	libubus.o \
	libubus-io.o \
	libubus-obj.o \
	libubus-req.o \
	libubus-sub.o \
	utils.o


main: $(OBJS)
	$(CC) $(OBJS) $(UBOX_OBJS) $(JSON_OBJS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $< $(CFLAGS) -c -o $@


clean:
	rm -f *.o main