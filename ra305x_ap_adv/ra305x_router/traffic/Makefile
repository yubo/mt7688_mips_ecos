#
# Makefile
#

#.EXPORT_ALL_VARIABLES:

CURR_DIR=$(shell pwd)
EXTRA_CFLAGS = -I$(CURR_DIR)/include -DUBUS_MAX_MSGLEN=1048576


MODULE = $(shell pwd | sed "s/.*\///" ).o

all: $(MODULE)

include $(TOPDIR)/rules.mak

TRAFFICDDIR = trafficd
JSONDIR = json-c-0.11
LIBUBOXDIR = libubox-2014-03-18

TRAFFICD_OBJS = \
	$(TRAFFICDDIR)/config.o \
	$(TRAFFICDDIR)/hw.o \
	$(TRAFFICDDIR)/ip.o \
	$(TRAFFICDDIR)/main.o \
	$(TRAFFICDDIR)/system_ecos.o \
	$(TRAFFICDDIR)/tbus.o \
	$(TRAFFICDDIR)/libubus.o \
	$(TRAFFICDDIR)/libubus-io.o \
	$(TRAFFICDDIR)/libubus-obj.o \
	$(TRAFFICDDIR)/libubus-req.o \
	$(TRAFFICDDIR)/libubus-sub.o \
	$(TRAFFICDDIR)/utils.o


JSON_OBJS = \
	$(JSONDIR)/arraylist.o \
	$(JSONDIR)/debug.o \
	$(JSONDIR)/json_c_version.o \
	$(JSONDIR)/json_object.o \
	$(JSONDIR)/json_object_iterator.o \
	$(JSONDIR)/json_tokener.o \
	$(JSONDIR)/json_util.o \
	$(JSONDIR)/libjson.o \
	$(JSONDIR)/linkhash.o \
	$(JSONDIR)/printbuf.o

LIBUBOX_OBJS = \
	$(LIBUBOXDIR)/avl.o \
	$(LIBUBOXDIR)/avl-cmp.o \
	$(LIBUBOXDIR)/blob.o \
	$(LIBUBOXDIR)/blobmsg.o \
	$(LIBUBOXDIR)/blobmsg_json.o \
	$(LIBUBOXDIR)/json_script.o \
	$(LIBUBOXDIR)/md5.o \
	$(LIBUBOXDIR)/runqueue.o \
	$(LIBUBOXDIR)/safe_list.o \
	$(LIBUBOXDIR)/uloop.o \
	$(LIBUBOXDIR)/usock.o \
	$(LIBUBOXDIR)/ustream.o \
	$(LIBUBOXDIR)/ustream-fd.o \
	$(LIBUBOXDIR)/utils.o \
	$(LIBUBOXDIR)/vlist.o


ALL_OBJS = $(TRAFFICD_OBJS) $(JSON_OBJS) $(LIBUBOX_OBJS)

$(MODULE): $(ALL_OBJS:.o=.d)
	$(XLD) -r $(ENDIAN) -o $(MODULE) $(ALL_OBJS)

clean:
	rm $(MODULE) $(ALL_OBJS)
