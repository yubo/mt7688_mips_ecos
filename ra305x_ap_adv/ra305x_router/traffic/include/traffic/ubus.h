/*
 * yubo@xiaomi.com
 * 2014-08-20
 */
#ifndef __TRAFFICD_UBUS_H
#define __TRAFFICD_UBUS_H

#include "libubox/blob.h"
#include "libubox/blobmsg_json.h"
#include "traffic/libubus.h"



int trafficd_ubus_init(void);
void trafficd_ubus_done(void);
extern struct blob_buf traffic_b;

enum {
	C2S_HW,
	C2S_STA,
	C2S_MAT,
	C2S_EVENT,
	C2S_IFNAME,
	C2S_FLAGS,
	C2S_ROUTER_NAME,
	C2S_VERSION,
	C2S_DESCRIPTION,
	__C2S_MAX,
};

static const struct blobmsg_policy c2s_policy[__C2S_MAX] = {
	[C2S_HW]          = { .name = "hw",          .type = BLOBMSG_TYPE_STRING },
	[C2S_STA]         = { .name = "sta",         .type = BLOBMSG_TYPE_STRING },
	[C2S_MAT]         = { .name = "mat",         .type = BLOBMSG_TYPE_ARRAY },
	[C2S_EVENT]       = { .name = "event",       .type = BLOBMSG_TYPE_INT32 },
	[C2S_IFNAME]      = { .name = "ifname",      .type = BLOBMSG_TYPE_STRING },
	[C2S_FLAGS]       = { .name = "ap_flags",    .type = BLOBMSG_TYPE_INT32 },
	[C2S_ROUTER_NAME] = { .name = "router_name", .type = BLOBMSG_TYPE_STRING },
	[C2S_VERSION]     = { .name = "version",     .type = BLOBMSG_TYPE_STRING },
	[C2S_DESCRIPTION] = { .name = "description", .type = BLOBMSG_TYPE_STRING },
};

enum {
	ARP_HW,
	ARP_IP,
	__ARP_MAX,
};

static const struct blobmsg_policy arp_policy[__ARP_MAX] = {
	[ARP_HW] = { .name = "sta", .type = BLOBMSG_TYPE_STRING },
	[ARP_IP] = { .name = "ip", .type = BLOBMSG_TYPE_STRING },
};


enum {
	POST_TOTALSIZE,
	POST_FILENAME,
	POST_OFFSET,
	POST_MD5,
	POST_DATA,
	__POST_MAX,
};

static const struct blobmsg_policy postfile_policy[__POST_MAX] = {
	[POST_TOTALSIZE] = { .name = "total_size", .type = BLOBMSG_TYPE_INT32 },
	[POST_FILENAME] = { .name = "filename", .type = BLOBMSG_TYPE_STRING },
	[POST_OFFSET] = { .name = "offset", .type = BLOBMSG_TYPE_INT32 },
	[POST_MD5] = { .name = "md5", .type = BLOBMSG_TYPE_STRING },
	[POST_DATA] = { .name = "data", .type = BLOBMSG_TYPE_UNSPEC },
};



#endif
