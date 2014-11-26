/*
 * yubo@xiaomi.com
 * 2014-08-20
 */
#ifndef __TRAFFICD_UBUS_H
#define __TRAFFICD_UBUS_H

#include "blob.h"
#include "blobmsg_json.h"
#include "libubus.h"



int trafficd_ubus_init(void);
void trafficd_ubus_done(void);
extern struct blob_buf b1;

enum {
	C2S_HW,
	C2S_IP,
	C2S_MAT,
	C2S_TABLE,
	C2S_EVENT,
	C2S_IFNAME,
	__C2S_MAX,
};

static const struct blobmsg_policy c2s_policy[__C2S_MAX] = {
	[C2S_HW] = { .name = "hw", .type = BLOBMSG_TYPE_STRING },
	[C2S_IP] = { .name = "ip", .type = BLOBMSG_TYPE_STRING },
	[C2S_MAT] = { .name = "mat", .type = BLOBMSG_TYPE_ARRAY },
	[C2S_TABLE] = { .name = "data", .type = BLOBMSG_TYPE_TABLE },
	[C2S_EVENT] = { .name = "event", .type = BLOBMSG_TYPE_INT32 },
	[C2S_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
};


#endif
