/*
 * yubo    <yubo@xiaomi.com>
 * 2014-12-02
 */
#include <stdio.h>
#include <unistd.h>

#include "traffic/trafficd.h"
#include "libubox/blob.h"
#include "libubox/blobmsg_json.h"
#include "traffic/libubus.h"


int trafficd_router2cli_msg_handle(const char *type, struct blob_attr *msg)
{
	char *str;

	str = blobmsg_format_json(msg, true);
	D(BUS, "{ \"%s\": %s }\n", type, str);
	free(str);

	/* subsys=xxx md5=xxx url=xxx version=xxx */

	return 0;
}