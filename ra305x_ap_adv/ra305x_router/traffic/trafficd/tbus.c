/*
 * Copyright (C) 2011-2014 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Changes:
 * yubo    <yubo@xiaomi.com>
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/uio.h>
#ifdef FreeBSD
#include <sys/param.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "trafficd.h"
#include "libubox/blob.h"
#include "libubox/uloop.h"
#include "libubox/usock.h"
#include "libubox/list.h"
#include "libubox/blobmsg_json.h"
#include "libubus.h"



static struct sockaddr_in ubus_addr;
static struct ubus_context *ctx = NULL;
static struct ubus_event_handler listener;
struct blob_buf b1;
/*--------------------------------------------------*/

static int trafficd_router2cli_msg_handle(const char *type, struct blob_attr *msg)
{
	char *str;

	str = blobmsg_format_json(msg, true);
	D(BUS, "{ \"%s\": %s }\n", type, str);
	free(str);

	return 0;
}


/*--------------------------------------------------*/
static void tbus_receive_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	trafficd_router2cli_msg_handle(type, msg);
}



static int trafficd_ubus_add_listen(){
	int ret = 0;
	listener.cb = tbus_receive_event;
	ret = ubus_register_event_handler(ctx, &listener, sys->cfg.tbus_listen_event);
	if (ret) {
		fprintf(stderr, "Error while registering for event '%s': %s\n",
			sys->cfg.tbus_listen_event, ubus_strerror(ret));
		goto out;
	}
out:
	return ret;
}

static void trafficd_ubus_add_fd(void)
{
	ubus_add_uloop(ctx);
	system_fd_set_cloexec(ctx->sock.fd);
}

static void trafficd_ubus_reconnect_timer(struct uloop_timeout *timeout)
{
	static struct uloop_timeout retry = {
		.cb = trafficd_ubus_reconnect_timer,
	};
	int t = 2;

	if (tbus_reconnect(ctx, &ubus_addr) != 0) {
		fprintf(stderr, "failed to reconnect, trying again in %d seconds\n", t);
		uloop_timeout_set(&retry, t * 1000);
		return;
	}

	fprintf(stderr, "reconnected to ubus, new id: %08x\n", ctx->local_id);
	trafficd_ubus_add_listen();
	trafficd_ubus_add_fd();
	sys->assoc_pending = true;

}

static void trafficd_ubus_connection_lost(struct ubus_context *ctx)
{
	trafficd_ubus_reconnect_timer(NULL);
}



static int tbus_init(struct sockaddr_in *a)
{
	D(BUS, "connected to %s:%d\n", inet_ntoa(a->sin_addr), ntohs(a->sin_port));
	while(!(ctx = tbus_connect(a) )){
		elog("failed to connect, trying again in 2 seconds \n");
		sleep(2);
	}

	D(BUS, "connected as 0x%08x\n", ctx->local_id);
	ctx->connection_lost = trafficd_ubus_connection_lost;

	memset(&listener, 0, sizeof(listener));
	trafficd_ubus_add_listen();
	trafficd_ubus_add_fd();
	sys->tbus_ctx = ctx;

	return 0;
}

int trafficd_tbus_done(){
	if(ctx){
		ubus_free(ctx);
		ctx = NULL;
	}
	return 0;
}


int trafficd_tbus_init(){

	memset(&ubus_addr, 0, sizeof(ubus_addr));
	ubus_addr.sin_port = htons(sys->cfg.tbus_listen_port);
	ubus_addr.sin_family = AF_INET;

	sys->tbus_ctx = NULL;

	D(BUS, "ap mode, tbus_init()\n");
	/* connect to lan_gw tbusd */
	if ( sys->cfg.lan_gw &&
			!inet_aton(sys->cfg.lan_gw,
				(struct in_addr *) &ubus_addr.sin_addr.s_addr)) {
		elog("bad IP address format\n");
		return -1;
	}

	return tbus_init(&ubus_addr);
}
