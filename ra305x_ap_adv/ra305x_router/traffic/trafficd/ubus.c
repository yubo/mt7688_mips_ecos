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
 */

/* yubo@xiaomi.com
 * 2014-08-15
 */

#include <unistd.h>
#include <signal.h>


#include "trafficd.h"
#include "ubus.h"
#include "ip.h"
#include "dev.h"
#include "point.h"
#include "ubusd.h"

static struct ubus_context *ctx;
static struct ubus_event_handler listener;

static int trafficd_ubus_add_listen();

static int trafficd_handle_restart(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	TR_REFRESH_TIME();
	trafficd_restart();
	return 0;
}

static int trafficd_handle_reload(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	trafficd_reload();
	return 0;
}

static int trafficd_handle_assoclist_update(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	system_assoclist_update();
	return 0;
}

static int trafficd_handle_point_dump(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	TR_REFRESH_TIME();
	blob_buf_init(&b1, 0);
	trafficd_point_dump_status(&b1);
	ubus_send_reply(ctx, req, b1.head);
	return 0;
}

static int trafficd_handle_wan_rate_dump(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	TR_REFRESH_TIME();
	blob_buf_init(&b1, 0);
	trafficd_dev_dump_wan_rate(&b1);
	ubus_send_reply(ctx, req, b1.head);
	return 0;
}

static int trafficd_handle_update_hostname(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	TR_REFRESH_TIME();
	trafficd_hw_update_hostname();
	trafficd_ip_update_hostname();
	return 0;
}


enum {
	TIMESTEP_DAY,
	TIMESTEP_HOUR,
	TIMESTEP_10MIN,
	__TIMESTEP_MAX,
};

static const struct blobmsg_policy timestep_policy[__TIMESTEP_MAX] = {
	[TIMESTEP_DAY] = { .name = "timestep_day", .type = BLOBMSG_TYPE_INT32 },
	[TIMESTEP_HOUR] = { .name = "timestep_hour", .type = BLOBMSG_TYPE_INT32 },
	[TIMESTEP_10MIN] = { .name = "timestep_10min", .type = BLOBMSG_TYPE_INT32 },
};


static int trafficd_handle_point_timestep(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__TIMESTEP_MAX];
	int timestep_day, timestep_hour, timestep_10min;

	TR_REFRESH_TIME();
	blobmsg_parse(timestep_policy, __TIMESTEP_MAX, tb, blob_data(msg), blob_len(msg));

	if(tb[TIMESTEP_DAY] && tb[TIMESTEP_HOUR] && tb[TIMESTEP_10MIN]){
		timestep_day = blobmsg_get_u32(tb[TIMESTEP_DAY]);
		timestep_hour = blobmsg_get_u32(tb[TIMESTEP_HOUR]);
		timestep_10min = blobmsg_get_u32(tb[TIMESTEP_10MIN]);
		if(timestep_day && timestep_hour && timestep_10min){
			trafficd_point_timestep_set(timestep_day, timestep_hour, timestep_10min);
			return 0;
		}else{
			return UBUS_STATUS_INVALID_ARGUMENT;
		}
	}else{
		blob_buf_init(&b1, 0);
		trafficd_point_timestep_dump(&b1);
		ubus_send_reply(ctx, req, b1.head);
	}
	return 0;
}


enum {
	IP_ADDR,
	IP_DEBUG,
	__IP_MAX,
};

static const struct blobmsg_policy ip_policy[__IP_MAX] = {
	[IP_ADDR] = { .name = "ip", .type = BLOBMSG_TYPE_STRING },
	[IP_DEBUG] = { .name = "debug", .type = BLOBMSG_TYPE_BOOL },
};




static int trafficd_handle_ip(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct ip_node *ip_node = NULL;
	struct blob_attr *tb[__IP_MAX];
	int debug = 0;

	TR_REFRESH_TIME();

	D(BUS, "EnterFunction\n");
	blobmsg_parse(ip_policy, __IP_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[IP_ADDR]) {
		ip_node = trafficd_ip_get(blobmsg_data(tb[IP_ADDR]), false);
		if (!ip_node){
			D(BUS, "UBUS_STATUS_INVALID_ARGUMENT\n");
			return UBUS_STATUS_INVALID_ARGUMENT;
		}

	}

	if(tb[IP_DEBUG])
		debug = blobmsg_get_bool(tb[IP_DEBUG]);

	blob_buf_init(&b1, 0);
	trafficd_ip_dump_status(&b1, ip_node, debug);
	ubus_send_reply(ctx, req, b1.head);

	return 0;
}


enum {
	HW_ADDR,
	HW_TREE,
	HW_ALL,
	HW_LOG,
	HW_DEBUG,
	__HW_MAX,
};

static const struct blobmsg_policy hw_policy[__HW_MAX] = {
	[HW_ADDR] = { .name = "hw", .type = BLOBMSG_TYPE_STRING },
	[HW_TREE] = { .name = "tree", .type = BLOBMSG_TYPE_BOOL },
	[HW_ALL] = { .name = "all", .type = BLOBMSG_TYPE_BOOL },
	[HW_LOG] = { .name = "log", .type = BLOBMSG_TYPE_BOOL },
	[HW_DEBUG] = { .name = "debug", .type = BLOBMSG_TYPE_BOOL },
};


static int trafficd_handle_hw(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct hw_node *hw_node = NULL;
	struct blob_attr *tb[__HW_MAX];
	int hw_debug = 0;
	int hw_all = 0;
	int hw_log = 0;
	int hw_tree = 0;
	TR_REFRESH_TIME();

	blobmsg_parse(hw_policy, __HW_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[HW_ADDR]) {
		hw_node = trafficd_hw_get(blobmsg_data(tb[HW_ADDR]), false);
		if (!hw_node)
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if(tb[HW_ALL])
		hw_all = blobmsg_get_bool(tb[HW_ALL]);

	if(tb[HW_LOG])
		hw_log = blobmsg_get_bool(tb[HW_LOG]);

	if(tb[HW_DEBUG])
		hw_debug = blobmsg_get_bool(tb[HW_DEBUG]);

	if(tb[HW_TREE])
		hw_tree = blobmsg_get_bool(tb[HW_TREE]);

	blob_buf_init(&b1, 0);
	trafficd_hw_dump_status(&b1, hw_node, hw_tree, hw_all, hw_log, hw_debug);
	ubus_send_reply(ctx, req, b1.head);

	return 0;
}


enum {
	DEV_IFNAME,
	DEV_DEBUG,
	__DEV_MAX,
};

static const struct blobmsg_policy dev_policy[__DEV_MAX] = {
	[DEV_IFNAME] = { .name = "dev", .type = BLOBMSG_TYPE_STRING },
	[DEV_DEBUG] = { .name = "debug", .type = BLOBMSG_TYPE_BOOL },
};


static int trafficd_handle_dev(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct dev_node *dev_node = NULL;
	struct blob_attr *tb[__DEV_MAX];
	int debug = 0;
	TR_REFRESH_TIME();

	blobmsg_parse(dev_policy, __DEV_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[DEV_IFNAME]) {
		dev_node = trafficd_dev_get(blobmsg_data(tb[DEV_IFNAME]), false);
		if (!dev_node)
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if(tb[DEV_DEBUG])
		debug = blobmsg_get_bool(tb[DEV_DEBUG]);

	blob_buf_init(&b1, 0);
	trafficd_dev_dump_status(&b1, dev_node, debug);
	ubus_send_reply(ctx, req, b1.head);

	return 0;
}

static int trafficd_handle_setwan(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__DEV_MAX];
	TR_REFRESH_TIME();

	blobmsg_parse(dev_policy, __DEV_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[DEV_IFNAME]) {
		if (!trafficd_wan_set(blobmsg_data(tb[DEV_IFNAME])))
			return UBUS_STATUS_NOT_FOUND;
	}else{
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	return 0;
}

static int trafficd_handle_setlan(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__DEV_MAX];

	TR_REFRESH_TIME();
	blobmsg_parse(dev_policy, __DEV_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[DEV_IFNAME]) {
		if (!trafficd_lan_set(blobmsg_data(tb[DEV_IFNAME])))
			return UBUS_STATUS_NOT_FOUND;
	}else{
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	return 0;
}


static int trafficd_handle_wan_dump(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	TR_REFRESH_TIME();

	blob_buf_init(&b1, 0);

	trafficd_dev_wan_dump(&b1);

	ubus_send_reply(ctx, req, b1.head);
	return 0;
}


static int trafficd_handle_lan_dump(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	TR_REFRESH_TIME();
	blob_buf_init(&b1, 0);

	trafficd_dev_lan_dump(&b1);

	ubus_send_reply(ctx, req, b1.head);
	return 0;
}

static const struct ubus_method trafficd_router_methods[] = {
	UBUS_METHOD("ip", trafficd_handle_ip, ip_policy),
	UBUS_METHOD("hw", trafficd_handle_hw, hw_policy),
	UBUS_METHOD("dev", trafficd_handle_dev, dev_policy),
	{ .name = "wan", .handler = trafficd_handle_wan_dump},
	{ .name = "lan", .handler = trafficd_handle_lan_dump},
	UBUS_METHOD("setwan", trafficd_handle_setwan, dev_policy),
	UBUS_METHOD("setlan", trafficd_handle_setlan, dev_policy),
	{ .name = "point_show", .handler = trafficd_handle_point_dump},
	{ .name = "list_wan_rate", .handler = trafficd_handle_wan_rate_dump},
	{ .name = "update_hostname", .handler = trafficd_handle_update_hostname},
	UBUS_METHOD("timestep", trafficd_handle_point_timestep, timestep_policy),
	{ .name = "restart", .handler = trafficd_handle_restart },
	{ .name = "reload", .handler = trafficd_handle_reload },
	{ .name = "update_assoclist", .handler = trafficd_handle_assoclist_update },
};

static struct ubus_object_type trafficd_router_object_type =
UBUS_OBJECT_TYPE("trafficd", trafficd_router_methods);

static struct ubus_object trafficd_router_object = {
	.name = "trafficd",
	.type = &trafficd_router_object_type,
	.methods = trafficd_router_methods,
	.n_methods = ARRAY_SIZE(trafficd_router_methods),
};

static const struct ubus_method trafficd_ap_methods[] = {
	UBUS_METHOD("ip", trafficd_handle_ip, ip_policy),
	UBUS_METHOD("hw", trafficd_handle_hw, hw_policy),
	{ .name = "restart", .handler = trafficd_handle_restart },
	{ .name = "reload", .handler = trafficd_handle_reload },
};

static struct ubus_object_type trafficd_ap_object_type =
UBUS_OBJECT_TYPE("trafficd", trafficd_ap_methods);

static struct ubus_object trafficd_ap_object = {
	.name = "trafficd",
	.type = &trafficd_ap_object_type,
	.methods = trafficd_ap_methods,
	.n_methods = ARRAY_SIZE(trafficd_ap_methods),
};


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

	if (ubus_reconnect(ctx, sys->cfg.ubus_socket) != 0) {
		D(BUS, "failed to reconnect, trying again in %d seconds\n", t);
		uloop_timeout_set(&retry, t * 1000);
		return;
	}

	D(BUS, "reconnected to ubus, new id: %08x\n", ctx->local_id);
	trafficd_ubus_add_listen();
	trafficd_ubus_add_fd();
}

static void trafficd_ubus_connection_lost(struct ubus_context *ctx)
{
	trafficd_ubus_reconnect_timer(NULL);
}

static int trafficd_add_object(struct ubus_object *obj)
{
	int ret = ubus_add_object(ctx, obj);

	if (ret != 0)
		elog("Failed to publish object '%s': %s\n", obj->name, ubus_strerror(ret));
	return ret;
}

static void ubus_receive_event(
		struct ubus_context *ctx, struct ubus_event_handler *ev,
		const char *type, struct blob_attr *msg)
{
	if(sys->cfg.is_router){
		trafficd_local_msg_handle(type, msg);
		blob_buf_init(&b1, 0);
		blobmsg_add_string(&b1, "id", type);
		blobmsg_add_field(&b1, BLOBMSG_TYPE_TABLE, "data", blob_data(msg), blob_len(msg));
		ubusd_event_send(b1.head);
	}
}


static int trafficd_ubus_add_listen(){
	int ret = 0;

	if(!sys->cfg.is_router)
		return 0;

	D(BUS, "ubus_register_event_handler %s\n", sys->cfg.tbus_listen_event);
	listener.cb = ubus_receive_event;
	ret = ubus_register_event_handler(ctx, &listener, sys->cfg.tbus_listen_event);
	if (ret) {
		elog("Error while registering for event '%s': %s\n",
				sys->cfg.tbus_listen_event, ubus_strerror(ret));
		goto out;
	}
out:
	return ret;
}

int trafficd_ubus_init()
{

	ctx = ubus_connect(sys->cfg.ubus_socket);
	if (!ctx)
		return -EIO;

	D(BUS, "connected as %08x\n", ctx->local_id);
	ctx->connection_lost = trafficd_ubus_connection_lost;
	trafficd_ubus_add_fd();
	memset(&listener, 0, sizeof(listener));
	trafficd_ubus_add_listen();
	if(sys->cfg.is_router)
		return trafficd_add_object(&trafficd_router_object);
	else
		return trafficd_add_object(&trafficd_ap_object);
}

void trafficd_ubus_done(void)
{
	if(ctx)
		ubus_free(ctx);
	ctx = NULL;
}

