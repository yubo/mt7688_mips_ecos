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

#include "traffic/trafficd.h"
#include "libubox/blob.h"
#include "libubox/uloop.h"
#include "libubox/list.h"
#include "libubox/md5.h"
#include "libubox/blobmsg_json.h"
#include "traffic/libubus.h"
#include "traffic/ubus.h"

#ifdef __ECOS
#include "nvram.h"
#endif

#define BUFFER_SIZE 1024*64

#ifdef CONFIG_HTTPD
extern unsigned int write_flsh_cfg_fwm_off;
extern unsigned int flsh_cfg_fwm_off;
extern int FirstImageSegment;
#else
unsigned int write_flsh_cfg_fwm_off;
unsigned int flsh_cfg_fwm_off;
int FirstImageSegment;
#endif

extern void sys_reboot(void);

static struct sockaddr_in ubus_addr;
static struct ubus_context *ctx = NULL;
static struct ubus_event_handler listener;
struct blob_buf traffic_b;
static struct {
	char *buff;
	uint32_t buff_len;
	uint32_t buff_offset;
	uint32_t offset;
	uint32_t totalsize;
	char filename[256];
	char post_md5[33];
	char recv_md5[33];
	uint32_t md5[4];
	struct uloop_timeout timeout;
	md5_ctx_t md5_ctx;
} recv_file;


/*--------------------------------------------------*/
static void tbus_receive_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
			  const char *type, struct blob_attr *msg)
{
	trafficd_router2cli_msg_handle(type, msg);
}


static int trafficd_ubus_add_listen(void){
	int ret = 0;
	listener.cb = tbus_receive_event;
	ret = ubus_register_event_handler(ctx, &listener, sys->cfg.tbus_listen_event);
	if (ret) {
		elog("Error while registering for event '%s': %s\n",
			sys->cfg.tbus_listen_event, ubus_strerror(ret));
		goto out;
	}
out:
	return ret;
}

static void trafficd_ubus_add_fd(void)
{
	ubus_add_uloop(ctx);
#ifndef __ECOS
	system_fd_set_cloexec(ctx->sock.fd);
#endif
}


static void recv_file_clean(void)
{
	if(recv_file.buff){
		free(recv_file.buff);
		recv_file.buff = NULL;
	}
	recv_file.offset = 0;
}

static void recv_file_timeout_cb(struct uloop_timeout *timeout)
{
	recv_file_clean();
}

static void trafficd_reboot_timer(struct uloop_timeout *timeout)
{
	sys_reboot();
}

static int trafficd_handle_postfile(
		struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg){

	struct blob_attr *tb[__POST_MAX];
	uint32_t totalsize, offset;
	int len, llen, hlen;
	char *filename;
	char *md5;
	void *data;
	int ret, result;

	ret = 0;
	//TR_REFRESH_TIME();

	D(BUS, "EnterFunction\n");
	blobmsg_parse(postfile_policy, __POST_MAX, tb, blob_data(msg), blob_len(msg));


	if(!(tb[POST_TOTALSIZE] && tb[POST_FILENAME] && tb[POST_OFFSET] && tb[POST_MD5] && tb[POST_DATA])){
		ret = UBUS_STATUS_INVALID_ARGUMENT;
		goto reset;
	}

	totalsize = blobmsg_get_u32(tb[POST_TOTALSIZE]);
	filename = blobmsg_get_string(tb[POST_FILENAME]);
	offset = blobmsg_get_u32(tb[POST_OFFSET]);
	md5 = blobmsg_get_string(tb[POST_MD5]);
	len = blobmsg_len(tb[POST_DATA]);
	data = blobmsg_data(tb[POST_DATA]);

	dlog("totalsize:%d, filename:%s, offset:%d, md5:%s, len:%d\n",
		totalsize, filename, offset, md5, len);

	if(offset == 0){
		if(totalsize <= 0){
			elog("totalsize <= 0");
			ret = UBUS_STATUS_INVALID_ARGUMENT;
			goto reset;
		}

		if(recv_file.buff){
			free(recv_file.buff);
		}

		md5_begin(&recv_file.md5_ctx);
		recv_file.buff = malloc(BUFFER_SIZE);
		recv_file.buff_len = BUFFER_SIZE;
		recv_file.offset = 0;
		recv_file.buff_offset = 0;
		strncpy(recv_file.filename, filename, sizeof(recv_file.filename));
		strncpy(recv_file.post_md5, md5, sizeof(recv_file.post_md5));
		recv_file.totalsize = totalsize;
		uloop_timeout_set(&recv_file.timeout, 10 * 60 * 1000);
	}else{
		if(strncmp(filename, recv_file.filename, sizeof(recv_file.filename)) ||
				(offset != recv_file.offset) ||
				(recv_file.totalsize < recv_file.offset + len) ){
			elog("UBUS_STATUS_INVALID_ARGUMENT");
			ret = UBUS_STATUS_INVALID_ARGUMENT;
			goto reset;
		}
	}

	if(!recv_file.buff){
		elog("malloc recv_file.buff error");
		ret = UBUS_STATUS_NO_DATA;
		goto reset;
	}

	/* add data to buff */
	if(recv_file.buff_len >= recv_file.buff_offset + len){
		memcpy(&recv_file.buff[recv_file.buff_offset], data, len);
		recv_file.buff_offset += len;
		dlog("recv_file.buff_len[%d] > recv_file.buff_offset[%d] + len[%d]\n",
			recv_file.buff_len, recv_file.buff_offset, len);
	}else{
		llen = recv_file.buff_len - recv_file.buff_offset;
		hlen = len - llen;
		memcpy(&recv_file.buff[recv_file.buff_offset], data, llen);

        dlog("recv_file.buff_len:%d\n", recv_file.buff_len);
#ifdef __ECOS
        result = CFG_write_image_tbus(recv_file.buff, recv_file.buff_len, recv_file.totalsize);
        if(result)
            elog("***Write segment error!***\n");
#endif
        if (FirstImageSegment) {
            FirstImageSegment = 0;
        }

        write_flsh_cfg_fwm_off += recv_file.buff_len;

        /* todo: hlen may be > recv_file.buff_len */
		memcpy(recv_file.buff, data + llen, hlen);
		recv_file.buff_offset = hlen;
		dlog("recv_file.buff_len[%d], recv_file.buff_offset[%d], len[%d], llen[%d], hlen[%d]\n",
			recv_file.buff_len, recv_file.buff_offset, len, llen, hlen);
	}

	recv_file.offset += len;
	md5_hash(data, len, &recv_file.md5_ctx);

	if(recv_file.offset == recv_file.totalsize){
		memset(recv_file.md5, 0, sizeof(uint32_t) * 4);
		md5_end(recv_file.md5, &recv_file.md5_ctx);
		snprintf(recv_file.recv_md5, sizeof(recv_file.recv_md5), "%08x%08x%08x%08x",
			htonl(recv_file.md5[0]), htonl(recv_file.md5[1]), htonl(recv_file.md5[2]), htonl(recv_file.md5[3]));
		blob_buf_init(&traffic_b, 0);
		//recv_file.buff[recv_file.totalsize] = '\0';
		blobmsg_add_string(&traffic_b, "filename", recv_file.filename);
		blobmsg_add_u32(&traffic_b, "size", recv_file.totalsize);
		blobmsg_add_string(&traffic_b, "post_md5", recv_file.post_md5);
		blobmsg_add_string(&traffic_b, "recv_md5", recv_file.recv_md5);
		//blobmsg_add_string(&traffic_b, "data", recv_file.buff);
		blobmsg_add_u32(&traffic_b, "code", strncmp(recv_file.recv_md5, recv_file.post_md5, sizeof(recv_file.post_md5)));
		ubus_send_reply(ctx, req, traffic_b.head);

		if(recv_file.buff_offset){
#ifdef __ECOS
			result = CFG_write_image_tbus(recv_file.buff, recv_file.buff_offset, recv_file.totalsize);
			if(result) {
				elog("***Write last segment error!***");
			}
			write_flsh_cfg_fwm_off += recv_file.buff_offset;
#endif
		}

		elog("postfile finished! 1:%d\n", recv_file.buff_offset);
#ifdef __ECOS
		if (strncmp(recv_file.recv_md5, recv_file.post_md5, sizeof(recv_file.post_md5)) == 0) {
			elog("postfile finished!\n");
			nvram_set(UBOOT_NVRAM, "flag_ota_reboot", "1");
			nvram_commit(UBOOT_NVRAM);

            // reboot after 2000ms
			static struct uloop_timeout reboot = {
				.cb = trafficd_reboot_timer,
			};
			uloop_timeout_set(&reboot, 2000);
		}
#endif
        write_flsh_cfg_fwm_off = flsh_cfg_fwm_off;
        FirstImageSegment = 1;

		goto reset;
	}
	else{
		blob_buf_init(&traffic_b, 0);
		blobmsg_add_u32(&traffic_b, "offset", recv_file.offset);
		ubus_send_reply(ctx, req, traffic_b.head);
	}
	return 0;

reset:
	dlog("recv_file_clean\n");
	recv_file_clean();
	return ret;
}

static const struct ubus_method trafficd_ecos_methods[] = {
	UBUS_METHOD("postfile", trafficd_handle_postfile, postfile_policy),
};

static struct ubus_object_type trafficd_ecos_object_type =
UBUS_OBJECT_TYPE("trafficd", trafficd_ecos_methods);

static struct ubus_object trafficd_ecos_object = {
	.name = "default",
	.type = &trafficd_ecos_object_type,
	.methods = trafficd_ecos_methods,
	.n_methods = ARRAY_SIZE(trafficd_ecos_methods),
};

static int trafficd_add_object(struct ubus_object *obj)
{
	int ret = ubus_replace_object(ctx, obj);

	if (ret != 0)
		D(SYSTEM, "Failed to publish object '%s': %s\n", obj->name, ubus_strerror(ret));
	else
		D(SYSTEM, "successful to publish object '%s'\n", obj->name);
	return ret;
}

static void trafficd_ubus_reconnect_timer(struct uloop_timeout *timeout)
{
	static struct uloop_timeout retry = {
		.cb = trafficd_ubus_reconnect_timer,
	};
	int t = 2;

	if (config_init_all())
		goto fail;

	/* change objects name before reconnect */
	trafficd_ecos_object.name = sys->cfg.wan_ip;

	if (tbus_reconnect(ctx, &ubus_addr) != UBUS_STATUS_OK)
		goto fail;

	D(SYSTEM, "reconnected to ubus, new id: %08x name:%s\n",
		ctx->local_id, trafficd_ecos_object.name);
	trafficd_ubus_add_listen();
	trafficd_ubus_add_fd();
	trafficd_config_push();
	sys->assoc_pending = true;
	return;

fail:
	D(SYSTEM, "failed to reconnect, trying again in %d seconds\n", t);
	uloop_timeout_set(&retry, t * 1000);
	return;
}

static void trafficd_ubus_connection_lost(struct ubus_context *ctx)
{
	trafficd_ubus_reconnect_timer(NULL);
}

static int tbus_init(struct sockaddr_in *a)
{
	D(BUS, "connected to %s:%d\n", inet_ntoa(a->sin_addr), ntohs(a->sin_port));
	while(!(ctx = tbus_connect(a) )){
		dlog("failed to connect, trying again in 5 seconds \n");

#ifdef __ECOS
		cyg_thread_delay(1000);
#else
		sleep(10);
#endif
	}
	D(BUS, "connected as 0x%08x sys->tbus_ctx = 0x%08x\n", ctx->local_id, ctx);
	ctx->connection_lost = trafficd_ubus_connection_lost;
	sys->tbus_ctx = ctx;
	memset(&listener, 0, sizeof(listener));
	trafficd_ubus_add_listen();
	trafficd_ubus_add_fd();
	trafficd_config_push();

	trafficd_add_object(&trafficd_ecos_object);
	return 0;
}

int trafficd_tbus_done(){
	if(ctx){
		tbus_free(ctx);
		ctx = NULL;
	}
	return 0;
}


int trafficd_tbus_init(){

	memset(&ubus_addr, 0, sizeof(ubus_addr));
	ubus_addr.sin_port = htons(sys->cfg.tbus_listen_port);
	ubus_addr.sin_family = AF_INET;

	memset(&recv_file, 0, sizeof(recv_file));
	recv_file.buff = NULL;
	recv_file.timeout.cb = recv_file_timeout_cb;

	trafficd_ecos_object.name = sys->cfg.wan_ip;

	sys->tbus_ctx = NULL;

	D(BUS, "ap mode, tbus_init()\n");
	/* connect to lan_gw tbusd */
	if ( sys->cfg.lan_gw &&
			!inet_aton(sys->cfg.lan_gw,
				(struct in_addr *) &ubus_addr.sin_addr.s_addr)) {
		elog("bad IP address format\n");
		return -1;
	}

    write_flsh_cfg_fwm_off = flsh_cfg_fwm_off;
    FirstImageSegment = 1;

	return tbus_init(&ubus_addr);
}



