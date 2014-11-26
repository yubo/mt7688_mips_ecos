/*
 *	Wireless Tools
 *
 *		Jean II - HPL 99->04
 *
 * Main code for "iwevent". This listent for wireless events on rtnetlink.
 * You need to link this code against "iwcommon.c" and "-lm".
 *
 * Part of this code is from Alexey Kuznetsov, part is from Casey Carter,
 * I've just put the pieces together...
 * By the way, if you know a way to remove the root restrictions, tell me
 * about it...
 *
 * This file is released under the GPL license.
 *     Copyright (c) 1997-2004 Jean Tourrilhes <jt@hpl.hp.com>
 */

/*
 * yubo@xiaomi.com
 * 2014-09-12
 */

#include <sys/socket.h>

#include "trafficd.h"
#include "ubus.h"
#include "hw.h"
#include "system.h"

struct trafficd_system_data {
	struct uloop_timeout timeout_mat;
} *sd;

static void update_mat_table()
{
	char line[200], ip[100], hw[100];
	int num;
	struct hw_node *hw_node;
	struct ip_node *ip_node;
	FILE *fp;


	/* Open the PROCps kernel table. */
	if ((fp = fopen(PROC_MAT_TABLE_FILE, "r")) == NULL) {
		D(SYSTEM, "fopen %s error\n", PROC_MAT_TABLE_FILE);
		return;
	}

	for (; fgets(line, sizeof(line), fp);) {
		num = sscanf(line, "%100s %100s\n",
				ip, hw);
		if (num < 2)
			break;
		upper_nstring(hw, HWAMAXLEN);

		hw_node = trafficd_hw_get(hw, true);
		ip_node = trafficd_ip_get(ip, true);
		if(hw_node && ip_node &&
				ip_node->hw != hw_node){
			ip_node->hw = hw_node;
			list_del(&ip_node->list);
			list_add(&ip_node->list, &hw_node->ip_list);
		}
	}
	fclose(fp);

}


static void mat_loop_cb(struct uloop_timeout *timeout)
{
	void *c, *t;
	int i;
	struct hw_node *hw_node;
	struct ip_node *ip_node;
	char buf[16];

	TR_REFRESH_TIME();
	update_mat_table();

	blob_buf_init(&b1, 0);
	blobmsg_add_string(&b1, "hw", sys->ap_hw);
	c = blobmsg_open_array(&b1, "mat");
	avl_for_each_element(sys->hd->hws, hw_node, avl) {
//		if(hw_is_local(hw_node) || sys->bd->seq != hw_node->br_seq)
//			continue;

		if(strncmp(hw_node->ifname,"wl", 2))
			continue;

		if(hw_node->assoc){
			if(hw_node->ip_list.next != &hw_node->ip_list){ /* not empty */
				list_for_each_entry(ip_node, &hw_node->ip_list, list){
					t = blobmsg_open_table(&b1, "data");
					sprintf(buf, "%u.%u.%u.%u", HIPQUAD(ip_node->ip));
					blobmsg_add_string(&b1, "ip", buf);
					blobmsg_add_string(&b1, "hw", hw_node->hwa);
					blobmsg_close_table(&b1, t);
				}
			}else{
				t = blobmsg_open_table(&b1, "data");
				blobmsg_add_string(&b1, "hw", hw_node->hwa);
				blobmsg_close_table(&b1, t);
			}
		}
	}

	blobmsg_close_array(&b1, c);
	ubus_send_event(sys->tbus_ctx, sys->cfg.tbus_listen_event, b1.head);
	if (sys->assoc_pending){
		trafficd_hw_update_assoclist();
	}
	D(BUS, "send msg and wait %d(s)\n", TRAFFICD_WIFIAP_LOOP_TIME / 1000);
	uloop_timeout_set(&sd->timeout_mat, TRAFFICD_WIFIAP_LOOP_TIME);
}


void system_assoclist_update()
{
	//_system_assoclist_update(sys->cfg.guest_2g);
}

int system_init()
{

	if(!sys->cfg.is_router && sys->tbus_ctx){
		sd = calloc(1, sizeof(* sd));
		if (!sd)
			return -1;
		sd->timeout_mat.cb = mat_loop_cb;
		uloop_timeout_set(&sd->timeout_mat, TRAFFICD_WIFIAP_LOOP_TIME);
	}

	return 0;
}

int system_done(void){
	return 0;
}