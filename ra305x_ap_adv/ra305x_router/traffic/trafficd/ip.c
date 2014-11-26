/*
 * yubo@xiaomi.com
 * 2014-08-20
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#ifdef linux
#include <netinet/ether.h>
#endif

#include "trafficd.h"
#include "ip.h"
#include "utils.h"

static struct avl_tree ips;
static struct trafficd_ip_data *id;


static struct ip_node * ip_create_default(const __be32 ip);
static void ip_delete(struct ip_node *ip_node);
static void ip_cleanup(struct ip_node *ip_node);
static struct ip_node * ip_update(struct ip_acc_ip_entry *ip_entry);



static struct ip_node * ip_create_default(const __be32 ip)
{
	struct ip_node *ip_node;
	int ret;

	D(IP, "Create ip node '%u.%u.%u.%u'\n",  HIPQUAD(ip));
	ip_node = calloc(1, sizeof(*ip_node));
	if (!ip_node)
		return NULL;

	INIT_LIST_HEAD(&ip_node->list);

	ip_node->avl.key = &ip_node->ip;
	ip_node->ip = ip;
	ip_node->uptime = id->uptime;
	ip_node->hw = NULL;
	ret = avl_insert(&ips, &ip_node->avl);
	if (ret < 0){
		free(ip_node);
		return NULL;
	}
	return ip_node;
}




struct ip_node * _trafficd_ip_get(__be32 ip, int create)
{
	struct ip_node *ip_node;

	ip_node = avl_find_element(&ips, &ip, ip_node, avl);
	if (ip_node) {
		return ip_node;
	}

	if (!create)
		return NULL;

	return ip_create_default(ip);
}

struct ip_node * trafficd_ip_get(char *ipaddr, int create)
{
	__be32 ip;

	D(IP, "ipaddr %s\n", ipaddr);
	if(ipaddr){
		if(inet_pton(AF_INET, ipaddr, &ip) > 0)
			return _trafficd_ip_get(ntohl(ip), create);
	}
	return NULL;
}

static void ip_delete(struct ip_node *ip_node)
{
	if (!ip_node->avl.key)
		return;

	D(IP, "Delete ip node '%u.%u.%u.%u'  from list\n",  HIPQUAD(ip_node->ip));
	avl_delete(&ips, &ip_node->avl);
	ip_node->avl.key = NULL;

}

static void ip_cleanup(struct ip_node *ip_node)
{
	D(IP, "Clean up ip '%u.%u.%u.%u'  from list\n", HIPQUAD(ip_node->ip));
	list_del(&ip_node->list);
	ip_delete(ip_node);
}


void trafficd_ip_free(struct ip_node *ip_node)
{
	ip_cleanup(ip_node);
	free(ip_node);
}


void ip_reset_counter(struct ip_node *ip_node)
{
	ip_node->rx_bytes = 0;
	ip_node->tx_bytes = 0;
	ip_node->dst_bytes_delta = 0;
	ip_node->src_bytes_delta = 0;
	ip_node->rx_rate = 0;
	ip_node->tx_rate = 0;
	ip_node->max_rx_rate = 0;
	ip_node->max_tx_rate = 0;
	ip_node->seq = 0;
	ip_node->uptime = 0;
}



void trafficd_ip_dump_status(struct blob_buf *b, struct ip_node *ip_node, int debug)
{
	void *c;
	char buf[16];
	struct ip_node *ip_node1;

	if (!ip_node) {
		avl_for_each_element(&ips, ip_node1, avl) {
			sprintf(buf, "%u.%u.%u.%u", HIPQUAD(ip_node1->ip));
			c = blobmsg_open_table(b, buf);
			trafficd_ip_dump_status(b, ip_node1, debug);
			blobmsg_close_table(b, c);
		}
		return;
	}

	sprintf(buf, "%u.%u.%u.%u", HIPQUAD(ip_node->ip));
	blobmsg_add_string(b, "ip", buf);
	blobmsg_add_string(b, "hw", ip_node->hw ? ip_node->hw->hwa : "");
	blobmsg_add_u32(b, "ageing_timer", (int)(id->uptime - ip_node->uptime));
	blobmsg_add_u64(b, "rx_bytes", ip_node->rx_bytes);
	blobmsg_add_u64(b, "tx_bytes", ip_node->tx_bytes);
	if (ip_node->seq == id->seq) {
		blobmsg_add_u32(b, "rx_rate", ip_node->rx_rate);
		blobmsg_add_u32(b, "tx_rate", ip_node->tx_rate);
	}else{
		blobmsg_add_u32(b, "rx_rate", 0);
		blobmsg_add_u32(b, "tx_rate", 0);
	}
	blobmsg_add_u32(b, "max_rx_rate", ip_node->max_rx_rate);
	blobmsg_add_u32(b, "max_tx_rate", ip_node->max_tx_rate);
	if (debug){
		blobmsg_add_u32(b, "current_seq",id->seq);
		blobmsg_add_u32(b, "seq", ip_node->seq);
		blobmsg_add_u32(b, "rx_bytes_delta",ip_node->dst_bytes_delta);
		blobmsg_add_u32(b, "tx_bytes_delta",ip_node->src_bytes_delta);
		blobmsg_add_u32(b, "current_uptime",id->uptime);
		blobmsg_add_u32(b, "last_uptime",ip_node->uptime);
	}
}




struct trafficd_ip_data * trafficd_ip_init()
{
	avl_init(&ips, cmp_ip, false, NULL);

	id = calloc(1, sizeof(* id));
	if (!id)
		return NULL;
	id->seq = 0;
	id->ips = &ips;
	return id;
}


void trafficd_ip_done()
{
	struct ip_node *ip_node, *tmp;
	avl_for_each_element_safe(&ips, ip_node, avl, tmp)
		trafficd_ip_free(ip_node);

	if (id)
		free(id);
	id = NULL;
}


