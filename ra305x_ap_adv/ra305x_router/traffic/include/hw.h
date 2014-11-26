/*
 * yubo@xiaomi.com
 * 2014-08-21
 */
#ifndef __TRAFFICD_HW_H
#define __TRAFFICD_HW_H


#include <netinet/in.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "trafficd.h"
#include "avl.h"
#include "safe_list.h"
#include "system.h"




struct ip_node;

struct hw_log_data {
	time_t up_time;
	time_t down_time;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
};

struct hw_log {
	char hwa[HWAMAXLEN];
	uint8_t index;
	struct hw_log_data data[TRAFFICD_HW_LOGSIZE];
};

struct hw_node {
	struct list_head list;
	struct list_head ip_list;	/* for ip_node */
	struct list_head child_list;
	struct avl_node avl;
	struct hw_node *parent;
	uint32_t seq;
	double uptime;
	char hwa[HWAMAXLEN];
	char ifname[IFNAMSIZ];
	char ap_ifname[IFNAMSIZ];
	unsigned char is_local;
	unsigned char is_ap;
	unsigned char assoc;
	struct timeval ageing_timer_value;
	uint32_t br_seq;
	double br_uptime;
	double point_time;
	uint64_t point_rx;
	uint64_t point_tx;
	struct hw_log log;
};

struct trafficd_hw_data {
	struct uloop_timeout timeout;
	struct avl_tree *hws;
	uint32_t seq;
};

struct arp_entry {
	__be32 ip;
	int flags;
	int type;
	char mask[100];
	char ipa[100];
	char dev[100];
	char hwa[100];
};

void trafficd_hw_iwevent(struct trafficd_iwevent *ev, struct hw_node *speaker);
void trafficd_hw_dump_status(struct blob_buf *b, struct hw_node *hw_node,
	int show_tree, int show_all, int show_log, int show_debug);
struct hw_node * trafficd_hw_get(char *hwa, int create);
void trafficd_hw_update_hostname(void);
void trafficd_hw_update_assoclist(void);
struct trafficd_hw_data * trafficd_hw_init(void);
void trafficd_hw_done(void);
void trafficd_hw_free(struct hw_node *hw_node);
void trafficd_hw_clean(void);
void trafficd_hw_log_save(void);
void trafficd_hw_update_ap(struct hw_node *hw_node, struct ip_node *ip_node);
void trafficd_hw_update_ap_sta(struct ip_node *ap, char *hw, char *ip);
#endif
