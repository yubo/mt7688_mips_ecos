/*
 * yubo@xiaomi.com
 * 2014-08-20
 */
#ifndef __TRAFFICD_IP_H
#define __TRAFFICD_IP_H

#include <netinet/in.h>
#include <sys/time.h>

#include "avl.h"
#include "safe_list.h"
#include "trafficd.h"


struct ip_node {
	struct list_head list;
	struct avl_node avl;
	//todo add mac head list
	//struct head_list mac;
	struct hw_node *hw;
	char hostname_dhcp[HOSTNAMSIZ];
	uint32_t   seq;
	__be32   ip;
	uint32_t   rx_rate;
	uint32_t   tx_rate;
	uint32_t   max_rx_rate;
	uint32_t   max_tx_rate;
	double     uptime;
	uint64_t   rx_bytes;
	uint64_t   tx_bytes;
	uint32_t   src_bytes_delta;
	uint32_t   dst_bytes_delta;
};

struct trafficd_ip_data {
	struct uloop_timeout timeout;
	uint32_t seq;
	struct avl_tree *ips;
	double uptime;
	double delta_time;
};


void trafficd_ip_dump_status(struct blob_buf *b, struct ip_node *ip_node, int debug);
struct trafficd_ip_data * trafficd_ip_init(void);
void trafficd_ip_done(void);
struct ip_node * _trafficd_ip_get(__be32 ip, int create);
struct ip_node * trafficd_ip_get(char *ipaddr, int create);
void ip_reset_counter(struct ip_node *ip_node);
void trafficd_ip_free(struct ip_node *ip_node);
void trafficd_ip_update_hostname(void);

#endif
