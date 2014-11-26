/*
 * yubo@xiaomi.com
 * 2014-08-28
 */
#ifndef __TRAFFICD_BRIDGE_H
#define __TRAFFICD_BRIDGE_H


#include <netinet/in.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/time.h>


#ifndef __ECOS
#include <linux/if_bridge.h>
#include <linux/sockios.h>
#include <asm/param.h>
#include <sys/fcntl.h>
#else
#include <sys/bsdtypes.h>
#endif


#include "avl.h"
#include "safe_list.h"
#include "hw.h"
#include "config.h"

#define MAX_PORTS   1024
#define CHUNK 128


struct trafficd_br_data {
	struct uloop_timeout timeout;
	uint32_t seq;
	double uptime;
	double delta_time;
};

struct fdb_entry
{
	char hwa[HWAMAXLEN];
	char ifname[IFNAMSIZ];
	u_int8_t mac_addr[6];
	u_int16_t port_no;
	unsigned char is_local;
	struct timeval ageing_timer_value;
};

struct trafficd_br_data * trafficd_br_init(void);
void trafficd_br_done(void);


#endif
