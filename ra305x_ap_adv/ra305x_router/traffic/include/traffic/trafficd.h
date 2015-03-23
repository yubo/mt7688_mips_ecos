/*
 * yubo@xiaomi.com
 * 2014-08-21
 */
#ifndef __trafficd_H
#define __trafficd_H

#ifndef __ECOS
#include <stdint.h>
#else
#include <sys/bsdtypes.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdbool.h>
#include <net/if.h>
#include <sys/time.h>



#include "libubox/uloop.h"
#include "libubox/blobmsg.h"
#include "traffic/utils.h"
#include "traffic/libubus.h"

#ifdef __ECOS
#define gettimeofday(a, b) microtime(a)
#endif

#define T_NONBLOCK 1
#define TRAFFICD_VERSION 1

#ifdef _DEBUG
#define DEFAULT_LOG_LEVEL L_DEBUG
#define DEFAULT_DEBUG_MASK 1
#else
#define DEFAULT_LOG_LEVEL 0
#define DEFAULT_DEBUG_MASK 0
#endif

#define PROC_MAT_TABLE_FILE	"/proc/miwifi_mat_table"
#define UBUS_UNIX_SOCKET    "/var/run/ubus.sock"

#define HWAMAXLEN 18
#define IPAMAXLEN 16
#define PORTMAXLEN 6
#define DEVMAXLEN 16
#define POINTSMAXLEN 1024
#define HOSTNAMSIZ 32
#define PATHMAXLEN 256
#define DEVIDSIZ	40

#define TRAFFICD_KV_SIZELIMIT		256
#define TRAFFICD_HW_SIZELIMIT		64
#define TRAFFICD_HW_LOGSIZE			10
#define TRAFFICD_HW_RECYCLE_PERCENT	10

#define TRAFFICD_IF_AP			"ra0"
#define TRAFFICD_IF_2G			"wl1"
#define TRAFFICD_IF_5G			"wl0"
#define TRAFFICD_GUEST_2G		"wl1.2"

#define TRAFFICD_HW_LOOP_TIME           2000
#define TRAFFICD_IP_LOOP_TIME           2000
#define TRAFFICD_WIFIAP_LOOP_TIME		10000
#define TRAFFICD_INIT_LOOP_TIME			2000
#define TRAFFICD_INIT_TIMEOUT			5000
#define TRAFFICD_SIGNAL_LOOP_TIME		1000
#define TRAFFICD_PUSH_CFG_RETRY			5
#define TRAFFICD_PUSH_CFG_LOOP_TIME		10000

#define TRAFFICD_CLI_TIMEOUT1			(TRAFFICD_WIFIAP_LOOP_TIME * 3 / 1000)
#define TRAFFICD_CLI_TIMEOUT2			(TRAFFICD_WIFIAP_LOOP_TIME * 6 / 1000)

#define WAN_RATE_SIZE 50

#define IPACCOUNT_LAN_TABLE_NAME "lan"

#define TBUS_SERVER_ADDR "192.168.31.1"
#define TBUS_LISENT_EVENT "trafficd"
#define TRAFFICD_LISTEN_PORT			784
#define TRAFFICD_LISTEN_ADDR			0



struct trafficd_hw_data;
struct trafficd_hw_data;
struct trafficd_point_data;
struct trafficd_ip_data;
struct trafficd_br_data;
struct trafficd_dev_data;


struct trafficd_cfg{
	bool is_router;
	bool is_wifiap;
	bool br_lan_on;
	bool br_guest_on;
	bool if_2g_on;
	bool if_5g_on;
	bool guest_2g_on;
	bool use_syslog;
	char br_lan[IFNAMSIZ];
	char br_guest[IFNAMSIZ];
	char if_2g[IFNAMSIZ];
	char if_5g[IFNAMSIZ];
	char guest_2g[IFNAMSIZ];
	uint32_t ap_flags;
	uint32_t hw_sizelimit;
	uint32_t hw_looptime;
	uint32_t br_looptime;
	uint32_t ip_looptime;
	uint32_t trafficd_version;
	uint32_t hw_recycle_percent;
	uint32_t hw_recycle;
	char log_file[PATHMAXLEN];
	char ubus_socket[PATHMAXLEN];
	char *tbus_listen_address;
	uint16_t tbus_listen_port;
	char tbus_listen_event[PATHMAXLEN];
	char lan_gw[IPAMAXLEN];
	char wan_gw[IPAMAXLEN];
	char wan_ip[IPAMAXLEN];
	char router_name[HOSTNAMSIZ];
	char device_id[DEVIDSIZ];
	char version[HOSTNAMSIZ];
	char *description;

};


struct trafficd_sys{
	double uptime;
	struct timeval tv;
	uint32_t hw_size;
	struct trafficd_cfg cfg;
	struct trafficd_hw_data *hd;
	struct trafficd_ip_data *id;
	struct trafficd_br_data *bd;
	struct ubus_context *tbus_ctx;
	char ap_hw[HWAMAXLEN];
	bool assoc_pending;
#ifdef HWNAT
	bool hwnat_on;
#endif
	bool init_mode;
};



extern struct trafficd_sys *sys;
int config_init_all(void);
int trafficd_config_push(void);
int config_done(void);


struct trafficd_iwevent
{
	char hwa[HWAMAXLEN];
	char ifname[IFNAMSIZ];
	int event_type;
};

struct trafficd_ap_iwevent
{
	struct trafficd_iwevent *ev;
	struct hw_node *speaker;
};


extern const char *resolv_conf;
extern char *hotplug_cmd_path;
extern unsigned int debug_mask;

enum {
	AP_LANMODE	= 0,
	AP_WIFIMODE	= 1,
};

enum {
	L_CRIT,
	L_ERR,
	L_WARNING,
	L_NOTICE,
	L_INFO,
	L_DEBUG
};

enum {
	P_NONE = 0,
	P_INSTANT
};

enum {
	DEBUG_SYSTEM	= 0,// 1
	DEBUG_IP	= 1,	// 2
	DEBUG_HW	= 2,	// 4
	DEBUG_BR	= 3,	// 8
	DEBUG_DEV	= 4,	// 16
	DEBUG_POINT	= 5,	// 32
	DEBUG_EVENT	= 6,	// 64
	DEBUG_CONF	= 7,	// 128
	DEBUG_BUS	= 8,	// 256
};





#define TR_MAX(a, b) ((a) > (b) ? (a) : (b))
#define TR_REFRESH_TIME() do { \
	gettimeofday(&sys->tv, NULL); \
	sys->uptime = get_uptime(NULL, NULL); \
}while (0)



#ifdef DEBUG

#ifdef __ECOS
#define DPRINTF(format, ...) printf( "[traffic]%s(%d): " format, __func__, __LINE__, ## __VA_ARGS__)
#else
#define DPRINTF(format, ...) fprintf(stderr, "%s(%d): " format, __func__, __LINE__, ## __VA_ARGS__)
#endif

#define D(level, format, ...) do { \
		if (debug_mask & (1 << (DEBUG_ ## level))) \
				DPRINTF(format, ##__VA_ARGS__); \
	} while (0)

#else /* not debug */

#define DPRINTF(format, ...) no_debug(0, format, ## __VA_ARGS__)
#define D(level, format, ...) no_debug(DEBUG_ ## level, format, ## __VA_ARGS__)

#endif /* end debug */


#ifdef __ECOS
#define _DPRINTF(format, ...) printf( "[traffic]%s(%d): " format, __func__, __LINE__, ## __VA_ARGS__)
#else
#define _DPRINTF(format, ...) fprintf(stderr, "%s(%d): " format, __func__, __LINE__, ## __VA_ARGS__)
#endif

#define _LOG_LEVEL(level, format, ...) do { \
		if (level <= log_level) \
			_DPRINTF(format, ##__VA_ARGS__); \
	} while (0)
#define dlog(format, ...) _LOG_LEVEL(L_DEBUG, format, ## __VA_ARGS__)
#define nlog(format, ...) _LOG_LEVEL(L_NOTICE, format, ## __VA_ARGS__)
#define elog(format, ...) _LOG_LEVEL(L_ERR, format, ## __VA_ARGS__)


static inline void no_debug(int level, const char *fmt, ...)
{
}

void trafficd_log_message(int priority, const char *format, ...);
void log_points(int instant, const char *format, ...);

struct device;
struct interface;

extern const char *main_path;
extern int log_level;

int trafficd_router2cli_msg_handle(const char *type, struct blob_attr *msg);

#endif
