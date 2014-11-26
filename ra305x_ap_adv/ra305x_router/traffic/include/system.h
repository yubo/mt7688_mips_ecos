/*
 * yubo@xiaomi.com
 * 2014-09-09
 */
#ifndef __TRAFFICD_SYSTEM_H
#define __TRAFFICD_SYSTEM_H

#define TRAFFICD_DISASSOC_EVENT 0
#define TRAFFICD_ASSOC_EVENT 1


int system_init(void);
int system_done(void);
void system_assoclist_update(void);

struct trafficd_iwevent
{
	char hwa[HWAMAXLEN];
	char ifname[IFNAMSIZ];
	int event_type;
};

#endif