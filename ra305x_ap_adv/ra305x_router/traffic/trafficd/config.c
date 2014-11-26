/*
 * trafficd/config.h
 * yubo@xiaomi.com
 * 2014-10-14
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>


#include "trafficd.h"


static struct uloop_timeout config_loop;



int config_init_all(void)
{
	struct trafficd_cfg *cfg;

	cfg = &sys->cfg;

	cfg->version = TRAFFICD_VERSION;
	cfg->hw_looptime = TRAFFICD_HW_LOOP_TIME;
	cfg->ip_looptime = TRAFFICD_IP_LOOP_TIME;
	cfg->br_looptime = TRAFFICD_BR_LOOP_TIME;
	sys->assoc_pending = true;
	cfg->is_wifiap = true;
	cfg->hw_sizelimit = TRAFFICD_HW_SIZELIMIT;
	cfg->hw_recycle_percent = TRAFFICD_HW_RECYCLE_PERCENT;
	cfg->hw_recycle = cfg->hw_sizelimit * 100 / cfg->hw_recycle_percent;
	cfg->hw_recycle = cfg->hw_recycle > 1 ? cfg->hw_recycle : 1;
	strncpy(sys->ap_hw, "00:1E:2A:A8:49:32", IPAMAXLEN);
	strncpy(cfg->lan_gw, TBUS_SERVER_ADDR, IPAMAXLEN);
	strncpy(cfg->tbus_listen_event, "trafficd", IPAMAXLEN);

	cfg->tbus_listen_port = TRAFFICD_LISTEN_PORT;

	return 0;
}

static void config_alive(struct uloop_timeout *t)
{
	int ret = 0;
	D(CONF, "enterfunction get gateway\n");

	if(ret)
		uloop_timeout_set(t, 2000);

}



int config_init_alive(void)
{
	memset(&config_loop, 0, sizeof(config_loop));
	config_loop.cb = config_alive;
	config_alive(&config_loop);
	return 0;
}


