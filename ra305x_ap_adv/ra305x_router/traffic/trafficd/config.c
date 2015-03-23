/*
 * trafficd/config.h
 * yubo@xiaomi.com
 * 2014-10-14
 */

#ifdef __ECOS
#include <http_proc.h>
#include <http_conf.h>
#endif

#if MODULE_SYSLOG
#include <eventlog.h>
#endif

#include "traffic/ubus.h"
#include "traffic/trafficd.h"
#include "nvram.h"

struct _config_loop{
	struct uloop_timeout push_cfg;
	int push_seq;
} ;

struct _config_loop * config_loop = NULL;



int config_init_all(void)
{
	char *buffer = NULL;
	struct trafficd_cfg *cfg;
	cfg = &sys->cfg;


#ifdef __ECOS
	int val;

	CFG_get(CFG_TRAFFIC_INIT, &val);
	sys->init_mode = val ? 1 : 0;

	//get wan gw
	buffer =  NSTR(primary_wan_ip_set[0].gw_ip);
	if(!strcmp(buffer, "0.0.0.0"))
		goto fail;
	strncpy(cfg->lan_gw, buffer, IPAMAXLEN);

	//get wan ip
	buffer =  NSTR(primary_wan_ip_set[0].ip);
	strncpy(cfg->wan_ip, buffer, IPAMAXLEN);


	//get wan mac
	buffer = ESTR(SYS_wan_mac);
	strncpy(sys->ap_hw, (char *)buffer, HWAMAXLEN);
	D(SYSTEM, "get apcli0 mac [%s]\n", buffer);
#else
	sys->init_mode = 0;
	strncpy(cfg->lan_gw, "127.0.0.1", IPAMAXLEN);
	strncpy(cfg->wan_ip, "192.168.31.27", IPAMAXLEN);
	strncpy(sys->ap_hw, "00:00:00:00:00:00", HWAMAXLEN);
#endif

	cfg->trafficd_version = TRAFFICD_VERSION;
	sys->assoc_pending = true;
	cfg->is_wifiap = true;
	cfg->hw_sizelimit = TRAFFICD_HW_SIZELIMIT;
	cfg->hw_recycle_percent = TRAFFICD_HW_RECYCLE_PERCENT;
	cfg->hw_recycle = cfg->hw_sizelimit * 100 / cfg->hw_recycle_percent;
	cfg->hw_recycle = cfg->hw_recycle > 1 ? cfg->hw_recycle : 1;
	strncpy(cfg->tbus_listen_event, "trafficd", HOSTNAMSIZ);
	cfg->tbus_listen_port = TRAFFICD_LISTEN_PORT;

	cfg->ap_flags = (1 << AP_WIFIMODE);
	strncpy((char *)cfg->router_name, "ecos_router_name", HOSTNAMSIZ);
	strncpy((char *)cfg->device_id, "ecos_device_id", HOSTNAMSIZ);
	strncpy((char *)cfg->version, "ecos_version", HOSTNAMSIZ);
	cfg->description = strdup("ecos_description");
	return 0;

fail:
	return 1;
}

static void _config_push(struct uloop_timeout *t){

	blob_buf_init(&traffic_b, 0);
	blobmsg_add_u32(&traffic_b, "ap_flags", sys->cfg.ap_flags);
	if(strlen((char *)sys->cfg.router_name))
		blobmsg_add_string(&traffic_b, "router_name", (char *)sys->cfg.router_name);
	if(strlen((char *)sys->cfg.device_id))
		blobmsg_add_string(&traffic_b, "device_id", (char *)sys->cfg.device_id);
	if(strlen((char *)sys->cfg.version))
		blobmsg_add_string(&traffic_b, "version", (char *)nvram_get(UBOOT_NVRAM, "ecos_version"));
//		blobmsg_add_string(&traffic_b, "version", (char *)sys->cfg.version);
	if(strlen(sys->cfg.description))
		blobmsg_add_string(&traffic_b, "description", sys->cfg.description);

	ubus_send_event(sys->tbus_ctx, sys->cfg.tbus_listen_event, traffic_b.head);

	if(config_loop->push_seq++ < TRAFFICD_PUSH_CFG_RETRY){
		D(BUS, "[%d]push config and wait %d(s)\n", config_loop->push_seq, TRAFFICD_PUSH_CFG_LOOP_TIME / 1000);
		uloop_timeout_set(t, TRAFFICD_PUSH_CFG_LOOP_TIME);
	}
}

int trafficd_config_push(void)
{
	config_init_all();
	if(!config_loop){
		config_loop = calloc(1, sizeof(* config_loop));
		if (!config_loop){
			dlog("1\n");
			return 1;
		}
	}
	config_loop->push_cfg.cb = _config_push;
	config_loop->push_seq = 0;
	_config_push(&config_loop->push_cfg);
	return 0;
}



int config_done(void)
{
	if(sys->cfg.description){
		free(sys->cfg.description);
		sys->cfg.description = NULL;
	}
}
