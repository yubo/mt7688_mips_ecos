/*
 * trafficd
 * yubo@xiaomi.com
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <time.h>

#include "trafficd.h"
#include "ubus.h"
#include "system.h"


unsigned int debug_mask = 0x0;

#define TRAFFIC_SIGHUP      1
#define TRAFFIC_SHUTDOWN    2

#define TRAFFIC_PRIORITY    9
#define TRAFFIC_STACKSIZE 1024
static char traffic_stack[TRAFFIC_STACKSIZE];

cyg_handle_t traffic_handle;
cyg_thread traffic_thread;




static int log_level = DEFAULT_LOG_LEVEL;
static const int log_class[] = {
	[L_CRIT] = LOG_CRIT,
	[L_ERR] = LOG_ERR,
	[L_WARNING] = LOG_WARNING,
	[L_NOTICE] = LOG_NOTICE,
	[L_INFO] = LOG_INFO,
	[L_DEBUG] = LOG_DEBUG
};

struct trafficd_sys *sys = NULL;

void trafficd_log_message(int priority, const char *format, ...)
{
	va_list vl;

	if (priority > log_level)
		return;

	va_start(vl, format);
	diag_printf(format, vl);
	va_end(vl);
}


static void
trafficd_handle_signal_cb(int signo)
{
	uloop_end();
}



static int traffic_main(void)
{
	int ch, ret;
	ret = 0;

	if(sys){
		elog("sys already malloc\n");
		return 1;
	}
	if(!(sys = calloc(1, sizeof(*sys)))){
		elog("Failed to initialize sys\n");
		return 1;
	}
	TR_REFRESH_TIME();

	sys->bd = NULL;
	sys->id = NULL;
	sys->hd = NULL;

	debug_mask = 256;
	sys->cfg.use_syslog = false;


	if(config_init_all()){
		elog("failed to config_init_all\n");
		return 1;
	}

	D(BUS, "hello\n");

	uloop_init();

	if (trafficd_tbus_init()) {
		elog("Failed to trafficd_tbus_init\n");
		ret = -1;
		goto out;
	}

	if (system_init()) {
		elog("Failed to initialize system control\n");
		ret = -1;
		goto out;
	}

	sys->id = trafficd_ip_init();
	sys->hd = trafficd_hw_init();
	sys->bd = trafficd_br_init();
	if (!(sys->id && sys->hd &&
			sys->bd)){
		ret = -1;
		goto out;
	}

	config_init_alive();
	trafficd_setup_signals();
	uloop_run();
	uloop_done();

	trafficd_br_done();
	trafficd_hw_done();
	trafficd_ip_done();
	trafficd_tbus_done();


	free(sys);
	sys = NULL;

	return ret;

out:

	uloop_done();

	free(sys);
	sys = NULL;
	return ret;
}





static cyg_mbox traffic_mbox_obj;
static cyg_handle_t traffic_mbox_id;

static int recv_infaces_num = 0;

//TRAFFICSERVER ubus_servers[3];
static int traffic_servers_num = 0;

//static TRAFFICSERVER *activeserver;
static int traffic_running = 0;
static int traffic_seq = 0;


void TRAFFIC_daemon(cyg_addrword_t data)
{
	//TRAFFICSERVER *new_active_srv;
	//int port = NAMESERVER_PORT;
	int first_loop	= 1;
	int recv_len	= 0;
	int i, cmd, traffic_sleep, ret;
	struct timeval	tv = {1, 0};
	time_t	now;
	//char	packet[PACKETSZ+MAXDNAME+RRFIXEDSZ];

	TRAFFIC_DBGPRINT(TRAFFIC_DEBUG_OFF, "%s\n", __FUNCTION__);
#if 0
	ret = trafficMasqstart(port);
	if (ret < 0)
	{
		TRAFFIC_DBGPRINT(TRAFFIC_DEBUG_OFF, "%s(): Line%d failed to start up\n", __FUNCTION__, __LINE__);
		return;
	}
	activeserver = &traffic_servers[0];
#endif
	traffic_running = 1;
	traffic_sleep = 0;
	while (traffic_running)
	{
		int ready, maxfd = 0;
		//fd_set rset;
		//TRAFFICHEADER *header;

		if ((cmd = (int )cyg_mbox_tryget(traffic_mbox_id)) != 0) {
			switch(cmd) {
				case TRAFFIC_SIGHUP:
					D(SYSTEM, "start up\n");
#if 0
					ret = trafficMasqstart(port);
					if (ret < 0) {
						D(TRAFFIC_DEBUG_OFF, "%s(): Line%d failed to start up\n", __FUNCTION__, __LINE__);
						traffic_running = 0;
						return;
					}
					traffic_sleep = 0;
#endif
					break;

				case TRAFFIC_SHUTDOWN: // do we need to return ??
					D(SYSTEM, "shutdown\n");
					//trafficstop();
					//traffic_sleep = 1;
					break;

				default:
					break;
			}
		}

		if (traffic_sleep) {
			cyg_thread_delay(100);
			continue;
		}

		cyg_thread_delay(100);
		traffic_seq++;
		/* do init stuff only first time round. */
#if 0
		if (first_loop) {
			first_loop = 0;
			ready = 0;
		} else {
			FD_ZERO(&rset);
			maxfd = 0;
			for (i=0; i<traffic_servers_num; i++)
			{
				if (traffic_servers[i].fd > 0)
				{
					FD_SET(traffic_servers[i].fd, &rset);
					if (traffic_servers[i].fd > maxfd)
						maxfd = traffic_servers[i].fd;
				}
			}

			for (i=0; i<recv_infaces_num; i++)
			{
				if (recv_infaces[i].fd > 0)
				{
					FD_SET(recv_infaces[i].fd, &rset);
					if (recv_infaces[i].fd > maxfd)
						maxfd = recv_infaces[i].fd;
				}
			}

			ready = select(maxfd+1, &rset, NULL, NULL, &tv); /* NONBLOCKING */
			if(ready <= 0)
			{
				if (TRAFFICDebugLevel > TRAFFIC_DEBUG_OFF) {
					TRAFFIC_DBGPRINT(TRAFFIC_DEBUG_ERROR, "%s(): select() return %d\n", __FUNCTION__, ready);
					cyg_thread_delay(100);
				} else
					cyg_thread_delay(2);

				continue;
			}
		}

		now = time(NULL);
		if (ready == 0)
			continue; /* no sockets ready */


		// check traffic query from querist
		for (i=0; i<recv_infaces_num; i++)
		{
			if (recv_infaces[i].fd > 0)
			{
				if (FD_ISSET(recv_infaces[i].fd, &rset))
				{
					// request packet, deal with query
					MYSOCKADDR queryaddr;
					size_t queryaddrlen = sizeof(queryaddr);

					FD_CLR(recv_infaces[i].fd, &rset);
					recv_len = recvfrom(recv_infaces[i].fd, packet, PACKETSZ, 0, &queryaddr.sa, &queryaddrlen);
					queryaddr.sa.sa_family = recv_infaces[i].addr.sa.sa_family;
					header = (TRAFFICHEADER *)packet;
					if (recv_len >= (int)sizeof(TRAFFICHEADER) && !header->qr)
					{
						activeserver = trafficMasqprocessquery(recv_infaces[i].fd, &queryaddr, header, recv_len,
								activeserver, now);
					}
				}
			}
		}

		// check traffic reply from traffic server
		for (i=0; i<traffic_servers_num; i++)
		{
			if (traffic_servers[i].fd > 0)
			{
				if (FD_ISSET(traffic_servers[i].fd, &rset))
				{
					FD_CLR(traffic_servers[i].fd, &rset);
					recv_len = recvfrom(traffic_servers[i].fd, packet, PACKETSZ, 0, NULL, NULL);
					new_active_srv = trafficMasqprocessreply(traffic_servers[i].fd, packet, recv_len, now);
					if (new_active_srv != NULL)
						activeserver = new_active_srv;
				}
			}
		}
#endif
	}
}

void TRAFFIC_init(void)
{
	int val=0;

	CFG_get(CFG_TRAFFIC_EN, &val);
	if(val)
	{
		cyg_mbox_create( &traffic_mbox_id, &traffic_mbox_obj );
		cyg_thread_create(TRAFFIC_PRIORITY, &TRAFFIC_daemon, 0, "TRAFFIC_daemon",
				&traffic_stack, TRAFFIC_STACKSIZE,
				&traffic_handle, &traffic_thread);
		cyg_thread_resume(traffic_handle);
	}

}



//------------------------------------------------------------------------------
// FUNCTION
//
//
// DESCRIPTION
//
//
// PARAMETERS
//
//
// RETURN
//
//
//------------------------------------------------------------------------------
#ifdef CONFIG_CLI_NET_CMD
int traffic_cmd(int argc, char* argv[])
{

#if 0
	extern TRAFFIC_PORTMAP *traffic_pmlist;
	extern TRAFFIC_CONTEXT traffic_context;

	TRAFFIC_CONTEXT *context = &traffic_context;
	TRAFFIC_SERVICE *service = traffic_service_table;
	TRAFFIC_SUBSCRIBER	*subscriber;

	TRAFFIC_INTERFACE *ifp;

	if (argc==0 || !strcmp(argv[0], "show") )
	{
		printf("# Interfaces\n");
		for (ifp=context->iflist; ifp; ifp=ifp->next)
		{
			printf("%10s %6d\n", ifp->ifname, ifp->http_sock);
		}

		printf("\n");

		if (traffic_pmlist==0)
		{
			printf("no port map!\n");
		}
		else
		{
			extern void upp_show_pmap(void);

			upp_show_pmap();
			printf("\n");
#ifdef CONFIG_WPS
			dumpDevCPNodeList();
#endif /* CONFIG_WPS */
		}

		printf("\n");
		printf("# Subscriber service\n");
		cyg_mutex_lock(&traffic_service_table_mutex);
		for (service = traffic_service_table; service->event_url; service++)
		{
			subscriber = service->subscribers;

			while (subscriber)
			{
				printf("%lu.%lu.%lu.%lu:%d%s %s %u\n",
						(subscriber->ipaddr >> 24) & 0xff,
						(subscriber->ipaddr >> 16) & 0xff,
						(subscriber->ipaddr >> 8) & 0xff,
						subscriber->ipaddr & 0xff,
						subscriber->port,
						subscriber->uri,
						subscriber->sid,
						subscriber->expire_time);

				subscriber = subscriber->next;
			}
		}
		cyg_mutex_unlock(&traffic_service_table_mutex);
	}
	else if (( argc == 2 ) && (!strcmp(argv[0], "debug" )))
	{
		int level = 0;

		level = atoi(argv[1]);
		if (level > 0)
			traffic_debug_level = level;
		else
			traffic_debug_level = RT_DBG_OFF;


		DBGPRINTF(RT_DBG_OFF, "TRAFFICD debug level = %d\n", traffic_debug_level);
	}
	else
		goto err1;

	return 0;
#endif

err1:
	printf("traffic hello world! set[%d]\n", traffic_seq);
	return 0;
}

#endif


