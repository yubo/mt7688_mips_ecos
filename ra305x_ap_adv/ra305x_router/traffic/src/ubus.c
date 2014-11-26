#include <sys/param.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/nameser.h>
#include <time.h>


#include <cfg_def.h>
#include <cfg_net.h>
#include <cfg_dns.h>
#include <sys_status.h>

#define UBUS_SIGHUP      1
#define UBUS_SHUTDOWN    2

#define UBUS_PRIORITY    9
#define UBUS_STACKSIZE 1024
static char ubus_stack[UBUS_STACKSIZE];

cyg_handle_t ubus_handle;
cyg_thread ubus_thread;

static cyg_mbox ubus_mbox_obj;
static cyg_handle_t ubus_mbox_id;

static int recv_infaces_num = 0;

static int ubus_servers_num = 0;

static int ubus_running = 0;
static int ubus_seq = 0;

#define UBUS_DBGPRINT(Level, fmt, args...) \
	diag_printf( fmt, ## args );

void UBUS_daemon(cyg_addrword_t data)
{
	//UBUSSERVER *new_active_srv;
	//int port = NAMESERVER_PORT;
	int first_loop	= 1;
	int recv_len	= 0;
	int i, cmd, ubus_sleep, ret;
	struct timeval	tv = {1, 0};
	time_t	now;
	//char	packet[PACKETSZ+MAXDNAME+RRFIXEDSZ];

	UBUS_DBGPRINT(UBUS_DEBUG_OFF, "%s\n", __FUNCTION__);
#if 0
	ret = ubusMasqstart(port);
	if (ret < 0)
	{
		UBUS_DBGPRINT(UBUS_DEBUG_OFF, "%s(): Line%d failed to start up\n", __FUNCTION__, __LINE__);
		return;
	}
	activeserver = &ubus_servers[0];
#endif
	ubus_running = 1;
	ubus_sleep = 0;
	while (ubus_running)
	{
		int ready, maxfd = 0;
		//fd_set rset;
		//UBUSHEADER *header;

		if ((cmd = (int )cyg_mbox_tryget(ubus_mbox_id)) != 0) {
			switch(cmd) {
				case UBUS_SIGHUP:
					UBUS_DBGPRINT(UBUS_DEBUG_OFF, "%s(): Line%d to start up\n", __FUNCTION__, __LINE__);
#if 0
					ret = ubusMasqstart(port);
					if (ret < 0) {
						UBUS_DBGPRINT(UBUS_DEBUG_OFF, "%s(): Line%d failed to start up\n", __FUNCTION__, __LINE__);
						ubus_running = 0;
						return;
					}
					ubus_sleep = 0;
#endif
					break;

				case UBUS_SHUTDOWN: // do we need to return ??
					UBUS_DBGPRINT(UBUS_DEBUG_OFF, "%s(): Line%d to shutdown up\n", __FUNCTION__, __LINE__);
					//ubusstop();
					//ubus_sleep = 1;
					break;

				default:
					break;
			}
		}

		if (ubus_sleep) {
			cyg_thread_delay(100);
			continue;
		}

		cyg_thread_delay(100);
		ubus_seq++;
		/* do init stuff only first time round. */
#if 0
		if (first_loop) {
			first_loop = 0;
			ready = 0;
		} else {
			FD_ZERO(&rset);
			maxfd = 0;
			for (i=0; i<ubus_servers_num; i++)
			{
				if (ubus_servers[i].fd > 0)
				{
					FD_SET(ubus_servers[i].fd, &rset);
					if (ubus_servers[i].fd > maxfd)
						maxfd = ubus_servers[i].fd;
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
				if (UBUSDebugLevel > UBUS_DEBUG_OFF) {
					UBUS_DBGPRINT(UBUS_DEBUG_ERROR, "%s(): select() return %d\n", __FUNCTION__, ready);
					cyg_thread_delay(100);
				} else
					cyg_thread_delay(2);

				continue;
			}
		}

		now = time(NULL);
		if (ready == 0)
			continue; /* no sockets ready */


		// check ubus query from querist
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
					header = (UBUSHEADER *)packet;
					if (recv_len >= (int)sizeof(UBUSHEADER) && !header->qr)
					{
						activeserver = ubusMasqprocessquery(recv_infaces[i].fd, &queryaddr, header, recv_len,
								activeserver, now);
					}
				}
			}
		}

		// check ubus reply from ubus server
		for (i=0; i<ubus_servers_num; i++)
		{
			if (ubus_servers[i].fd > 0)
			{
				if (FD_ISSET(ubus_servers[i].fd, &rset))
				{
					FD_CLR(ubus_servers[i].fd, &rset);
					recv_len = recvfrom(ubus_servers[i].fd, packet, PACKETSZ, 0, NULL, NULL);
					new_active_srv = ubusMasqprocessreply(ubus_servers[i].fd, packet, recv_len, now);
					if (new_active_srv != NULL)
						activeserver = new_active_srv;
				}
			}
		}
#endif
	}
}

void UBUS_init(void)
{
	int val=0;

	CFG_get(CFG_UBUS_EN, &val);
	if(val)
	{
		cyg_mbox_create( &ubus_mbox_id, &ubus_mbox_obj );
		cyg_thread_create(UBUS_PRIORITY, &UBUS_daemon, 0, "UBUS_daemon",
				&ubus_stack, UBUS_STACKSIZE,
				&ubus_handle, &ubus_thread);
		cyg_thread_resume(ubus_handle);
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
int ubus_cmd(int argc, char* argv[])
{

#if 0
	extern UBUS_PORTMAP *ubus_pmlist;
	extern UBUS_CONTEXT ubus_context;

	UBUS_CONTEXT *context = &ubus_context;
	UBUS_SERVICE *service = ubus_service_table;
	UBUS_SUBSCRIBER	*subscriber;

	UBUS_INTERFACE *ifp;

	if (argc==0 || !strcmp(argv[0], "show") )
	{
		printf("# Interfaces\n");
		for (ifp=context->iflist; ifp; ifp=ifp->next)
		{
			printf("%10s %6d\n", ifp->ifname, ifp->http_sock);
		}

		printf("\n");

		if (ubus_pmlist==0)
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
		cyg_mutex_lock(&ubus_service_table_mutex);
		for (service = ubus_service_table; service->event_url; service++)
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
		cyg_mutex_unlock(&ubus_service_table_mutex);
	}
	else if (( argc == 2 ) && (!strcmp(argv[0], "debug" )))
	{
		int level = 0;

		level = atoi(argv[1]);
		if (level > 0)
			ubus_debug_level = level;
		else
			ubus_debug_level = RT_DBG_OFF;


		DBGPRINTF(RT_DBG_OFF, "UBUSD debug level = %d\n", ubus_debug_level);
	}
	else
		goto err1;

	return 0;
#endif

err1:
	printf("ubus hello world! set[%d]\n", ubus_seq);
	return 0;
}

#endif

