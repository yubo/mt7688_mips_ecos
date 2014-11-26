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

#ifdef __ECOS
#include <cfg_def.h>
#else
#include <syslog.h>
#endif

#include "trafficd.h"
#include "ubus.h"
#include "system.h"

#ifdef __ECOS
unsigned int debug_mask = 0x0;

#define TRAFFIC_SIGHUP      1
#define TRAFFIC_SHUTDOWN    2

#define TRAFFIC_PRIORITY    9
#define TRAFFIC_STACKSIZE 102400

static char traffic_stack[TRAFFIC_STACKSIZE];

cyg_handle_t traffic_handle;
cyg_thread traffic_thread;
static cyg_mbox traffic_mbox_obj;
static cyg_handle_t traffic_mbox_id;

struct uloop_timeout sig_timeout;


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


static void trafficstop()
{
	uloop_end();
}

static void sig_cb(struct uloop_timeout *timeout)
{
	int cmd;

	if ((cmd = (int )cyg_mbox_tryget(traffic_mbox_id)) != 0) {
		switch(cmd) {
			case TRAFFIC_SIGHUP:
				D(SYSTEM, "start up , ignore\n");
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
				trafficstop();
				return;
				//traffic_sleep = 1;
				break;

			default:
				break;
		}
	}

	D(BUS, "send msg and wait %d(s)\n", TRAFFICD_WIFIAP_LOOP_TIME / 1000);
	uloop_timeout_set(timeout, TRAFFICD_SIGNAL_LOOP_TIME);

}

void TRAFFIC_daemon(void)
{
	int ret = 0;

	if(sys){
		elog("sys already malloc\n");
		return;
	}
	if(!(sys = calloc(1, sizeof(*sys)))){
		elog("Failed to initialize sys\n");
		return;
	}
	TR_REFRESH_TIME();

	sys->bd = NULL;
	sys->id = NULL;
	sys->hd = NULL;

	debug_mask = 256;
	sys->cfg.use_syslog = false;


	if(config_init_all()){
		elog("failed to config_init_all\n");
		free(sys);
		sys = NULL;
		return;
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
	if (!(sys->id && sys->hd &&
			sys->bd)){
		ret = -1;
		goto out;
	}

	config_init_alive();

	memset(&sig_timeout, 0 , sizeof(sig_timeout));
	sig_timeout.cb = sig_cb;
	uloop_timeout_set(&sig_timeout, TRAFFICD_SIGNAL_LOOP_TIME);

	uloop_run();
	uloop_done();

	trafficd_hw_done();
	trafficd_ip_done();
	trafficd_tbus_done();


	free(sys);
	sys = NULL;

	return;

out:
	uloop_done();
	free(sys);
	sys = NULL;
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

//err1:
	printf("traffic hello world! set\n");
	return 0;
}

#endif


#else
// for x86


unsigned int debug_mask = 0x0;


static char **global_argv;


static int log_level = DEFAULT_LOG_LEVEL;
static const int log_class[] = {
	[L_CRIT] = LOG_CRIT,
	[L_ERR] = LOG_ERR,
	[L_WARNING] = LOG_WARNING,
	[L_NOTICE] = LOG_NOTICE,
	[L_INFO] = LOG_INFO,
	[L_DEBUG] = LOG_DEBUG
};

struct trafficd_sys *sys;

void trafficd_log_message(int priority, const char *format, ...)
{
	va_list vl;

	if (priority > log_level)
		return;

	va_start(vl, format);
	if (sys->cfg.use_syslog)
		vsyslog(log_class[priority], format, vl);
	else
		vfprintf(stderr, format, vl);
	va_end(vl);
}

void log_points(int instant, const char *format, ...)
{
	va_list vl;
	char buff[POINTSMAXLEN];

	va_start(vl, format);
	vsnprintf(buff, POINTSMAXLEN, format, vl);
	va_end(vl);

	if (sys->cfg.use_syslog){
		if (instant){
			syslog(LOG_NOTICE, "stat_points_instant %s", buff);
		}else{
			syslog(LOG_NOTICE, "stat_points_none %s", buff);
		}
	}else{
		if (debug_mask & (1 << (DEBUG_POINT))){
			if (instant){
				fprintf(stderr, "stat_points_instant %s\n", buff);
			}else{
				fprintf(stderr, "stat_points_none %s\n", buff);
			}
		}
	}

}


static struct uloop_timeout main_timer;



static int usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options:\n"
		" -d <mask>:		Mask for debug messages\n"
		" -s <path>:		Path to the ubus socket\n"
		" -r <path>:		Path to resolv.conf\n"
		" -l <level>:		Log output level (default: %d)\n"
		" -S:			Use stderr instead of syslog for log messages\n"
		"\n", progname, DEFAULT_LOG_LEVEL);

	return 1;
}

static void
trafficd_handle_signal(int signo)
{
	uloop_end();
}

static void
trafficd_setup_signals(void)
{
	struct sigaction s;

	memset(&s, 0, sizeof(s));
	s.sa_handler = trafficd_handle_signal;
	s.sa_flags = 0;
	sigaction(SIGINT, &s, NULL);
	sigaction(SIGTERM, &s, NULL);
	sigaction(SIGUSR1, &s, NULL);
	sigaction(SIGUSR2, &s, NULL);

	s.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &s, NULL);
}


int main(int argc, char **argv)
{
	int ch, ret;
	ret = 0;

	if(!(sys = calloc(1, sizeof(*sys)))){
		elog("Failed to initialize sys\n");
		return 1;
	}
	TR_REFRESH_TIME();

	sys->bd = NULL;
	sys->id = NULL;

	sys->cfg.use_syslog = true;
	global_argv = argv;
	while ((ch = getopt(argc, argv, "d:h:l:S")) != -1) {
		switch(ch) {
		case 'd':
			debug_mask = strtoul(optarg, NULL, 0);
			break;
		case 'l':
			log_level = atoi(optarg);
			if (log_level >= ARRAY_SIZE(log_class))
				log_level = ARRAY_SIZE(log_class) - 1;
			break;
		case 'S':
			sys->cfg.use_syslog = false;
			break;
		default:
			return usage(argv[0]);
		}
	}

	if (sys->cfg.use_syslog)
		openlog("trafficd", 0, LOG_DAEMON);

	if(config_init_all()){
		elog("failed to config_init_all\n");
		return 1;
	}

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
	if (!(sys->id && sys->hd )){
		ret = -1;
		goto out;
	}

	config_init_alive();
	trafficd_setup_signals();
	uloop_run();
	uloop_done();

	trafficd_hw_done();
	trafficd_ip_done();
	trafficd_tbus_done();
	system_done();

	if (sys->cfg.use_syslog)
		closelog();

	free(sys);

	return ret;

out:

	uloop_done();

	if (sys->cfg.use_syslog)
		closelog();

	free(sys);

	return ret;
}


#endif





