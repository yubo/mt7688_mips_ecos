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

#include "traffic/trafficd.h"
#include "traffic/ubus.h"
#include "traffic/system.h"


static const int log_class[] = {
	[L_CRIT] = LOG_CRIT,
	[L_ERR] = LOG_ERR,
	[L_WARNING] = LOG_WARNING,
	[L_NOTICE] = LOG_NOTICE,
	[L_INFO] = LOG_INFO,
	[L_DEBUG] = LOG_DEBUG
};
struct trafficd_sys *sys = NULL;
/*
enum {
	L_CRIT,
	L_ERR,
	L_WARNING,
	L_NOTICE,
	L_INFO,
	L_DEBUG
};

enum {
	DEBUG_SYSTEM	= 0,
	DEBUG_IP	= 1,	// 2
	DEBUG_HW	= 2,	// 4
	DEBUG_BR	= 3,	// 8
	DEBUG_DEV	= 4,	// 16
	DEBUG_POINT	= 5,	// 32
	DEBUG_EVENT	= 6,	// 64
	DEBUG_CONF	= 7,	// 128
	DEBUG_BUS	= 8,	// 256
};
*/
uint32_t debug_mask = DEFAULT_DEBUG_MASK; //DEFAULT_DEBUG_MASK
int log_level = DEFAULT_LOG_LEVEL; //DEFAULT_LOG_LEVEL;

void trafficd_log_message(int priority, const char *format, ...)
{
	va_list vl;

	if (priority > log_level)
		return;

	va_start(vl, format);
	printf(format, vl);
	va_end(vl);
}


#ifdef __ECOS


#define TRAFFIC_SIGHUP      1
#define TRAFFIC_SHUTDOWN    2

#define TRAFFIC_PRIORITY    9
#define TRAFFIC_STACKSIZE   (1024*64)
static char traffic_stack[TRAFFIC_STACKSIZE];
cyg_handle_t traffic_handle;
cyg_thread traffic_thread;
static cyg_mbox traffic_mbox_obj;
static cyg_handle_t traffic_mbox_id;

struct uloop_timeout sig_timeout;


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

	//dlog("sig_cb() for syg_mbox_tryget, sleep %d(s)\n", TRAFFICD_SIGNAL_LOOP_TIME / 1000);
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

	sys->cfg.use_syslog = false;

	while(config_init_all()){
		elog("config_init_all() failed\n");
		cyg_thread_delay(500);
	}
	elog("config_init_all() done\n");


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
	dlog("system_init() done\n");

	memset(&sig_timeout, 0 , sizeof(sig_timeout));
	sig_timeout.cb = sig_cb;
	uloop_timeout_set(&sig_timeout, TRAFFICD_SIGNAL_LOOP_TIME);

	dlog("uloop_run()\n");
	uloop_run();
	uloop_done();

	trafficd_tbus_done();
	config_done();
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


	if (argc==0 || !strcmp(argv[0], "show")){
		printf("log_level:%d debug_mask:%d\n", log_level, debug_mask);
		printf("system_dump()\n");
		system_dump();
	} else if (( argc == 2 ) && (!strcmp(argv[0], "log_level" ))) {
		int level = 0;

		level = atoi(argv[1]);
		if (level > 0)
			log_level = level;
		else
			log_level = L_CRIT;

		printf("TRAFFICD log_level = %d\n", log_level);
	}
#ifdef DEBUG
	else if (( argc == 2 ) && (!strcmp(argv[0], "debug_mask" ))) {
		int mask = 0;
		mask = atoi(argv[1]);
		if (mask > 0)
			debug_mask = mask;
		else
			debug_mask = 0;
		printf("TRAFFICD debug_mask = %d\n", debug_mask);
	}
#endif
	else
		goto err1;

	return 0;

err1:

	printf("traffic show\n");
	printf("traffic log_level CRIT:%d, ERR:%d, WARNING:%d, NOTICE:%d, INFO:%d, DEBUG:%d\n",
	 	L_CRIT, L_ERR, L_WARNING, L_NOTICE, L_INFO, L_DEBUG);
#ifdef DEBUG
	printf("traffic debug_mask SYSTEM:%d, IP:%d, HW:%d, EVENT:%d, CONF:%d, BUS:%d\n",
	 	1<<DEBUG_SYSTEM, 1<<DEBUG_IP, 1<<DEBUG_HW, 1<<DEBUG_EVENT, 1<<DEBUG_CONF, 1<<DEBUG_BUS);
#endif
	printf("traffic hello world! set\n");
	return 0;
}

#endif

#else



/*
###########################################################
### for x86                                               #
###########################################################
*/
static char **global_argv;

static int usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options:\n"
		" -d <mask>:		Mask for debug messages\n"
		" -s <path>:		Path to the ubus socket\n"
		" -D:				enable DEMO modle\n"
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

	trafficd_setup_signals();
	uloop_run();
	uloop_done();

	trafficd_tbus_done();
	config_done();
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





