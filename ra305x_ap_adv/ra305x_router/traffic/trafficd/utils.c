/*
 * netifd - network interface daemon
 * Copyright (C) 2012 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <string.h>
#include <stdlib.h>


#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <locale.h>

#ifdef __APPLE__
#include <libproc.h>
#endif

#include "trafficd.h"
#include "utils.h"

static int uptime_fd = -1;

// As of 2.6.24 /proc/meminfo seems to need 888 on 64-bit,
// and would need 1258 if the obsolete fields were there.
static char buf[2048];



/***********************************************************************/
double get_uptime(double * uptime_secs, double * idle_secs) {
    return 0;  /* assume never be zero seconds in practice */
}





void
__vlist_simple_init(struct vlist_simple_tree *tree, int offset)
{
	INIT_LIST_HEAD(&tree->list);
	tree->version = 1;
	tree->head_offset = offset;
}

void
vlist_simple_delete(struct vlist_simple_tree *tree, struct vlist_simple_node *node)
{
	char *ptr;

	list_del(&node->list);
	ptr = (char *) node - tree->head_offset;
	free(ptr);
}

void
vlist_simple_flush(struct vlist_simple_tree *tree)
{
	struct vlist_simple_node *n, *tmp;

	list_for_each_entry_safe(n, tmp, &tree->list, list) {
		if ((n->version == tree->version || n->version == -1) &&
		    tree->version != -1)
			continue;

		vlist_simple_delete(tree, n);
	}
}

void
vlist_simple_replace(struct vlist_simple_tree *dest, struct vlist_simple_tree *old)
{
	struct vlist_simple_node *n, *tmp;

	vlist_simple_update(dest);
	list_for_each_entry_safe(n, tmp, &old->list, list) {
		list_del(&n->list);
		vlist_simple_add(dest, n);
	}
	vlist_simple_flush(dest);
}

void
vlist_simple_flush_all(struct vlist_simple_tree *tree)
{
	tree->version = -1;
	vlist_simple_flush(tree);
}

char *
format_macaddr(uint8_t *mac)
{
	static char str[sizeof("ff:ff:ff:ff:ff:ff ")];

	snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return str;
}




bool check_pid_path(int pid, const char *exe)
{
	int proc_exe_len;
	int exe_len = strlen(exe);

#ifdef __APPLE__
	char proc_exe_buf[PROC_PIDPATHINFO_SIZE];

	proc_exe_len = proc_pidpath(pid, proc_exe_buf, sizeof(proc_exe_buf));
#else
	char proc_exe[32];
	char *proc_exe_buf = alloca(exe_len);

	sprintf(proc_exe, "/proc/%d/exe", pid);
	proc_exe_len = readlink(proc_exe, proc_exe_buf, exe_len);
#endif

	if (proc_exe_len != exe_len)
		return false;

	return !memcmp(exe, proc_exe_buf, exe_len);
}

void system_fd_set_cloexec(int fd)
{
#ifdef FD_CLOEXEC
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
}


int cmp_ip(const void *k1, const void *k2, void *ptr)
{
    const __be32 *ip1 = k1, *ip2 = k2;

    if (*ip1 < *ip2)
        return -1;
    else
        return *ip1 > *ip2;
}


void upper_nstring(char *string, int size)
{
	int i;
	for(i=0; i<size; i++){
		if(string[i] == '\0')
			return;
		if(string[i] >= 'a' && string[i] <= 'z'){
			string[i] -= 32;
		}
	}
}


char *trafficd_ctime(time_t time){
	static char buff[20];
	struct tm *tm;
	time_t t;
	t = time;
	tm = localtime(&t);
	snprintf(buff, 20, "%4d-%02d-%02d %02d:%02d:%02d",
		tm->tm_year + 1900, tm->tm_mon, tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
	return buff;
}