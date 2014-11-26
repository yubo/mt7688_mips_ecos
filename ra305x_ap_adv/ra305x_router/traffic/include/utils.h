
/*yubo@xiaomi.com
 * 2014-08-20
 */
#ifndef __TRAFFICD_UTILS_H
#define __TRAFFICD_UTILS_H
#define __STDC_FORMAT_MACROS
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <fcntl.h>

#ifndef __ECOS
#include <stdint.h>
#include <stdio.h>
#else
#include "int.h"
#endif

#include "libubox/list.h"
#include "libubox/avl.h"
#include "libubox/avl-cmp.h"
#include "libubox/blobmsg.h"
#include "libubox/vlist.h"



#define BAD_OPEN_MESSAGE                    \
"Error: /proc must be mounted\n"                \
"  To mount /proc at boot you need an /etc/fstab line like:\n"  \
"      /proc   /proc   proc    defaults\n"          \
"  In the meantime, run \"mount /proc /proc -t proc\"\n"

#define up2time(a) (sys->tv.tv_sec + (time_t)((a) - sys->uptime))
#define hw_is_local(a) ((a)->is_local && !(a)->assoc)

#define __init __attribute__((constructor))

struct vlist_simple_tree {
	struct list_head list;
	int head_offset;
	int version;
};

struct vlist_simple_node {
	struct list_head list;
	int version;
};

#define vlist_for_each_element_safe(tree, element, node_member, ptr) \
        avl_for_each_element_safe(&(tree)->avl, element, node_member.avl, ptr)

#define vlist_simple_init(tree, node, member) \
	__vlist_simple_init(tree, offsetof(node, member))

void __vlist_simple_init(struct vlist_simple_tree *tree, int offset);
void vlist_simple_delete(struct vlist_simple_tree *tree, struct vlist_simple_node *node);
void vlist_simple_flush(struct vlist_simple_tree *tree);
void vlist_simple_flush_all(struct vlist_simple_tree *tree);
void vlist_simple_replace(struct vlist_simple_tree *dest, struct vlist_simple_tree *old);

static inline void vlist_simple_update(struct vlist_simple_tree *tree)
{
	tree->version++;
}

static inline void vlist_simple_add(struct vlist_simple_tree *tree, struct vlist_simple_node *node)
{
	node->version = tree->version;
	list_add_tail(&node->list, &tree->list);
}

#define vlist_simple_for_each_element(tree, element, node_member) \
	list_for_each_entry(element, &(tree)->list, node_member.list)

#define vlist_simple_empty(tree) \
	list_empty(&(tree)->list)


unsigned int parse_netmask_string(const char *str, bool v6);
bool split_netmask(char *str, unsigned int *netmask, bool v6);
int parse_ip_and_netmask(int af, const char *str, void *addr, unsigned int *netmask);
bool check_pid_path(int pid, const char *exe);

char * format_macaddr(uint8_t *mac);

void system_fd_set_cloexec(int fd);
int cmp_ip(const void *k1, const void *k2, void *ptr);
#ifdef __APPLE__
#define s6_addr32	__u6_addr.__u6_addr32
#endif




#ifndef  NIPQUAD
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#ifndef  HIPQUAD
#define HIPQUAD(addr) \
    ((unsigned char *)&addr)[3], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[0]
#define HIPQUAD_FMT "%u.%u.%u.%u"
#endif


double get_uptime (double *uptime_secs, double *idle_secs);
void upper_nstring(char *string, int size);

char *trafficd_ctime(time_t time);


#endif