
/*
 * utils - misc libubox utility functions
 *
 * Copyright (C) 2012 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __LIBUBOX_UTILS_H
#define __LIBUBOX_UTILS_H

#include <sys/types.h>
#include <sys/time.h>
#include <stdbool.h>
#include <time.h>

#ifndef __ECOS
#include <stdint.h>
#else
#include <sys/bsdtypes.h>
#endif

/*
 * calloc_a(size_t len, [void **addr, size_t len,...], NULL)
 *
 * allocate a block of memory big enough to hold multiple aligned objects.
 * the pointer to the full object (starting with the first chunk) is returned,
 * all other pointers are stored in the locations behind extra addr arguments.
 * the last argument needs to be a NULL pointer
 */

#define calloc_a(len, ...) __calloc_a(len, ##__VA_ARGS__, NULL)

void *__calloc_a(size_t len, ...);

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef BUILD_BUG_ON

#define __BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

#ifdef __OPTIMIZE__
extern int __BUILD_BUG_ON_CONDITION_FAILED;
#define BUILD_BUG_ON(condition)					\
	do {							\
		__BUILD_BUG_ON(condition);			\
		if (condition)					\
			__BUILD_BUG_ON_CONDITION_FAILED = 1;	\
	} while(0)
#else
#define BUILD_BUG_ON __BUILD_BUG_ON
#endif

#endif

#ifdef __APPLE__

#define CLOCK_REALTIME	0
#define CLOCK_MONOTONIC	1

void clock_gettime(int type, struct timespec *tv);

#endif

#ifdef __GNUC__
#define _GNUC_MIN_VER(maj, min) (((__GNUC__ << 8) + __GNUC_MINOR__) >= (((maj) << 8) + (min)))
#else
#define _GNUC_MIN_VER(maj, min) 0
#endif

#if defined(__linux__) || defined(__CYGWIN__)
#include <byteswap.h>
#include <endian.h>

#elif defined(__APPLE__)
#include <machine/endian.h>
#include <machine/byte_order.h>
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)
#elif defined(__FreeBSD__)
#include <sys/endian.h>
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)
#else
#include <machine/endian.h>
#define bswap_32(x) swap32(x)
#define bswap_64(x) swap64(x)
#endif

#ifndef __BYTE_ORDER
#define __BYTE_ORDER BYTE_ORDER
#endif
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN BIG_ENDIAN
#endif
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#endif

static inline uint16_t __u_bswap16(uint16_t val)
{
	return ((val >> 8) & 0xffu) | ((val & 0xffu) << 8);
}

#if _GNUC_MIN_VER(4, 2)
#define __u_bswap32(x) __builtin_bswap32(x)
#define __u_bswap64(x) __builtin_bswap64(x)
#else
#define __u_bswap32(x) bswap_32(x)
#define __u_bswap64(x) bswap_64(x)
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN

#define cpu_to_be64(x) __u_bswap64(x)
#define cpu_to_be32(x) __u_bswap32(x)
#define cpu_to_be16(x) __u_bswap16((uint16_t) (x))

#define be64_to_cpu(x) __u_bswap64(x)
#define be32_to_cpu(x) __u_bswap32(x)
#define be16_to_cpu(x) __u_bswap16((uint16_t) (x))

#define cpu_to_le64(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le16(x) (x)

#define le64_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le16_to_cpu(x) (x)

#else /* __BYTE_ORDER == __LITTLE_ENDIAN */

#define cpu_to_le64(x) __u_bswap64(x)
#define cpu_to_le32(x) __u_bswap32(x)
#define cpu_to_le16(x) __u_bswap16((uint16_t) (x))

#define le64_to_cpu(x) __u_bswap64(x)
#define le32_to_cpu(x) __u_bswap32(x)
#define le16_to_cpu(x) __u_bswap16((uint16_t) (x))

#define cpu_to_be64(x) (x)
#define cpu_to_be32(x) (x)
#define cpu_to_be16(x) (x)

#define be64_to_cpu(x) (x)
#define be32_to_cpu(x) (x)
#define be16_to_cpu(x) (x)

#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef __constructor
#define __constructor __attribute__((constructor))
#endif

#ifndef __hidden
#define __hidden __attribute__((visibility("hidden")))
#endif

#ifndef BITS_PER_LONG
#define BITS_PER_LONG (8 * sizeof(unsigned long))
#endif

static inline void bitfield_set(unsigned long *bits, int bit)
{
	bits[bit / BITS_PER_LONG] |= (1UL << (bit % BITS_PER_LONG));
}

static inline bool bitfield_test(unsigned long *bits, int bit)
{
	return !!(bits[bit / BITS_PER_LONG] & (1UL << (bit % BITS_PER_LONG)));
}

#endif



/*yubo@xiaomi.com
 * 2014-08-20
 */
#ifdef __TRAFFICD__
#ifndef __TRAFFICD_UTILS_H
#define __TRAFFICD_UTILS_H
#define __STDC_FORMAT_MACROS
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <fcntl.h>

#ifndef __ECOS
#include <stdint.h>
#else
#include "int.h"
#endif

#include "list.h"
#include "avl.h"
#include "avl-cmp.h"
#include "blobmsg.h"
#include "vlist.h"



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

uint32_t crc32_file(FILE *fp);

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
#endif