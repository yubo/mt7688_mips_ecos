/*
 * yubo@xiaomi.com
 * 2014-09-09
 */
#ifndef __TRAFFICD_SYSTEM_H
#define __TRAFFICD_SYSTEM_H

#define TRAFFICD_DISASSOC_EVENT 0
#define TRAFFICD_ASSOC_EVENT 1

#ifdef __ECOS


#define SIOCIWFIRSTPRIV 0x00
#define RTPRIV_IOCTL_IW_CALLBACK    (SIOCIWFIRSTPRIV + 0x1B)
#define RTPRIV_IOCTL_MAT_CALLBACK    (SIOCIWFIRSTPRIV + 0x1C)

#endif

int system_init(void);
int system_done(void);
void system_assoclist_update(void);
void system_show_assoclist(void);
void system_dump();





#endif
