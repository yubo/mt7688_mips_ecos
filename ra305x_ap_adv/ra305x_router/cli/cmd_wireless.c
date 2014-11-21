/****************************************************************************
 * Ralink Tech Inc.
 * Taiwan, R.O.C.
 *
 * (c) Copyright 2002, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************

    Module Name:
    cmd_wireless.c

    Abstract:

    Revision History:
    Who         When            What
    --------    ----------      ------------------------------------------
*/

#ifdef CONFIG_WIRELESS
#include <sys/types.h>
#include <cyg/kernel/kapi.h>
#include <stdlib.h>
#include <stdio.h>

#include <cyg/io/flash.h>
#include <cyg/infra/diag.h>

#include <network.h>
#include <ifaddrs.h>
#include <cyg/io/eth/eth_drv_stats.h>
#include <cyg/io/eth/eth_drv.h>
#include <cyg/io/eth/netdev.h>
#include <string.h>

// Put platform dependent declaration here
// For example, linux type definition
typedef unsigned char			UINT8;
typedef unsigned short			UINT16;
typedef unsigned int			UINT32;
typedef unsigned long long		UINT64;
typedef int				INT32;
typedef long long 			INT64;

typedef unsigned char			UCHAR;
typedef unsigned short			USHORT;
typedef unsigned int			UINT;
typedef unsigned long			ULONG;

typedef unsigned char * 		PUINT8;
typedef unsigned short *		PUINT16;
typedef unsigned int *			PUINT32;
typedef unsigned long long *	        PUINT64;
typedef int *				PINT32;
typedef long long * 			PINT64;

// modified for fixing compile warning on Sigma 8634 platform
typedef char 				STRING;
typedef signed char			CHAR;

typedef signed short			SHORT;
typedef signed int			INT;
typedef signed long			LONG;
typedef signed long long		LONGLONG;	

typedef unsigned long long		ULONGLONG;
 
typedef unsigned char			BOOLEAN;
typedef void				VOID;

typedef char *				PSTRING;
typedef VOID *				PVOID;
typedef CHAR *				PCHAR;
typedef UCHAR * 			PUCHAR;
typedef USHORT *			PUSHORT;
typedef LONG *				PLONG;
typedef ULONG *				PULONG;
typedef UINT *				PUINT;

#define SIOCIWFIRSTPRIV 0x00
#define RT_PRIV_IOCTL (SIOCIWFIRSTPRIV + 0x01)
#define RTPRIV_IOCTL_SET (SIOCIWFIRSTPRIV + 0x02)
#define RTPRIV_IOCTL_BBP (SIOCIWFIRSTPRIV + 0x03)
#define RTPRIV_IOCTL_MAC (SIOCIWFIRSTPRIV + 0x05)
#define RTPRIV_IOCTL_E2P (SIOCIWFIRSTPRIV + 0x07)
#define RTPRIV_IOCTL_STATISTICS (SIOCIWFIRSTPRIV + 0x09)
#define RTPRIV_IOCTL_GSITESURVEY (SIOCIWFIRSTPRIV + 0x0D)
#define RTPRIV_IOCTL_GET_MAC_TABLE (SIOCIWFIRSTPRIV + 0x0F)
#define RTPRIV_IOCTL_SHOW (SIOCIWFIRSTPRIV + 0x11)
#define RTPRIV_IOCTL_RF (SIOCIWFIRSTPRIV + 0x13)

#define RTPRIV_IOCTL_FLAG_UI 0x0001	/* Notidy this private cmd send by UI. */
#define RTPRIV_IOCTL_FLAG_NODUMPMSG 0x0002	/* Notify driver cannot dump msg to stdio/stdout when run this private ioctl cmd */
#define RTPRIV_IOCTL_FLAG_NOSPACE 0x0004	/* Notify driver didn't need copy msg to caller due to the caller didn't reserve space for this cmd */



typedef struct
{
	const char*	cmd;					// Input command string
	int	(*func)(int argc, char* argv[]);
	const char*	msg;					// Help message
} COMMAND_TABLE;

// Define Linux ioctl relative structure, keep only necessary things
struct iw_point
{
	PVOID		pointer;
	USHORT		length;
	USHORT		flags;
};
	
union iwreq_data
{
	struct iw_point data;
};

struct iwreq {
	union
	{
		char    ifrn_name[IFNAMSIZ];    /* if name, e.g. "eth0" */
	} ifr_ifrn;
	
	union   iwreq_data      u;
};

typedef struct eth_drv_sc	*PNET_DEV;

#ifndef NULL
#define NULL	0
#endif

#ifndef TRUE
#define TRUE	1
#endif

#ifndef FALSE
#define FALSE	0
#endif

int CmdIwpriv(int argc, char *argv[]);

extern INT rt28xx_ap_ioctl(
	PNET_DEV	pEndDev, 
	INT			cmd, 
	caddr_t		pData);

//static char TempString[8192];
int CmdIwpriv(int argc, char *argv[])
{
	int cmd;
	cyg_netdevtab_entry_t *t;
	struct eth_drv_sc *sc;
	struct iwreq param;
	int found = 0;

	if ( argc < 2 )
                goto error_exit;

        if ((strcmp(argv[0], "ra0") != 0 )
                && (strcmp(argv[0], "ra1") != 0 )
                && (strcmp(argv[0], "ra2") != 0 )
                && (strcmp(argv[0], "ra3") != 0 )
                && (strcmp(argv[0], "ra4") != 0 )
                && (strcmp(argv[0], "ra5") != 0 )
                && (strcmp(argv[0], "ra6") != 0 )
                && (strcmp(argv[0], "ra7") != 0 )
                && (strcmp(argv[0], "wds0") != 0 )
                && (strcmp(argv[0], "apcli0") != 0 )
                && (strcmp(argv[0], "mesh0") != 0 )
        )
                goto error_exit;

        memset(&param, 0, sizeof(struct iwreq));

	if ( strcmp(argv[1], "set") == 0 )
	{
		cmd = RTPRIV_IOCTL_SET;
	} 
	else if ( strcmp(argv[1], "show") == 0 )
	{
		cmd = RTPRIV_IOCTL_SHOW;
	} 
	else if ( strcmp(argv[1], "e2p") == 0 )
	{
		cmd = RTPRIV_IOCTL_E2P;
	} 
	else if ( strcmp(argv[1], "bbp") == 0 )
	{
		cmd = RTPRIV_IOCTL_BBP;
                param.u.data.flags |= (RTPRIV_IOCTL_FLAG_NOSPACE | RTPRIV_IOCTL_FLAG_NODUMPMSG);
	} 
	else if ( strcmp(argv[1], "mac") == 0 )
	{
		cmd = RTPRIV_IOCTL_MAC;
                param.u.data.flags |= (RTPRIV_IOCTL_FLAG_NOSPACE | RTPRIV_IOCTL_FLAG_NODUMPMSG);
	} 
	else if ( strcmp(argv[1], "rf") == 0 )
	{
		cmd = RTPRIV_IOCTL_RF;
                param.u.data.flags |= (RTPRIV_IOCTL_FLAG_NOSPACE | RTPRIV_IOCTL_FLAG_NODUMPMSG);
	} 
	else if (( strcmp(argv[1], "GetSiteSurvey") == 0 ) ||( strcmp(argv[1], "get_site_survey") == 0 ))
	{
		cmd = RTPRIV_IOCTL_GSITESURVEY;
                param.u.data.flags |= (RTPRIV_IOCTL_FLAG_NOSPACE | RTPRIV_IOCTL_FLAG_NODUMPMSG);
	}                 
	else if ( strcmp(argv[1], "stat") == 0 )
	{
		cmd = RTPRIV_IOCTL_STATISTICS;
                param.u.data.flags |= (RTPRIV_IOCTL_FLAG_NOSPACE | RTPRIV_IOCTL_FLAG_NODUMPMSG);
	}
	else 
	{
                goto error_exit;
	}

	for (t = &__NETDEVTAB__[0]; t != &__NETDEVTAB_END__; t++) 
	{
		sc = (struct eth_drv_sc *)t->device_instance;
		if (strcmp(sc->dev_name, argv[0]) == 0) {
			found =1;
			break;
	        }
	}

	if ( found == 1 )
	{
		char *TempString=NULL;
		int original_length = 0;
		
		TempString =malloc(7168);//7*1024
		if(TempString==NULL){diag_printf("Not enough memory for CmdIwpriv!\n");return FALSE;}	    
		 TempString[0] = '\0';

		if ( argc > 2 )
		{              
			sprintf(&TempString[0], "%s", argv[2]);
			original_length = strlen(argv[2]);
		}
		
		param.u.data.pointer = &TempString[0];                
		param.u.data.length = strlen(TempString);
		//diag_printf("cmd:%s [%d][%d]",TempString,param.u.data.length,original_length);
		rt28xx_ap_ioctl(sc, cmd, (caddr_t)&param);
		
		if (param.u.data.length != original_length)
		{
			TempString[param.u.data.length] = '\0';
			diag_printf("%s", TempString);
		}
		
		free(TempString);
    		return TRUE;			
	}	
    
error_exit:
	diag_printf("usage: iwpriv <interface> set|show|e2p|bbp|mac|rf <command>\n");
	diag_printf("usage: iwpriv <interface> stat|GetSiteSurvey\n");
	return FALSE;    
}

#endif // CONFIG_WIRELESS //


