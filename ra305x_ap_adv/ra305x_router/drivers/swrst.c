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
    swrst.c

    Abstract:

    Revision History:
    Who         When            What
    --------    ----------      ------------------------------------------
*/

//==============================================================================
//                                INCLUDE FILES
//==============================================================================
#include <stdio.h>
#include <config.h>
#include <cyg/kernel/kapi.h>
#include <cfg_def.h>
#include <network.h>
#include <cfg_net.h>

#ifdef	CONFIG_LED
#include <led.h>
#endif

//==============================================================================
//                                    MACROS
//==============================================================================

#ifdef	CONFIG_RST

extern	int	IS_SWRST_ON();
extern	void CONFIG_SWRST();
extern	void ENABLE_SWRST();

#endif	// CONFIG_RST

#ifndef HZ
#define HZ		100
#endif

#define SWRST_CHECK_TIME		(4*HZ/10)		/*  0.4 Sec*/
#define FACTORY_RESET_TIME		((32*HZ/10)/SWRST_CHECK_TIME)	/*  3.2 sec  */
//==============================================================================
//                          LOCAL FUNCTION PROTOTYPES
//==============================================================================

//==============================================================================
//                              EXTERNAL FUNCTIONS
//==============================================================================

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
void swrst_chk(void)
{
	static cyg_uint32 pressed_time=0;
	
	/*  Check reset button  */
	if (IS_SWRST_ON()) {
		if (pressed_time>0) {
			/*  Reset button released  */
			if (pressed_time <= FACTORY_RESET_TIME) {
				diag_printf("SW RESET -> reboot!\n");
			} else {
				CFG_reset_default();
			}
			mon_snd_cmd(MON_CMD_REBOOT);
			pressed_time = 0;
			/*  Stop checking the reset button and wait for rebooting  */
			return;
		}
	}
	else {
		/*  Reset button pressed  */
		pressed_time ++;
		if (pressed_time == (FACTORY_RESET_TIME+1)) {
			diag_printf("Factory default!\n");

#ifdef	CONFIG_LED
			/*  Blink twice per second  */
			LED_set(LED_ID_STAT, LED_BLINK, HZ/2);
#endif
		}
	}

	/*  Schedule next check*/
	timeout(&swrst_chk, 0, SWRST_CHECK_TIME);
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
void swrst_init(void)
{
#ifdef	CONFIG_RST
	CONFIG_SWRST();
	ENABLE_SWRST();
#endif
	
	timeout(&swrst_chk, 0, SWRST_CHECK_TIME);
}


