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
    led.h

    Abstract:

    Revision History:
    Who         When            What
    --------    ----------      ------------------------------------------
*/

#ifndef LED_H
#define LED_H

typedef struct led_stat_t
{
	cyg_tick_count_t last_tick;
	unsigned short period;
#ifndef	CONFIG_WP322X
	char stat;
	int gpio;
#else
	int stat;
	int gpio;
	int group;
#endif
} LED_STAT;


enum {
	LED_OFF=0,
	LED_ON,
	LED_BLINK,
	LED_TOGGLE,
	LED_OFF2,
	LED_ON2,
	LED_TOGGLE2
};

#define	LED_MIN_PERIOD		10
#define	LED_MAX_PERIOD		0xffff
// after the toggle, 1 seconds later, reset the LED to orginal state
#define	LED_RECHECK_PERIOD		100
// minium between two toggle

extern int LED_ID_STAT;

int LED_set(int id, int stat, int period);
int LED_init(void);
int LED_cmd(int status);

#endif /* LED_H */


