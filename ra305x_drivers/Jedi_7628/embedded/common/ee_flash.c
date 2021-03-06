/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 4F, No. 2 Technology 5th Rd.
 * Science-based Industrial Park
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright 2002-2004, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************

	Module Name:
	ee_flash.c

	Abstract:
	Miniport generic portion header file

	Revision History:
	Who         When          What
	--------    ----------    ----------------------------------------------
*/

#ifdef RTMP_FLASH_SUPPORT

#include	"rt_config.h"






#define EEPROM_DFT_FILE_DIR	"/etc_ro/wlan/"
#define EEPROM_1ST_FILE_DIR	"/etc_ro/Wireless/RT2860/"
#define EEPROM_2ND_FILE_DIR	"/etc_ro/Wireless/iNIC/"



static NDIS_STATUS rtmp_ee_flash_init(PRTMP_ADAPTER pAd, PUCHAR start);



static USHORT EE_FLASH_ID_LIST[]={
#ifdef RT305x
	0x3052,
	0x3051,
	0x3050,
	0x3350,
#endif /* RT305x */
#ifdef RT3352
	0x3352,
#endif /* RT3352 */
#ifdef RT5350
	0x5350,
#endif /* RT5350 */





#ifdef MT7628
    0x7628,
#endif
};

#define EE_FLASH_ID_NUM  (sizeof(EE_FLASH_ID_LIST) / sizeof(USHORT))



/*******************************************************************************
  *
  *	Flash-based EEPROM read/write procedures.
  *		some chips use the flash memory instead of internal EEPROM to save the
  *		calibration info, we need these functions to do the read/write.
  *
  ******************************************************************************/
BOOLEAN rtmp_ee_flash_read(PRTMP_ADAPTER pAd, UINT16 Offset, UINT16 *pValue)
{
	BOOLEAN IsEmpty = 0;

	if (!pAd->chipCap.ee_inited)
	{
		*pValue = 0xffff;
	}
	else
	{
		memcpy(pValue, pAd->eebuf + Offset, 2);
	}

	if ((*pValue == 0xffff) || (*pValue == 0x0000))
		IsEmpty = 1;

	return IsEmpty;
}


int rtmp_ee_flash_write(PRTMP_ADAPTER pAd, USHORT Offset, USHORT Data)
{
	if (pAd->chipCap.ee_inited)
	{
		memcpy(pAd->eebuf + Offset, &Data, 2);
		/*rt_nv_commit();*/
		/*rt_cfg_commit();*/
#ifdef MULTIPLE_CARD_SUPPORT
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("rtmp_ee_flash_write:pAd->MC_RowID = %d\n", pAd->MC_RowID));
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("E2P_OFFSET = 0x%08x\n", pAd->E2P_OFFSET_IN_FLASH[pAd->MC_RowID]));
		if ((pAd->E2P_OFFSET_IN_FLASH[pAd->MC_RowID]==0x48000) || (pAd->E2P_OFFSET_IN_FLASH[pAd->MC_RowID]==0x40000))
			RtmpFlashWrite(pAd->eebuf, pAd->E2P_OFFSET_IN_FLASH[pAd->MC_RowID], EEPROM_SIZE);
#else
		RtmpFlashWrite(pAd->eebuf, pAd->flash_offset, EEPROM_SIZE);
#endif /* MULTIPLE_CARD_SUPPORT */
	}
	return 0;
}


VOID rtmp_ee_flash_read_all(PRTMP_ADAPTER pAd, USHORT *Data)
{
	if (!pAd->chipCap.ee_inited)
		return;

	memcpy(Data, pAd->eebuf, EEPROM_SIZE);
}


VOID rtmp_ee_flash_write_all(PRTMP_ADAPTER pAd, USHORT *Data)
{
	if (!pAd->chipCap.ee_inited)
		return;
	memcpy(pAd->eebuf, Data, EEPROM_SIZE);
#ifdef MULTIPLE_CARD_SUPPORT
	MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("rtmp_ee_flash_write_all:pAd->MC_RowID = %d\n", pAd->MC_RowID));
	MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("E2P_OFFSET = 0x%08x\n", pAd->E2P_OFFSET_IN_FLASH[pAd->MC_RowID]));
	if ((pAd->E2P_OFFSET_IN_FLASH[pAd->MC_RowID]==0x48000) || (pAd->E2P_OFFSET_IN_FLASH[pAd->MC_RowID]==0x40000))
		RtmpFlashWrite(pAd->eebuf, pAd->E2P_OFFSET_IN_FLASH[pAd->MC_RowID], EEPROM_SIZE);
#else
	RtmpFlashWrite(pAd->eebuf, pAd->flash_offset, EEPROM_SIZE);
#endif /* MULTIPLE_CARD_SUPPORT */
}


static NDIS_STATUS rtmp_ee_flash_reset(RTMP_ADAPTER *pAd, UCHAR *start)
{
	PUCHAR src;
	RTMP_OS_FS_INFO osFsInfo;
	RTMP_OS_FD srcf;
	INT retval;

#ifdef RT_SOC_SUPPORT
#ifdef MULTIPLE_CARD_SUPPORT
	RTMP_STRING BinFilePath[128];
	RTMP_STRING *pBinFileName = NULL;
	UINT32	ChipVerion = (pAd->MACVersion >> 16);

	if (rtmp_get_default_bin_file_by_chip(pAd, ChipVerion, &pBinFileName) == TRUE)
	{
		if (pAd->MC_RowID > 0)
			sprintf(BinFilePath, "%s%s", EEPROM_2ND_FILE_DIR, pBinFileName);
		else
			sprintf(BinFilePath, "%s%s", EEPROM_1ST_FILE_DIR, pBinFileName);

		src = BinFilePath;
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("%s(): src = %s\n", __FUNCTION__, src));
	}
	else
#endif /* MULTIPLE_CARD_SUPPORT */
#endif /* RT_SOC_SUPPORT */
	{
#if defined(MT_MAC) && defined(MT7603)
		if (IS_MT7603(pAd))
		{
			src = EEPROM_DEFAULT_7603_FILE_PATH;
		}
		else
#endif /* MT_MAC && MT7603 */
		{
			src = EEPROM_DEFAULT_FILE_PATH;
		}
	}

	RtmpOSFSInfoChange(&osFsInfo, TRUE);

	if (src && *src)
	{
		srcf = RtmpOSFileOpen(src, O_RDONLY, 0);
		if (IS_FILE_OPEN_ERR(srcf))
		{
			MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("--> Error opening file %s\n", src));
			if ( pAd->chipCap.EEPROM_DEFAULT_BIN != NULL )
			{
				NdisMoveMemory(start, pAd->chipCap.EEPROM_DEFAULT_BIN,
					pAd->chipCap.EEPROM_DEFAULT_BIN_SIZE > MAX_EEPROM_BUFFER_SIZE?MAX_EEPROM_BUFFER_SIZE:pAd->chipCap.EEPROM_DEFAULT_BIN_SIZE);
				MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("Load EEPROM Buffer from default BIN.\n"));
				return NDIS_STATUS_SUCCESS;
			}
			else
			{
			return NDIS_STATUS_FAILURE;
		}
		}
		else
		{
			/* The object must have a read method*/
			NdisZeroMemory(start, EEPROM_SIZE);

			retval = RtmpOSFileRead(srcf, start, EEPROM_SIZE);
			if (retval < 0)
			{
				MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("--> Read %s error %d\n", src, -retval));
			}
			else
			{
				MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("--> rtmp_ee_flash_reset copy %s to eeprom buffer\n", src));
			}

			retval = RtmpOSFileClose(srcf);
			if (retval)
			{
				MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("--> Error %d closing %s\n", -retval, src));
			}
		}
	}

	RtmpOSFSInfoChange(&osFsInfo, FALSE);

	return NDIS_STATUS_SUCCESS;
}



static BOOLEAN  validFlashEepromID(RTMP_ADAPTER *pAd)
{
	USHORT eeFlashId;
	int listIdx;

	rtmp_ee_flash_read(pAd, 0, &eeFlashId);
	for(listIdx =0 ; listIdx < EE_FLASH_ID_NUM; listIdx++)
	{
		if (eeFlashId == EE_FLASH_ID_LIST[listIdx])
		{
			return TRUE;
		}
	}
	return FALSE;
}


static NDIS_STATUS rtmp_ee_flash_init(PRTMP_ADAPTER pAd, PUCHAR start)
{
#ifdef CAL_FREE_IC_SUPPORT
	BOOLEAN bCalFree=0;
#endif /* CAL_FREE_IC_SUPPORT */

	pAd->chipCap.ee_inited = 1;

	if (validFlashEepromID(pAd) == FALSE)
	{
		if (rtmp_ee_flash_reset(pAd, start) != NDIS_STATUS_SUCCESS)
		{
			MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_ERROR, ("rtmp_ee_init(): rtmp_ee_flash_init() failed\n"));
			return NDIS_STATUS_FAILURE;
		}

#ifdef CAL_FREE_IC_SUPPORT
		RTMP_CAL_FREE_IC_CHECK(pAd,bCalFree);
		if (bCalFree)
		{
			MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("Cal Free IC!!\n"));
			RTMP_CAL_FREE_DATA_GET(pAd);
		}
		else
		{
			MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("Non Cal Free IC!!\n"));
		}
		
#endif /* CAL_FREE_IC_SUPPORT */

	
		/* Random number for the last bytes of MAC address*/
		{
			USHORT  Addr45;

			rtmp_ee_flash_read(pAd, 0x08, &Addr45);
			Addr45 = Addr45 & 0xff;
			Addr45 = Addr45 | (RandomByte(pAd)&0xf8) << 8;
			MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_ERROR, ("The EEPROM in Flash is wrong, use default\n"));
		}

		/*write back  all to flash*/
		rtmp_ee_flash_write_all(pAd,pAd->EEPROMImage);

		if (validFlashEepromID(pAd) == FALSE)
		{
			MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_ERROR, ("rtmp_ee_flash_init(): invalid eeprom\n"));
			return NDIS_STATUS_FAILURE;
		}
	}

	return NDIS_STATUS_SUCCESS;
}


NDIS_STATUS rtmp_nv_init(RTMP_ADAPTER *pAd)
{
#ifdef MULTIPLE_CARD_SUPPORT
	UCHAR *eepromBuf;
#endif /* MULTIPLE_CARD_SUPPORT */

	MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_TRACE, ("--> rtmp_nv_init\n"));

#ifdef __ECOS
	int stat;

	pAd->eebuf = pAd->EEPROMImage;
	if ((stat = cyg_flash_init(NULL)) != 0)
	{
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_ERROR, ("FLASH: driver init failed: %s\n", cyg_flash_errmsg(stat)));
        	return -1;
   	}
	
	if (pAd->chipCap.EEPROM_DEFAULT_BIN == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("pAd->chipCap.EEPROM_DEFAULT_BIN == NULL!!!\n"));
		return NDIS_STATUS_FAILURE;
	}

	{
		UCHAR *eepromBuf;

		if (os_alloc_mem(pAd, &eepromBuf, EEPROM_SIZE) == NDIS_STATUS_SUCCESS)
		{
			NdisZeroMemory(eepromBuf, EEPROM_SIZE);
			NdisMoveMemory(eepromBuf, pAd->chipCap.EEPROM_DEFAULT_BIN, EEPROM_SIZE);
			RtmpFlashRead(pAd->eebuf, pAd->flash_offset, EEPROM_SIZE);
			pAd->chipCap.ee_inited = 1;
			if (validFlashEepromID(pAd) == FALSE)
			{
				MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_ERROR, ("The EEPROM in Flash are wrong, use default\n"));
				NdisMoveMemory(pAd->eebuf, eepromBuf, EEPROM_SIZE);
			}
			os_free_mem(pAd, eepromBuf);
		}
	}
	return NDIS_STATUS_SUCCESS;
#else

/*
	if (pAd->chipCap.EEPROMImage == NULL)
	{
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_ERROR, ("pAd->chipCap.EEPROMImage == NULL!!!\n"));
		return NDIS_STATUS_FAILURE;
	}
*/

/*	ASSERT((pAd->eebuf == NULL)); */
	pAd->eebuf = pAd->EEPROMImage;
#ifdef MULTIPLE_CARD_SUPPORT
	MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("rtmp_nv_init:pAd->MC_RowID = %d\n", pAd->MC_RowID));
	os_alloc_mem(pAd, &eepromBuf, EEPROM_SIZE);
	if (eepromBuf)
	{
		pAd->eebuf = eepromBuf;
		NdisMoveMemory(pAd->eebuf, pAd->chipCap.EEPROM_DEFAULT_BIN, EEPROM_SIZE);
		}
	else
	{
		MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_ERROR,("rtmp_nv_init:Alloc memory for pAd->MC_RowID[%d] failed! used default one!\n", pAd->MC_RowID));
	}
	MTWF_LOG(DBG_CAT_ALL, DBG_SUBCAT_ALL, DBG_LVL_OFF, ("E2P_OFFSET = 0x%08x\n", pAd->E2P_OFFSET_IN_FLASH[pAd->MC_RowID]));
	RtmpFlashRead(pAd->eebuf, pAd->E2P_OFFSET_IN_FLASH[pAd->MC_RowID], EEPROM_SIZE);
#else
	RtmpFlashRead(pAd->eebuf, pAd->flash_offset, EEPROM_SIZE);
#endif /* MULTIPLE_CARD_SUPPORT */

	return rtmp_ee_flash_init(pAd, pAd->eebuf);
#endif /* __ECOS */
}

#endif /* RTMP_FLASH_SUPPORT */

