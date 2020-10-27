/*
 * Tencent Cloud IoT AT library
 * Copyright (C) 2016 THL A29 Limited, a Tencent company. All rights reserved.

 * Licensed under the MIT License (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://opensource.org/licenses/MIT

 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __QCLOUD_AT_FLASH_H__
#define __QCLOUD_AT_FLASH_H__

#include "qcloud_iot_export.h"
#include <stddef.h>

#define VALID_MAGIC_CODE 0xC0DEF00D

#define MAX_SIZE_OF_CRYPT_PSK (64)

#define RESERVE_INFO_SIZE   (64)

/* SIZE of these structures should be multiple of 4 bytes (word aligned )*/

typedef struct _dev_info_ {
    uint32_t magic_header; /* VALID_MAGIC_CODE for valid info */
    uint32_t TLS_mode;
    char     product_id[MAX_SIZE_OF_PRODUCT_ID + 2];
    char     device_name[MAX_SIZE_OF_DEVICE_NAME + 4];
    char     device_secret[MAX_SIZE_OF_CRYPT_PSK + 8];
    char     product_region[MAX_SIZE_OF_PRODUCT_REGION + 8];
    char     reserve[RESERVE_INFO_SIZE];
    uint32_t crc32;

} sDevInfo;

typedef struct _prd_info_ {
    uint32_t magic_header; /* VALID_MAGIC_CODE for valid info */
    uint32_t TLS_mode;
    char     product_id[MAX_SIZE_OF_PRODUCT_ID + 2];
    char     device_name[MAX_SIZE_OF_DEVICE_NAME + 4];
    char     product_secret[MAX_SIZE_OF_CRYPT_PSK + 8];
    char     product_region[MAX_SIZE_OF_PRODUCT_REGION + 8];
    char     reserve[RESERVE_INFO_SIZE];
    uint32_t crc32;

} sPrdInfo;

#define MAX_SIZE_OF_MODULE_NAME 30
typedef struct _module_info_ {
    uint32_t magic_header; /* VALID_MAGIC_CODE for valid info */
    char     module_name[MAX_SIZE_OF_MODULE_NAME + 2];
    uint32_t module_flash_size;
    uint32_t wifi_led_gpio;
    uint32_t ota_info_addr;
    uint32_t ota_base_addr;
    uint32_t ota_max_size;
    uint32_t use_fixed_connid;
    uint32_t crc32;

} sModuleInfo;

#define OTA_FW_START_FLASH_ADDR (0x100000)
#define OTA_FW_MAX_FLASH_SIZE  (0x180000)
#define MAX_SIZE_OF_FW_NAME    32
#define MAX_SIZE_OF_FW_VERSION 32
#define MAX_SIZE_OF_FW_MD5     33

#define OTA_FW_MCU_DOWNLOADING 1
#define OTA_FW_MCU_VALID       2
#define OTA_FW_ESP_DOWNLOADING 3
#define OTA_FW_ESP_VALID       4

typedef struct _firmware_info_ {
    uint32_t magic_header;                           /* VALID_MAGIC_CODE for valid info */
    uint32_t fw_state;                               /* fw for MCU or ESP module, valid or not */
    uint32_t downloaded_size;                        /* size that has been downloaded */
    uint32_t fw_size;                                /* size of firmware */
    uint32_t fw_max_size_of_module;                  /* max size of firmware in this module */
    char     fw_name[MAX_SIZE_OF_FW_NAME + 4];       /* firmware name */
    char     fw_version[MAX_SIZE_OF_FW_VERSION + 4]; /* firmware version */
    char     fw_md5[MAX_SIZE_OF_FW_MD5 + 7];         /* MD5 string */
} sOTAFirmwareInfo;

typedef enum _eFlash_Err_Code_ {
    eFLASH_HEADER_ERR = -300, /*magic header error*/
    eFLASH_CRC32_ERR  = -301, /*CRC32 error*/
    eFLASH_CRYPT_ERR  = -302, /*crypt error*/
    eFLASH_OPS_ERR    = -303, /*ESP flash error*/
    eFLASH_NULL_ERR   = -304, /* NULL parameters error*/
} eFlash_Err_Code;

int          init_flash_addr();
int          load_module_info(sModuleInfo *info);
int          save_module_info(sModuleInfo *info);
sModuleInfo *get_module_info(void);

int load_dev_info(const char *entry, sDevInfo *info);
int save_dev_info(sDevInfo *info);
int clear_dev_info(void);

int load_prd_info(const char *entry, sPrdInfo *info);
int save_prd_info(sPrdInfo *info);
int clear_prd_info(void);

int load_fw_info(sOTAFirmwareInfo *info);
int save_fw_info(sOTAFirmwareInfo *info);
int clear_fw_info(void);

int read_fw_from_flash(void *dst_buf, uint32_t read_size_bytes, uint32_t fetched_bytes, uint32_t fw_size_bytes);
int save_fw_to_flash(uint32_t fw_size, uint32_t saved_size, const void *src_buf, uint32_t write_size);
int erase_fw_flash_sectors(uint32_t fw_size);

int check_err_log(uint32_t *log_cnt);
int load_err_log(void *log, size_t log_size);
int save_err_log(void *log, size_t log_size);
int clear_err_log(void);

#endif  //__QCLOUD_AT_FLASH_H__
