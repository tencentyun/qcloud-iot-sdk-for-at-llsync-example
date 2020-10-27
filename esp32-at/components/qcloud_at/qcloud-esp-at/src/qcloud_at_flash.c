/*
 * Tencent is pleased to support the open source community by making IoT Hub available.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "esp_at.h"
#include "mbedtls/base64.h"
#include "mbedtls/aes.h"
#include "esp_spi_flash.h"
#include "esp32/rom/crc.h"
#include "qcloud_iot_export_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "qcloud_at_flash.h"

/****************************** device info cryption *******************************************/

#define UTILS_AES_BLOCK_LEN 16

#define MAX_SIZE_OF_DEVICE_SECRET (44)
#define MAX_SIZE_OF_CRYPT_PSK     (64)
#define MAX_SIZE_OF_DEVICE_NAME   (48)
#define MAX_SIZE_OF_PRODUCT_ID    (10)

#define uLog(fmt, ...) printf("%s(%d): " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define MBEDTLS_AES_BLOCK_LEN 16
#define MBEDTLS_AES_KEY_BITS  128

#define UTILS_AES_ENCRYPT MBEDTLS_AES_ENCRYPT /**< AES encryption. */
#define UTILS_AES_DECRYPT MBEDTLS_AES_DECRYPT /**< AES decryption. */

#define UTILS_MODE_ENCRYPT 1
#define UTILS_MODE_DECRYPT 0

static int utils_crypt_data(uint8_t *pInData, size_t *data_len, uint8_t *pOutData, uint8_t mode, uint8_t *pKey,
                            uint8_t *iv)
{
    int                 ret     = 0;
    uint16_t            keybits = MBEDTLS_AES_KEY_BITS;
    int                 padlen  = 0;
    size_t              datalen = *data_len;
    mbedtls_aes_context ctx;

    mbedtls_aes_init(&ctx);

    if (MBEDTLS_AES_ENCRYPT == mode) {
        ret = mbedtls_aes_setkey_enc(&ctx, pKey, keybits);
        if (ret != 0) {
            uLog("Set encrypt key err, ret:%d", ret);
            ret = -1;
            goto exit;
        }

        if (datalen % MBEDTLS_AES_BLOCK_LEN) {
            padlen = MBEDTLS_AES_BLOCK_LEN - datalen % MBEDTLS_AES_BLOCK_LEN;
            memcpy(pOutData, pInData, datalen);
            memset(pOutData + datalen, '\0', padlen); /*zero-padding*/
            datalen += padlen;
            *data_len = datalen;
        }

    } else {
        ret = mbedtls_aes_setkey_dec(&ctx, pKey, keybits);
        if (ret != 0) {
            uLog("Set decrypt key err, ret:%d", ret);
            ret = -1;
            goto exit;
        }
    }

    ret = mbedtls_aes_crypt_cbc(&ctx, mode, datalen, iv, pInData, pOutData);
    if (ret != 0) {
        uLog("crypt(mode %u len %u) err, ret: %d", mode, datalen, ret);
        ret = -1;
        goto exit;
    } else {
        ret = 0;
    }

exit:
    mbedtls_aes_free(&ctx);

    return ret;
}

static void byte_shift(uint8_t *data, size_t len)
{
    uint8_t temp;
    int     i = 0;
    while (i < (len - 1)) {
        temp        = data[i];
        data[i]     = data[i + 1];
        data[i + 1] = temp;
        i += 2;
    }
}

static int crypt_devinfo(char *product_id, char *device_name, char *device_sec, uint8_t mode)
{
    //#define DEBUG_CRYPT_DEVINFO
    if (device_sec == NULL || product_id == NULL || device_name == NULL) {
        uLog("null devinfo: %p %p %p", product_id, device_name, device_sec);
        return -1;
    }

    if (mode != UTILS_AES_DECRYPT && mode != UTILS_AES_ENCRYPT) {
        uLog("invalid mode: %d", mode);
        return -1;
    }

    unsigned char key[UTILS_AES_BLOCK_LEN] = "oldsoldierneverD";
    unsigned char iv[UTILS_AES_BLOCK_LEN];
    uint8_t       data_out[MAX_SIZE_OF_CRYPT_PSK + 1] = {0};
    int           ret                                 = 0;
    uint8_t *     data_in                             = (uint8_t *)device_sec;
    size_t        sec_len, base64_len;
    int           i = 0;

    if (mode == UTILS_AES_ENCRYPT) {
        sec_len = strnlen(device_sec, MAX_SIZE_OF_DEVICE_SECRET + 1);

        if (sec_len == 0 || sec_len > (MAX_SIZE_OF_DEVICE_SECRET)) {
            uLog("invalid sec len: %d for encrypt mode", sec_len);
            return -1;
        }
    } else {
        sec_len = strnlen(device_sec, MAX_SIZE_OF_CRYPT_PSK + 1);

        if (sec_len == 0 || sec_len > (MAX_SIZE_OF_CRYPT_PSK)) {
            uLog("invalid sec len: %d for decrypt mode", sec_len);
            return -1;
        }
    }

    size_t dev_name_len = strnlen(device_name, MAX_SIZE_OF_DEVICE_NAME);
    size_t key_pos      = dev_name_len % 6;
    memcpy((char *)(key + key_pos), product_id, MAX_SIZE_OF_PRODUCT_ID);
    size_t alphabet = dev_name_len % 10;
    for (i = 0; i < UTILS_AES_BLOCK_LEN; i++) iv[i] = 'A' + alphabet + i;

#ifdef DEBUG_CRYPT_DEVINFO
    uLog("data before %s: %s", mode == UTILS_AES_ENCRYPT ? "encrypt" : "decrypt", device_sec);
    for (i = 0; i < sec_len; i++) {
        printf("%02x ", device_sec[i]);
    }
    printf("\nkey: ");
    for (i = 0; i < UTILS_AES_BLOCK_LEN; i++) printf("%c", key[i]);
    printf("\niv: ");
    for (i = 0; i < UTILS_AES_BLOCK_LEN; i++) printf("%c", iv[i]);
    printf("\n");
#endif

    if (mode == UTILS_AES_ENCRYPT) {
        ret = utils_crypt_data(data_in, &sec_len, data_in, mode, key, iv);
        if (ret) {
            uLog("encrypt failed: %d", ret);
            return -1;
        }

#ifdef DEBUG_CRYPT_DEVINFO
        uLog("data before encode:");
        for (i = 0; i < sec_len; i++) {
            printf("%02x ", data_in[i]);
        }
        printf("\n");
#endif

        byte_shift(data_in, sec_len);

        ret = mbedtls_base64_encode(data_out, sizeof(data_out), &base64_len, data_in, sec_len);
        if (ret) {
            uLog("encode failed: %d", ret);
            return -1;
        }
        sec_len = strnlen((char *)data_out, MAX_SIZE_OF_CRYPT_PSK);
        memcpy((uint8_t *)device_sec, data_out, sec_len);

    } else {
        ret = mbedtls_base64_decode(data_out, sizeof(data_out), &base64_len, data_in, sec_len);
        if (ret) {
            uLog("decode failed: %d", ret);
            return -1;
        }
        byte_shift(data_out, base64_len);

        ret = utils_crypt_data(data_out, &base64_len, data_out, mode, key, iv);
        if (ret) {
            uLog("decrypt failed: %d", ret);
            return -1;
        }

        memcpy((uint8_t *)device_sec, data_out, sizeof(data_out));
        sec_len = strnlen((char *)data_out, MAX_SIZE_OF_DEVICE_SECRET);
    }

#ifdef DEBUG_CRYPT_DEVINFO
    uLog("data after %s: %s", mode == UTILS_AES_ENCRYPT ? "encrypt" : "decrypt", device_sec);
    for (i = 0; i < sec_len; i++) {
        printf("%02x ", device_sec[i]);
    }
    printf("\n");
#endif

    return 0;
}

/****************************** device info cryption *******************************************/

/*
ESP8266 IDF FLASH partitions
addr               sector   name                        size
0x000000-0x008000   0       "bootloader.bin"            12KB
0x008000-0x009000   8       "partitions_at.bin"         4KB
0x009000-0x00b000   9       "ota_data_initial.bin"      8KB
0x010000-0x0f0000   16      "ESP8266_QCLOUD_AT.bin(0)"  0xE0000(896KB)
0x0f0000-0x110000   240     "nvs"                       128KB
0x110000-0x1f0000   272     "ESP8266_QCLOUD_AT.bin(1)"  0xE0000(896KB)
0x1f0000-0x1f1000   496     "at_customize.bin"          4KB
0x1f1000-0x1f2000   497     "factory_param.bin"         4KB

0x1f8000-0x1f9000   504     "qcloud_modinfo.bin"        4KB
0x1f9000-0x1fa000   505     "qcloud_devinfo.bin"        4KB
0x1fa000-0x1fb000   506     "qcloud_prdinfo.bin"        4KB
0x1fb000-0x1fc000   507     "qcloud_otainfo.bin"        4KB
0x1fc000-0x1fd000   507     "qcloud_errlog.bin"         4KB

* OTA 2MB FLASH partitions
0x110000-0x1f0000   272     "ota.FW"                    0xE0000(896KB)

* OTA 4MB FLASH partitions
0x210000-0x310000   528     "ota.usr.FW"                0x100000(1024KB)
*/

#define MODULE_INFO_FLASH_ADDR (0x3D000)
#define DEV_INFO_FLASH_ADDR    (0x3E000)
#define PRD_INFO_FLASH_ADDR    (0x3F000)
#define FW_INFO_FLASH_ADDR     (0x40000)
#define ERR_LOG_FLASH_ADDR     (0x41000)

size_t g_module_info_addr = MODULE_INFO_FLASH_ADDR;
size_t g_devinfo_addr     = DEV_INFO_FLASH_ADDR;
size_t g_prdinfo_addr     = PRD_INFO_FLASH_ADDR;
size_t g_errlog_addr      = ERR_LOG_FLASH_ADDR;

size_t      g_fw_info_addr = FW_INFO_FLASH_ADDR;
size_t      g_fw_base_addr = OTA_FW_START_FLASH_ADDR;
size_t      g_fw_max_size  = OTA_FW_MAX_FLASH_SIZE;
sModuleInfo g_this_module_info;

uint32_t get_ota_base_addr(void)
{
    esp_partition_t *      partition_ptr = NULL;
    esp_partition_t        partition;
    const esp_partition_t *next_partition = NULL;

    // search ota partition
    partition_ptr = (esp_partition_t *)esp_ota_get_boot_partition();
    if (partition_ptr == NULL) {
        Log_e("esp boot partition NULL!");
        return 0;
    }

    Log_i("current fw partition type: %d subtype: %d addr: 0x%x label: %s", partition_ptr->type, partition_ptr->subtype,
          partition_ptr->address, partition_ptr->label);

    if (partition_ptr->type != ESP_PARTITION_TYPE_APP) {
        Log_e("esp_current_partition->type != ESP_PARTITION_TYPE_APP");
        return 0;
    }

    if (partition_ptr->subtype == ESP_PARTITION_SUBTYPE_APP_FACTORY) {
        partition.subtype = ESP_PARTITION_SUBTYPE_APP_OTA_0;
    } else {
        next_partition = esp_ota_get_next_update_partition(partition_ptr);

        if (next_partition) {
            partition.subtype = next_partition->subtype;
        } else {
            partition.subtype = ESP_PARTITION_SUBTYPE_APP_OTA_0;
        }
    }

    partition.type = ESP_PARTITION_TYPE_APP;

    partition_ptr = (esp_partition_t *)esp_partition_find_first(partition.type, partition.subtype, NULL);
    if (partition_ptr == NULL) {
        Log_e("esp app partition NULL!");
        return 0;
    }

    Log_i("download partition type: %d subtype: %d addr: 0x%x label: %s", partition_ptr->type, partition_ptr->subtype,
          partition_ptr->address, partition_ptr->label);

    return partition_ptr->address;
}

int init_flash_addr()
{
    const esp_partition_t *partition = esp_at_custom_partition_find(0x40, 0xff, "qcloud_devinfo");
    if (partition) {
        g_devinfo_addr = partition->address;
    } else {
        g_devinfo_addr = DEV_INFO_FLASH_ADDR;
        Log_e("read devinfo partition failed. use default addr: 0x%x", g_devinfo_addr);
    }

    partition = esp_at_custom_partition_find(0x40, 0xff, "qcloud_prdinfo");
    if (partition) {
        g_prdinfo_addr = partition->address;
    } else {
        g_prdinfo_addr = PRD_INFO_FLASH_ADDR;
        Log_e("read prdinfo partition failed. use default addr: 0x%x", g_prdinfo_addr);
    }

    partition = esp_at_custom_partition_find(0x40, 0xff, "qcloud_errlog");
    if (partition) {
        g_errlog_addr = partition->address;
    } else {
        g_errlog_addr = ERR_LOG_FLASH_ADDR;
        Log_e("read errlog partition failed. use default addr: 0x%x", g_errlog_addr);
    }

    partition = esp_at_custom_partition_find(0x40, 0xff, "qcloud_modinfo");
    if (partition) {
        g_module_info_addr = partition->address;
    } else {
        g_module_info_addr = MODULE_INFO_FLASH_ADDR;
        Log_e("read modinfo partition failed. use default addr: 0x%x", g_module_info_addr);
    }

    partition = esp_at_custom_partition_find(0x40, 0xff, "qcloud_fwinfo");
    if (partition) {
        g_fw_info_addr = partition->address;
    } else {
        g_fw_info_addr = FW_INFO_FLASH_ADDR;
        Log_e("read fwinfo partition failed. use default addr: 0x%x", g_fw_info_addr);
    }

    if (load_module_info(&g_this_module_info)) {
        Log_e("load module info failed. use default value");
        g_this_module_info.module_flash_size = 2;
        g_this_module_info.ota_info_addr     = FW_INFO_FLASH_ADDR;
        g_this_module_info.ota_base_addr     = OTA_FW_START_FLASH_ADDR;
        g_this_module_info.ota_max_size      = OTA_FW_MAX_FLASH_SIZE;
        g_this_module_info.wifi_led_gpio     = 5;
        g_this_module_info.use_fixed_connid  = 1;
        strcpy(g_this_module_info.module_name, "ESP-DEFAULT-2MB");
    }

    // for 2MB flash, fw_addr is reused with self-OTA so have to get it from partition table
    if (g_this_module_info.module_flash_size == 2) {
        g_fw_base_addr                   = get_ota_base_addr();
        g_this_module_info.ota_base_addr = g_fw_base_addr;
    } else {
        g_fw_base_addr = g_this_module_info.ota_base_addr;
    }
    g_fw_max_size                    = g_this_module_info.ota_max_size;
    g_this_module_info.ota_info_addr = g_fw_info_addr;

    return 0;
}

int load_module_info(sModuleInfo *pModuleInfo)
{
    esp_err_t ret;
    memset((char *)pModuleInfo, 0, sizeof(sModuleInfo));
    ret = spi_flash_read(g_module_info_addr, (uint32_t *)pModuleInfo, sizeof(sModuleInfo));
    if (ESP_OK != ret) {
        Log_e("spi_flash_read error: %d", ret);
        return (int)ret;
    }

    /* not a valid info */
    if (pModuleInfo->magic_header != VALID_MAGIC_CODE) {
        Log_w("invalid header: 0x%x", pModuleInfo->magic_header);
        memset((char *)pModuleInfo, 0, sizeof(sModuleInfo));
        return eFLASH_HEADER_ERR;
    }

    uint32_t crc32 = crc32_le(0, (uint8_t *)pModuleInfo, sizeof(sModuleInfo) - sizeof(uint32_t));
    if (crc32 != pModuleInfo->crc32) {
        Log_e("invalid crc: 0x%x calc: 0x%x", pModuleInfo->crc32, crc32);
        memset((char *)pModuleInfo, 0, sizeof(sModuleInfo));
        return eFLASH_CRC32_ERR;
    }

    return 0;
}

int save_module_info(sModuleInfo *pModuleInfo)
{
    esp_err_t ret;

    ret = spi_flash_erase_sector(g_module_info_addr / SPI_FLASH_SEC_SIZE);
    if (ESP_OK != ret) {
        Log_e("spi_flash_erase error: %d", ret);
        return (int)ret;
    }

    pModuleInfo->ota_info_addr = g_fw_info_addr;

    pModuleInfo->crc32 = crc32_le(0, (uint8_t *)pModuleInfo, sizeof(sModuleInfo) - sizeof(uint32_t));
    ret                = spi_flash_write(g_module_info_addr, (uint32_t *)pModuleInfo, sizeof(sModuleInfo));
    if (ESP_OK != ret) {
        Log_e("spi_flash_write error: %d", ret);
        return (int)ret;
    }

    memcpy(&g_this_module_info, pModuleInfo, sizeof(sModuleInfo));

    return 0;
}

sModuleInfo *get_module_info(void)
{
    return &g_this_module_info;
}

static const char *_get_filename(const char *p)
{
    char        ch = '/';
    const char *q  = strrchr(p, ch);
    if (q == NULL) {
        q = p;
    } else {
        q++;
    }
    return q;
}

typedef struct _old_dev_info_ {
    uint32_t magic_header; /* VALID_MAGIC_CODE for valid info */
    uint32_t TLS_mode;
    char     product_id[MAX_SIZE_OF_PRODUCT_ID + 2];
    char     device_name[MAX_SIZE_OF_DEVICE_NAME + 4];
    char     device_secret[MAX_SIZE_OF_CRYPT_PSK + 8];
    uint32_t crc32;

} sOldDevInfo;

typedef struct _old_prd_info_ {
    uint32_t magic_header; /* VALID_MAGIC_CODE for valid info */
    uint32_t TLS_mode;
    char     product_id[MAX_SIZE_OF_PRODUCT_ID + 2];
    char     device_name[MAX_SIZE_OF_DEVICE_NAME + 4];
    char     product_secret[MAX_SIZE_OF_CRYPT_PSK + 8];
    uint32_t crc32;

} sOldPrdInfo;


int load_dev_info(const char *entry, sDevInfo *pdevInfo)
{
    esp_err_t ret;
    if (pdevInfo->magic_header != 0x0feedbeef) {
        memset((char *)pdevInfo, 0, sizeof(sDevInfo));
        return 0;
    }

    const char *filename = _get_filename(entry);
    if (0 != strcmp("qcloud_at_cmd.c", filename) && 0 != strcmp("qcloud_wifi_config.c", filename) &&
        0 != strcmp("qcloud_at_flash.c", filename)) {
        memset((char *)pdevInfo, 0, sizeof(sDevInfo));
        return 0;
    }

    memset((char *)pdevInfo, 0, sizeof(sDevInfo));
    ret = spi_flash_read(g_devinfo_addr, (uint32_t *)pdevInfo, sizeof(sDevInfo));
    if (ESP_OK != ret) {
        Log_e("spi_flash_read error: %d", ret);
        return (int)ret;
    }

    /* not a valid info */
    if (pdevInfo->magic_header != VALID_MAGIC_CODE) {
        Log_w("invalid header: 0x%x", pdevInfo->magic_header);
        memset((char *)pdevInfo, 0, sizeof(sDevInfo));
        return eFLASH_HEADER_ERR;
    }

    uint32_t crc32 = crc32_le(0, (uint8_t *)pdevInfo, sizeof(sDevInfo) - sizeof(uint32_t));
    if (crc32 != pdevInfo->crc32) {
        Log_e("invalid crc: 0x%x calc: 0x%x", pdevInfo->crc32, crc32);

        sOldDevInfo *old_dev = (sOldDevInfo *)pdevInfo;
        crc32 = crc32_le(0, (uint8_t *)old_dev, sizeof(sOldDevInfo) - sizeof(uint32_t));
        if (crc32 != old_dev->crc32) {
            Log_e("invalid legacy crc: 0x%x calc: 0x%x", pdevInfo->crc32, crc32);
            memset((char *)pdevInfo, 0, sizeof(sDevInfo));
            return eFLASH_CRC32_ERR;
        } else {
            // update from legacy data structure
            memset(pdevInfo->product_region, 0, MAX_SIZE_OF_PRODUCT_REGION + 8);
            strcpy(pdevInfo->product_region, DEFAULT_HOST_REGION);
            memset(pdevInfo->reserve, 0, RESERVE_INFO_SIZE);

            pdevInfo->crc32 = crc32_le(0, (uint8_t *)pdevInfo, sizeof(sDevInfo) - sizeof(uint32_t));

            ret = spi_flash_erase_sector(g_devinfo_addr / SPI_FLASH_SEC_SIZE);
            if (ESP_OK != ret) {
                Log_e("spi_flash_erase error: %d", ret);
            }

            ret = spi_flash_write(g_devinfo_addr, (uint32_t *)pdevInfo, sizeof(sDevInfo));
            if (ESP_OK != ret) {
                Log_e("spi_flash_write error: %d", ret);
            }
        }
    }

    ret = crypt_devinfo(pdevInfo->product_id, pdevInfo->device_name, pdevInfo->device_secret, UTILS_MODE_DECRYPT);
    if (ret) {
        Log_e("crypt devinfo error: %d", ret);
        return eFLASH_CRYPT_ERR;
    }

    return 0;
}

int save_dev_info(sDevInfo *pdevInfo)
{
    esp_err_t ret;

    if (pdevInfo == NULL) {
        Log_e("invalid dev info");
        return eFLASH_NULL_ERR;
    }

    ret = crypt_devinfo(pdevInfo->product_id, pdevInfo->device_name, pdevInfo->device_secret, UTILS_MODE_ENCRYPT);
    if (ret) {
        Log_e("crypt devinfo error: %d", ret);
        return eFLASH_CRYPT_ERR;
    }

    pdevInfo->crc32 = crc32_le(0, (uint8_t *)pdevInfo, sizeof(sDevInfo) - sizeof(uint32_t));

    ret = spi_flash_erase_sector(g_devinfo_addr / SPI_FLASH_SEC_SIZE);
    if (ESP_OK != ret) {
        Log_e("spi_flash_erase error: %d", ret);
        return (int)ret;
    }

    ret = spi_flash_write(g_devinfo_addr, (uint32_t *)pdevInfo, sizeof(sDevInfo));
    if (ESP_OK != ret) {
        Log_e("spi_flash_write error: %d", ret);
        return (int)ret;
    }

    return 0;
}

int clear_dev_info(void)
{
    esp_err_t ret = spi_flash_erase_sector(g_devinfo_addr / SPI_FLASH_SEC_SIZE);
    if (ESP_OK != ret) {
        Log_e("spi_flash_erase error: %d", ret);
        return (int)ret;
    }

    return 0;
}

int load_prd_info(const char *entry, sPrdInfo *info)
{
    esp_err_t ret;
    if (info->magic_header != 0x0feedbeef) {
        memset((char *)info, 0, sizeof(sPrdInfo));
        return 0;
    }

    const char *filename = _get_filename(entry);
    if (0 != strcmp("qcloud_at_cmd.c", filename) && 0 != strcmp("qcloud_wifi_config.c", filename) &&
        0 != strcmp("qcloud_at_flash.c", filename)) {
        memset((char *)info, 0, sizeof(sPrdInfo));
        return 0;
    }

    memset((char *)info, 0, sizeof(sPrdInfo));
    ret = spi_flash_read(g_prdinfo_addr, (uint32_t *)info, sizeof(sPrdInfo));
    if (ESP_OK != ret) {
        Log_e("spi_flash_read error: %d", ret);
        return (int)ret;
    }

    /* not a valid info */
    if (info->magic_header != VALID_MAGIC_CODE) {
        Log_w("invalid header: 0x%x", info->magic_header);
        memset((char *)info, 0, sizeof(sPrdInfo));
        return eFLASH_HEADER_ERR;
    }

    uint32_t crc32 = crc32_le(0, (uint8_t *)info, sizeof(sPrdInfo) - sizeof(uint32_t));
    if (crc32 != info->crc32) {
        Log_e("invalid crc: 0x%x calc: 0x%x", info->crc32, crc32);

        sOldPrdInfo *old_dev = (sOldPrdInfo *)info;
        crc32 = crc32_le(0, (uint8_t *)old_dev, sizeof(sOldPrdInfo) - sizeof(uint32_t));
        if (crc32 != old_dev->crc32) {
            Log_e("invalid legacy crc: 0x%x calc: 0x%x", info->crc32, crc32);
            memset((char *)info, 0, sizeof(sPrdInfo));
            return eFLASH_CRC32_ERR;
        } else {
            // update from legacy data structure
            memset(info->product_region, 0, MAX_SIZE_OF_PRODUCT_REGION + 8);
            strcpy(info->product_region, DEFAULT_HOST_REGION);
            memset(info->reserve, 0, RESERVE_INFO_SIZE);

            info->crc32 = crc32_le(0, (uint8_t *)info, sizeof(sPrdInfo) - sizeof(uint32_t));

            ret = spi_flash_erase_sector(g_prdinfo_addr / SPI_FLASH_SEC_SIZE);
            if (ESP_OK != ret) {
                Log_e("spi_flash_erase error: %d", ret);
            }

            ret = spi_flash_write(g_prdinfo_addr, (uint32_t *)info, sizeof(sPrdInfo));
            if (ESP_OK != ret) {
                Log_e("spi_flash_write error: %d", ret);
            }
        }
    }

    ret = crypt_devinfo(info->product_id, info->device_name, info->product_secret, UTILS_MODE_DECRYPT);
    if (ret) {
        Log_e("crypt devinfo error: %d", ret);
        return eFLASH_CRYPT_ERR;
    }

    return 0;
}

int save_prd_info(sPrdInfo *info)
{
    esp_err_t ret;

    if (info == NULL) {
        Log_e("invalid dev info");
        return eFLASH_NULL_ERR;
    }

    ret = crypt_devinfo(info->product_id, info->device_name, info->product_secret, UTILS_MODE_ENCRYPT);
    if (ret) {
        Log_e("crypt devinfo error: %d", ret);
        return eFLASH_CRYPT_ERR;
    }

    info->crc32 = crc32_le(0, (uint8_t *)info, sizeof(sPrdInfo) - sizeof(uint32_t));

    ret = spi_flash_erase_sector(g_prdinfo_addr / SPI_FLASH_SEC_SIZE);
    if (ESP_OK != ret) {
        Log_e("spi_flash_erase error: %d", ret);
        return (int)ret;
    }

    ret = spi_flash_write(g_prdinfo_addr, (uint32_t *)info, sizeof(sPrdInfo));
    if (ESP_OK != ret) {
        Log_e("spi_flash_write error: %d", ret);
        return (int)ret;
    }

    return 0;
}

int clear_prd_info(void)
{
    esp_err_t ret = spi_flash_erase_sector(g_prdinfo_addr / SPI_FLASH_SEC_SIZE);
    if (ESP_OK != ret) {
        Log_e("spi_flash_erase error: %d", ret);
        return (int)ret;
    }

    return 0;
}

int load_fw_info(sOTAFirmwareInfo *pFirmwareInfo)
{
    esp_err_t ret;
    memset((char *)pFirmwareInfo, 0, sizeof(sOTAFirmwareInfo));
    ret = spi_flash_read(g_fw_info_addr, (uint32_t *)pFirmwareInfo, sizeof(sOTAFirmwareInfo));
    if (ESP_OK != ret) {
        Log_e("spi_flash_read error: %d", ret);
        return (int)ret;
    }

    /* not a valid info */
    if (pFirmwareInfo->magic_header != VALID_MAGIC_CODE) {
        Log_w("invalid header: 0x%x", pFirmwareInfo->magic_header);
        memset((char *)pFirmwareInfo, 0, sizeof(sOTAFirmwareInfo));
        return eFLASH_HEADER_ERR;
    }

    return 0;
}

int save_fw_info(sOTAFirmwareInfo *pFirmwareInfo)
{
    esp_err_t ret;

    ret = spi_flash_erase_sector(g_fw_info_addr / SPI_FLASH_SEC_SIZE);
    if (ESP_OK != ret) {
        Log_e("spi_flash_erase error: %d", ret);
        return (int)ret;
    }

    ret = spi_flash_write(g_fw_info_addr, (uint32_t *)pFirmwareInfo, sizeof(sOTAFirmwareInfo));
    if (ESP_OK != ret) {
        Log_e("spi_flash_write error: %d", ret);
        return (int)ret;
    }

    return 0;
}

int clear_fw_info(void)
{
    esp_err_t ret = spi_flash_erase_sector(g_fw_info_addr / SPI_FLASH_SEC_SIZE);
    if (ESP_OK != ret) {
        Log_e("spi_flash_erase error: %d", ret);
        return (int)ret;
    }

    return 0;
}

int read_fw_from_flash(void *dst_buf, uint32_t read_size_bytes, uint32_t fetched_bytes, uint32_t fw_size_bytes)
{
    esp_err_t ret;
    int       retry_cnt = 0;

    if (fw_size_bytes > (g_fw_max_size) || fetched_bytes > fw_size_bytes) {
        Log_e("fw oversize: %u or invalid fetched_size: %u", fw_size_bytes, fetched_bytes);
        return -1;
    }

    if (fetched_bytes % 4 || read_size_bytes % 4) {
        Log_e("fetched size: %u and read bytes: %u should be word aligned", fetched_bytes, read_size_bytes);
        return -1;
    }

    uint32_t src_addr = g_fw_base_addr + fetched_bytes;

    do {
        ret = spi_flash_read(src_addr, dst_buf, read_size_bytes);
        if (ret != ESP_OK) {
            retry_cnt++;
            if (retry_cnt > 3)
                return -1;
            Log_e("read %u bytes from addr %u failed: %u retry: %d", read_size_bytes, src_addr, ret, retry_cnt);
            HAL_SleepMs(100);
        }
    } while (ret != ESP_OK);

    return 0;
}

int save_fw_to_flash(uint32_t fw_size, uint32_t saved_size, const void *src_buf, uint32_t write_size)
{
    esp_err_t ret;
    int       retry_cnt = 0;

    if (fw_size > (g_fw_max_size) || saved_size >= fw_size) {
        Log_e("fw oversize: %u or invalid saved_size %u", fw_size, saved_size);
        return -1;
    }

    if (saved_size % 4) {
        Log_e("saved_size: %u and write_size: %u should be word aligned", saved_size, write_size);
        return -1;
    }

    uint32_t dst_addr = g_fw_base_addr + saved_size;
    do {
        /* write SPI_FLASH_SEC_SIZE in anycase */
        ret = spi_flash_write(dst_addr, src_buf, write_size);
        if (ret != ESP_OK) {
            retry_cnt++;
            if (retry_cnt > 3)
                return -1;
            Log_e("write addr %u failed: %u retry: %d", dst_addr, ret, retry_cnt);
        }
    } while (ret != ESP_OK);

    return 0;
}

int erase_fw_flash_sectors(uint32_t fw_size)
{
    uint32_t  number_of_sectors;
    esp_err_t ret;

    if (fw_size > (g_fw_max_size)) {
        Log_e("fw oversize: %u", fw_size);
        return -1;
    }

    Log_w("start erase flash");

    ret = clear_fw_info();
    if (ESP_OK != ret) {
        Log_e("clear_fw_info error: %d", ret);
        return (int)ret;
    }

    if (fw_size % SPI_FLASH_SEC_SIZE)
        number_of_sectors = fw_size / SPI_FLASH_SEC_SIZE + 1;
    else
        number_of_sectors = fw_size / SPI_FLASH_SEC_SIZE;

#if 0
    uint32_t i = 0;
    int retry_cnt = 0;
    size_t base_sector = g_fw_base_addr/SPI_FLASH_SEC_SIZE;

    /* including the FW info sector */
    while ( i<=number_of_sectors ) {
        ret = spi_flash_erase_sector(base_sector+i);
        if (ESP_OK == ret) {
            retry_cnt = 0;
            i++;
        } else {
            retry_cnt++;
            if (retry_cnt > 3)
                return -1;

            Log_e("erase sector %u failed: %u retry: %d", base_sector+i, ret, retry_cnt);            
            HAL_SleepMs(200);
        }
    }
#endif

    ret = spi_flash_erase_range(g_fw_base_addr, number_of_sectors * SPI_FLASH_SEC_SIZE);
    if (ESP_OK != ret) {
        Log_e("spi_flash_erase_range error: %d", ret);
        return (int)ret;
    }

    Log_w("end erase flash");
    return 0;
}

int check_err_log(uint32_t *log_cnt)
{
    esp_err_t ret;
    uint32_t  header, msg_cnt;
    ret = spi_flash_read(g_errlog_addr, (uint32_t *)&header, sizeof(uint32_t));
    if (ESP_OK != ret) {
        Log_e("spi_flash_read error: %d", ret);
        return (int)ret;
    }

    /* not a valid log */
    if (header != VALID_MAGIC_CODE) {
        Log_i("invalid magic code: 0x%x", header);
        return 0;
    }

    ret = spi_flash_read(g_errlog_addr + sizeof(uint32_t), (uint32_t *)&msg_cnt, sizeof(uint32_t));
    if (ESP_OK != ret) {
        Log_e("spi_flash_read error: %d", ret);
        return (int)ret;
    }

    *log_cnt = msg_cnt;
    return 0;
}

int load_err_log(void *log, size_t log_size)
{
    esp_err_t ret;
    size_t    log_addr = g_errlog_addr + 2 * sizeof(uint32_t);
    ret                = spi_flash_read(log_addr, (uint32_t *)log, log_size);
    if (ESP_OK != ret) {
        Log_e("spi_flash_read error: %d", ret);
        return (int)ret;
    }

    return 0;
}

int save_err_log(void *log, size_t log_size)
{
    esp_err_t ret;

    ret = spi_flash_erase_sector(g_errlog_addr / SPI_FLASH_SEC_SIZE);
    if (ESP_OK != ret) {
        Log_e("spi_flash_erase error: %d", ret);
        return (int)ret;
    }

    ret = spi_flash_write(g_errlog_addr, (uint32_t *)log, log_size);
    if (ESP_OK != ret) {
        Log_e("spi_flash_write error: %d", ret);
        return (int)ret;
    }

    return 0;
}

int clear_err_log(void)
{
    esp_err_t ret = spi_flash_erase_sector(g_errlog_addr / SPI_FLASH_SEC_SIZE);
    if (ESP_OK != ret) {
        Log_e("spi_flash_erase error: %d", ret);
        return (int)ret;
    }

    return 0;
}
