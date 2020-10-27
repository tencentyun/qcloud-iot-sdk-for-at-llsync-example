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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>

#include <stddef.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_at.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"

#include "qcloud_iot_export.h"
#include "qcloud_iot_import.h"

#include "qcloud_at_cmd.h"
#include "qcloud_at_mqtt.h"
#include "qcloud_at_flash.h"
#include "qcloud_at_board.h"

#define OTA_CLIENT_TASK_NAME        "mqtt_ota_task"
#define OTA_CLIENT_TASK_STACK_BYTES 5120
#define OTA_CLIENT_TASK_PRIO        2

#define ESP8266_FW_NAME     "ESP8266_QCLOUD_AT.bin"
#define ESP8266_FW_NAME_LEN 17

#define ESP_OTA_BUF_LEN   2048
#define MAX_OTA_RETRY_CNT 3

typedef struct _EspOTAHandle {
    esp_partition_t  partition;
    esp_ota_handle_t handle;
} EspOTAHandle;

typedef struct OTAContextData {
    void *ota_handle;
    void *mqtt_client;

    // remote_version means version for the FW in the cloud and to be downloaded
    char     remote_version[MAX_SIZE_OF_FW_VERSION + 4];
    char     remote_file_name[MAX_SIZE_OF_FW_NAME + 4];
    uint32_t fw_file_size;

    // for resuming download
    uint32_t downloaded_size;
    uint32_t ota_fail_cnt;

    EspOTAHandle *esp_ota;

    TaskHandle_t task_handle;
    char         local_version[MAX_SIZE_OF_FW_VERSION + 4];
} OTAContextData;

static OTAContextData sg_ota_ctx         = {0};
static bool           g_fw_downloading   = false;
static bool           g_ota_task_running = false;
// static bool g_flash_erasing = false;

// bool is_flash_erasing()
// {
//    return g_flash_erasing;
// }

bool is_fw_downloading()
{
    return g_fw_downloading;
}

#define SUPPORT_RESUMING_DOWNLOAD

#ifdef SUPPORT_RESUMING_DOWNLOAD

int _read_esp_fw(void *dst_buf, uint32_t read_size_bytes, uint32_t fetched_bytes, OTAContextData *ota_ctx)
{
    esp_err_t ret;
    int       retry_cnt = 0;

    if (fetched_bytes % 4 || read_size_bytes % 4) {
        Log_e("fetched size: %u and read bytes: %u should be word aligned", fetched_bytes, read_size_bytes);
        return -1;
    }

    uint32_t src_addr = ota_ctx->esp_ota->partition.address + fetched_bytes;

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

// calculate left MD5 for resuming download from break point
static int _cal_exist_fw_md5(OTAContextData *ota_ctx)
{
    char * buff;
    size_t rlen, total_read = 0;
    int    ret = QCLOUD_RET_SUCCESS;

    ret = IOT_OTA_ResetClientMD5(ota_ctx->ota_handle);
    if (ret) {
        Log_e("reset MD5 failed: %d", ret);
        return QCLOUD_ERR_FAILURE;
    }

    buff = HAL_Malloc(ESP_OTA_BUF_LEN);
    if (buff == NULL) {
        Log_e("malloc ota buffer failed");
        return QCLOUD_ERR_MALLOC;
    }

    size_t size = ota_ctx->downloaded_size;

    while (total_read < ota_ctx->downloaded_size) {
        rlen = (size > ESP_OTA_BUF_LEN) ? ESP_OTA_BUF_LEN : size;
        if (strncmp(ota_ctx->remote_file_name, ESP8266_FW_NAME, ESP8266_FW_NAME_LEN) == 0)
            ret = _read_esp_fw(buff, rlen, total_read, ota_ctx);
        else
            ret = read_fw_from_flash(buff, rlen, total_read, ota_ctx->downloaded_size);
        if (ret) {
            Log_e("read data from flash error");
            ret = QCLOUD_ERR_FAILURE;
            break;
        }
        IOT_OTA_UpdateClientMd5(ota_ctx->ota_handle, buff, rlen);
        size -= rlen;
        total_read += rlen;
    }

    HAL_Free(buff);
    Log_d("total read: %d", total_read);
    return ret;
}

/* update local firmware info for resuming download from break point */
static int _update_local_fw_info(OTAContextData *ota_ctx)
{
    sOTAFirmwareInfo fw_info = {0};
    fw_info.fw_size          = ota_ctx->fw_file_size;
    fw_info.downloaded_size  = ota_ctx->downloaded_size;
    strncpy(fw_info.fw_name, ota_ctx->remote_file_name, strlen(ota_ctx->remote_file_name));
    strncpy(fw_info.fw_version, ota_ctx->remote_version, strlen(ota_ctx->remote_version));
    fw_info.magic_header = VALID_MAGIC_CODE;

    if (strncmp(ota_ctx->remote_file_name, ESP8266_FW_NAME, ESP8266_FW_NAME_LEN) == 0) {
        fw_info.fw_state = OTA_FW_ESP_DOWNLOADING;
    } else {
        fw_info.fw_state = OTA_FW_MCU_DOWNLOADING;
    }

    if (save_fw_info(&fw_info)) {
        Log_e("save fw info to flash failed");
        return eFLASH_ERR;
    }
    return 0;
}

/* get local firmware offset for resuming download from break point */
static uint32_t _update_fw_downloaded_size(OTAContextData *ota_ctx)
{
    // only do resuming download for self-OTA if failure happen (memory not reset)
    if (ota_ctx->ota_fail_cnt == 0 && strncmp(ota_ctx->remote_file_name, ESP8266_FW_NAME, ESP8266_FW_NAME_LEN) == 0) {
        ota_ctx->downloaded_size = 0;
        return 0;
    }

    sOTAFirmwareInfo fw_info = {0};
    if (load_fw_info(&fw_info)) {
        Log_e("load fw info from flash failed");
        ota_ctx->downloaded_size = 0;
        return 0;
    }

    if (fw_info.fw_state != OTA_FW_ESP_DOWNLOADING && fw_info.fw_state != OTA_FW_MCU_DOWNLOADING) {
        Log_w("no valid pre-download fw info");
        ota_ctx->downloaded_size = 0;
        return 0;
    }

    if ((0 != strcmp(fw_info.fw_name, ota_ctx->remote_file_name)) ||
        (0 != strcmp(fw_info.fw_version, ota_ctx->remote_version)) ||
        (fw_info.downloaded_size > ota_ctx->fw_file_size)) {
        Log_w("different FW with local: %s %s %u", fw_info.fw_name, fw_info.fw_version, fw_info.downloaded_size);
        ota_ctx->downloaded_size = 0;
        return 0;
    }

    ota_ctx->downloaded_size = fw_info.downloaded_size;

    return ota_ctx->downloaded_size;
}
#endif

static int _reset_local_fw_info(OTAContextData *ota_ctx)
{
    return clear_fw_info();
}

static int _save_fw_data(OTAContextData *ota_ctx, char *buf, int len)
{
    if (strncmp(ota_ctx->remote_file_name, ESP8266_FW_NAME, ESP8266_FW_NAME_LEN) == 0) {
        if (esp_ota_write(ota_ctx->esp_ota->handle, buf, len) != ESP_OK) {
            Log_e("write esp fw failed");
            return eOTA_ERR;
        }
    } else {
        if (save_fw_to_flash(ota_ctx->fw_file_size, ota_ctx->downloaded_size, buf, len)) {
            Log_e("write fw to flash failed");
            return eFLASH_ERR;
        }
    }

    return 0;
}

static int _init_esp_fw_ota(EspOTAHandle *ota_handle, size_t fw_size)
{
    esp_partition_t *      partition_ptr = NULL;
    esp_partition_t        partition;
    const esp_partition_t *next_partition = NULL;

    // search ota partition
    partition_ptr = (esp_partition_t *)esp_ota_get_boot_partition();
    if (partition_ptr == NULL) {
        Log_e("esp boot partition NULL!");
        return eFLASH_ERR;
    }

    Log_i("partition type: %d subtype: %d addr: 0x%x label: %s", partition_ptr->type, partition_ptr->subtype,
          partition_ptr->address, partition_ptr->label);

    if (partition_ptr->type != ESP_PARTITION_TYPE_APP) {
        Log_e("esp_current_partition->type != ESP_PARTITION_TYPE_APP");
        return eFLASH_ERR;
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
        return eFLASH_ERR;
    }

    Log_i("to use partition type: %d subtype: %d addr: 0x%x label: %s", partition_ptr->type, partition_ptr->subtype,
          partition_ptr->address, partition_ptr->label);
    memcpy(&ota_handle->partition, partition_ptr, sizeof(esp_partition_t));
    if (esp_ota_begin(&ota_handle->partition, fw_size, &ota_handle->handle) != ESP_OK) {
        Log_e("esp_ota_begin failed!");
        return eOTA_ERR;
    }

    Log_i("esp_ota_begin done!");

    return 0;
}

static int _pre_ota_download(OTAContextData *ota_ctx)
{
#ifdef SUPPORT_RESUMING_DOWNLOAD
    // re-generate MD5 for resuming download */
    if (ota_ctx->downloaded_size) {
        Log_i("calc MD5 for resuming download from offset: %d", ota_ctx->downloaded_size);
        int ret = _cal_exist_fw_md5(ota_ctx);
        if (ret) {
            Log_e("regen OTA MD5 error: %d", ret);
            ota_ctx->downloaded_size = 0;
            return 0;
        }
        Log_d("local MD5 update done!");
        return 0;
    }
#endif

    // new download, erase partition first
    if (strncmp(ota_ctx->remote_file_name, ESP8266_FW_NAME, ESP8266_FW_NAME_LEN) == 0) {
        if (_init_esp_fw_ota(ota_ctx->esp_ota, ota_ctx->fw_file_size)) {
            Log_e("init esp ota failed");
            return eOTA_ERR;
        }
    } else {
        if (erase_fw_flash_sectors(ota_ctx->fw_file_size)) {
            Log_e("erase flash failed");
            return eFLASH_ERR;
        }
    }

    return 0;
}

static int _post_ota_download(OTAContextData *ota_ctx)
{
    sOTAFirmwareInfo fw_info    = {0};
    char             md5sum[33] = {0};
    IOT_OTA_Ioctl(ota_ctx->ota_handle, IOT_OTAG_MD5SUM, md5sum, 33);
    fw_info.fw_size         = ota_ctx->fw_file_size;
    fw_info.downloaded_size = ota_ctx->fw_file_size;
    strncpy(fw_info.fw_name, ota_ctx->remote_file_name, strlen(ota_ctx->remote_file_name));
    strncpy(fw_info.fw_version, ota_ctx->remote_version, strlen(ota_ctx->remote_version));
    strncpy(fw_info.fw_md5, md5sum, MAX_SIZE_OF_FW_MD5);
    fw_info.fw_max_size_of_module = get_module_info()->ota_max_size;
    fw_info.magic_header          = VALID_MAGIC_CODE;

    if (strncmp(ota_ctx->remote_file_name, ESP8266_FW_NAME, ESP8266_FW_NAME_LEN) == 0) {
        if (esp_ota_end(ota_ctx->esp_ota->handle) != ESP_OK) {
            Log_e("esp_ota_end failed!");
            return eOTA_ERR;
        }
        Log_i("esp_ota_end done!");

        if (esp_ota_set_boot_partition(&ota_ctx->esp_ota->partition) != ESP_OK) {
            Log_e("esp_ota_set_boot_partition failed!");
            return eOTA_ERR;
        }
        Log_i("esp_ota_set_boot_partition done!");

        fw_info.fw_state = OTA_FW_ESP_VALID;

    } else {
        fw_info.fw_state = OTA_FW_MCU_VALID;
    }

    if (save_fw_info(&fw_info)) {
        Log_e("save fw info to flash failed");
        return eFLASH_ERR;
    }

    return 0;
}

/**********************************************************************************
 * OTA file operations END
 **********************************************************************************/

// main OTA cycle
static void _ota_update_task(void *pvParameters)
{
    OTAContextData *ota_ctx               = (OTAContextData *)pvParameters;
    bool            upgrade_fetch_success = true;
    char *          buf_ota               = NULL;
    int             rc;
    void *          h_ota               = ota_ctx->ota_handle;
    int             err_code            = eUNKNOW_ERR;
    int             mqtt_disconnect_cnt = 0;
    EspOTAHandle    esp_ota             = {0};

    if (h_ota == NULL) {
        Log_e("mqtt ota not ready");
        err_code = eSTATE_ERR;
        goto end_of_ota;
    }

    ota_ctx->esp_ota = &esp_ota;

#ifdef CONFIG_FREERTOS_USE_TRACE_FACILITY
    int          print_cnt = 0;
    TaskStatus_t task_status;
    vTaskGetInfo(NULL, &task_status, pdTRUE, eRunning);
    Log_i(">>>>> task %s start! stack left: %u, free heap: %u", task_status.pcTaskName,
          task_status.usStackHighWaterMark, esp_get_free_heap_size());
#endif

begin_of_ota:

    while (g_ota_task_running) {
#ifdef CONFIG_FREERTOS_USE_TRACE_FACILITY
        if (print_cnt++ > 10) {
            print_cnt = 0;
            vTaskGetInfo(NULL, &task_status, pdTRUE, eRunning);
            Log_d(">>>>> task %s stack left: %u, free heap: %u", task_status.pcTaskName,
                  task_status.usStackHighWaterMark, esp_get_free_heap_size());
        }
#endif

        // recv the upgrade cmd
        if (IOT_OTA_IsFetching(h_ota)) {
            g_fw_downloading = true;
            at_cmd_printf("+TCOTASTATUS:ENTERUPDATE\n");

            IOT_OTA_Ioctl(h_ota, IOT_OTAG_FILE_SIZE, &ota_ctx->fw_file_size, 4);
            IOT_OTA_Ioctl(h_ota, IOT_OTAG_VERSION, ota_ctx->remote_version, MAX_SIZE_OF_FW_VERSION);
            IOT_OTA_Ioctl(h_ota, IOT_OTAG_FILE_NAME, ota_ctx->remote_file_name, MAX_SIZE_OF_FW_NAME);

#ifdef SUPPORT_RESUMING_DOWNLOAD
            /* check if pre-downloading finished or not */
            /* if local FW downloaded size (ota_ctx->downloaded_size) is not zero, it will do resuming download */
            _update_fw_downloaded_size(ota_ctx);
#endif

            rc = _pre_ota_download(ota_ctx);
            if (rc) {
                Log_e("pre ota download failed: %d", rc);
                upgrade_fetch_success = false;
                err_code              = rc;
                goto end_of_ota;
            }

            buf_ota = HAL_Malloc(ESP_OTA_BUF_LEN + 1);
            if (buf_ota == NULL) {
                Log_e("malloc ota buffer failed");
                upgrade_fetch_success = false;
                err_code              = eMEM_ERR;
                goto end_of_ota;
            }

            /*set offset and start http connect*/
            rc = IOT_OTA_StartDownload(h_ota, ota_ctx->downloaded_size, ota_ctx->fw_file_size);
            if (QCLOUD_RET_SUCCESS != rc) {
                Log_e("OTA download start err,rc:%d", rc);
                upgrade_fetch_success = false;
                err_code              = eHTTP_ERR;
                goto end_of_ota;
            }

            // download and save the fw
            while (!IOT_OTA_IsFetchFinish(h_ota)) {
                if (!g_ota_task_running) {
                    Log_e("OTA task stopped during downloading!");
                    upgrade_fetch_success = false;
                    err_code              = eSTATE_ERR;
                    goto end_of_ota;
                }

                memset(buf_ota, 0, ESP_OTA_BUF_LEN + 1);
                int len = IOT_OTA_FetchYield(h_ota, buf_ota, ESP_OTA_BUF_LEN + 1, 20);
                if (len > 0) {
                    // Log_i("save fw data %d from addr %u", len, ota_ctx->downloaded_size);
                    rc = _save_fw_data(ota_ctx, buf_ota, len);
                    if (rc) {
                        Log_e("write data to file failed");
                        upgrade_fetch_success = false;
                        err_code              = rc;
                        goto end_of_ota;
                    }
                } else if (len < 0) {
                    Log_e("download fail rc=%d, size_downloaded=%u", len, ota_ctx->downloaded_size);
                    upgrade_fetch_success = false;
                    err_code              = eHTTP_ERR;
                    goto end_of_ota;
                } else {
                    Log_e("OTA download timeout! size_downloaded=%u", ota_ctx->downloaded_size);
                    upgrade_fetch_success = false;
                    err_code              = eTIME_OUT_ERR;
                    goto end_of_ota;
                }

                // get OTA downloaded size
                IOT_OTA_Ioctl(h_ota, IOT_OTAG_FETCHED_SIZE, &ota_ctx->downloaded_size, 4);
                // delay is needed to avoid TCP read timeout ?!
                HAL_SleepMs(500);

#ifdef CONFIG_FREERTOS_USE_TRACE_FACILITY
                if (esp_get_free_heap_size() < 10240) {
                    vTaskGetInfo(NULL, &task_status, pdTRUE, eRunning);
                    Log_w(">>>>> task %s stack left: %u, free heap: %u", task_status.pcTaskName,
                          task_status.usStackHighWaterMark, esp_get_free_heap_size());
                }
#endif

                if (!IOT_MQTT_IsConnected(ota_ctx->mqtt_client)) {
                    mqtt_disconnect_cnt++;
                    Log_e("MQTT disconnect %d during OTA download!", mqtt_disconnect_cnt);
                    if (mqtt_disconnect_cnt > 2) {
                        upgrade_fetch_success = false;
                        err_code              = eSTATE_ERR;
                        goto end_of_ota;
                    }
                    HAL_SleepMs(1000);
                } else {
                    mqtt_disconnect_cnt = 0;
                }
            }

            /* Must check MD5 match or not */
            if (upgrade_fetch_success) {
                uint32_t firmware_valid = 0;
                IOT_OTA_Ioctl(h_ota, IOT_OTAG_CHECK_FIRMWARE, &firmware_valid, 4);
                if (0 == firmware_valid) {
                    Log_e("The firmware is invalid");
                    ota_ctx->downloaded_size = 0;
                    _reset_local_fw_info(ota_ctx);
                    upgrade_fetch_success = false;
                    // special handling for this error
                    err_code              = eFIRMWARE_ERR;
                    ota_ctx->ota_fail_cnt = MAX_OTA_RETRY_CNT + 1;
                    goto end_of_ota;
                } else {
                    Log_i("The firmware is valid");

                    rc = _post_ota_download(ota_ctx);
                    if (rc) {
                        Log_e("post ota handling failed: %d", rc);
                        upgrade_fetch_success = false;
                        err_code              = rc;
                        goto end_of_ota;
                    }
                    upgrade_fetch_success = true;
                    break;
                }
            }
        } else if (IOT_OTA_GetLastError(h_ota)) {
            err_code = IOT_OTA_GetLastError(h_ota);
            Log_e("OTA update failed! last error: %d", err_code);
            upgrade_fetch_success = false;
            goto end_of_ota;
        }

        HAL_SleepMs(900);
    }

end_of_ota:

    if (!upgrade_fetch_success && g_fw_downloading && err_code != eFIRMWARE_ERR) {
        IOT_OTA_ReportUpgradeFail(h_ota, NULL);
        ota_ctx->ota_fail_cnt++;

#ifdef SUPPORT_RESUMING_DOWNLOAD
        if (ota_ctx->downloaded_size) {
            Log_i("update local FW size to %u", ota_ctx->downloaded_size);
            _update_local_fw_info(ota_ctx);
        }
#endif
    }

    // do it again
    if (g_ota_task_running && IOT_MQTT_IsConnected(ota_ctx->mqtt_client) && !upgrade_fetch_success &&
        ota_ctx->ota_fail_cnt <= MAX_OTA_RETRY_CNT) {
        HAL_Free(buf_ota);
        buf_ota               = NULL;
        g_fw_downloading      = false;
        upgrade_fetch_success = true;

        Log_e("OTA failed: %d, retry %d time!", err_code, ota_ctx->ota_fail_cnt);
        HAL_SleepMs(1000);

        if (0 > IOT_OTA_ReportVersion(ota_ctx->ota_handle, ota_ctx->local_version)) {
            Log_e("report OTA version %s failed", ota_ctx->local_version);
        }

        sResInfo esp8266_fw_info   = {0};
        esp8266_fw_info.res_name   = ESP8266_FW_NAME;
        esp8266_fw_info.res_ver    = QCLOUD_IOT_AT_VERSION;
        esp8266_fw_info.res_type   = "FILE";
        sResInfo *resource_list[1] = {&esp8266_fw_info};
        if (0 > IOT_OTA_ReportResVersion(ota_ctx->ota_handle, 1, resource_list)) {
            Log_e("report RES version %s failed", QCLOUD_IOT_AT_VERSION);
        }

        goto begin_of_ota;
    }

    // response to +TCOTASTATUS:ENTERUPDATE
    if (upgrade_fetch_success && g_fw_downloading) {
        IOT_OTA_ReportUpgradeSuccess(h_ota, NULL);
        at_cmd_printf("+TCOTASTATUS:UPDATESUCCESS\n");

        // for self-OTA, restart after successful upgrade
        if (strncmp(ota_ctx->remote_file_name, ESP8266_FW_NAME, ESP8266_FW_NAME_LEN) == 0) {
            at_cmd_printf("+TCOTASTATUS:UPDATERESET\n");
            HAL_SleepMs(2000);
            esp_restart();
        }
    } else if (g_fw_downloading) {
        at_cmd_printf("+TCOTASTATUS:UPDATEFAIL,%d\n", err_code);
        Log_e("OTA failed %d! Quit the task and reset", err_code);
    }

    g_fw_downloading = false;
    Log_w("OTA task going to be deleted");

    if (buf_ota) {
        HAL_Free(buf_ota);
        buf_ota = NULL;
    }

    IOT_OTA_Destroy(ota_ctx->ota_handle);
    memset(ota_ctx, 0, sizeof(OTAContextData));

#ifdef CONFIG_FREERTOS_USE_TRACE_FACILITY
    vTaskGetInfo(NULL, &task_status, pdTRUE, eRunning);
    Log_i(">>>>> task %s quit. stack left: %u, free heap: %u", task_status.pcTaskName, task_status.usStackHighWaterMark,
          esp_get_free_heap_size());
#endif

    vTaskDelete(NULL);
    return;
}

int do_fw_ota_update(bool ota_enable, char *version)
{
    /* to disable FW update */
    if (!ota_enable) {
        if (g_ota_task_running) {
            g_ota_task_running = false;
            Log_w("Disable OTA upgrade!");

            do {
                HAL_SleepMs(1000);
            } while (is_fw_downloading());

            HAL_SleepMs(500);
        }
        return 0;
    }

    if (get_mqtt_connect_state() == 0) {
        Log_e("MQTT NOT connected yet!");
        return eSTATE_ERR;
    }

    /* to enable FW update */
    g_ota_task_running = true;
    if (sg_ota_ctx.ota_handle == NULL) {
        void *mqtt_client = get_mqtt_client();
        void *ota_handle  = IOT_OTA_Init(IOT_MQTT_GetDeviceInfo(mqtt_client)->product_id,
                                        IOT_MQTT_GetDeviceInfo(mqtt_client)->device_name, mqtt_client);
        if (NULL == ota_handle) {
            Log_e("initialize OTA failed");
            return eEXEC_ERR;
        }

        memset(&sg_ota_ctx, 0, sizeof(sg_ota_ctx));
        sg_ota_ctx.mqtt_client = mqtt_client;
        sg_ota_ctx.ota_handle  = ota_handle;

        int ret = xTaskCreate(_ota_update_task, OTA_CLIENT_TASK_NAME, OTA_CLIENT_TASK_STACK_BYTES, (void *)&sg_ota_ctx,
                              OTA_CLIENT_TASK_PRIO, &sg_ota_ctx.task_handle);
        if (ret != pdPASS) {
            Log_e("create ota task failed: %d", ret);
            IOT_OTA_Destroy(sg_ota_ctx.ota_handle);
            memset(&sg_ota_ctx, 0, sizeof(sg_ota_ctx));
            return eEXEC_ERR;
        }
    }

    /* report current user version */
    if (0 > IOT_OTA_ReportVersion(sg_ota_ctx.ota_handle, version)) {
        Log_e("report OTA version %s failed", version);
        g_ota_task_running = false;
        HAL_SleepMs(1000);
        IOT_OTA_Destroy(sg_ota_ctx.ota_handle);
        memset(&sg_ota_ctx, 0, sizeof(sg_ota_ctx));
        return eEXEC_ERR;
    }
    memset(sg_ota_ctx.local_version, 0, MAX_SIZE_OF_FW_VERSION + 4);
    strncpy(sg_ota_ctx.local_version, version, strlen(version));

    sResInfo esp8266_fw_info   = {0};
    esp8266_fw_info.res_name   = ESP8266_FW_NAME;
    esp8266_fw_info.res_ver    = QCLOUD_IOT_AT_VERSION;
    esp8266_fw_info.res_type   = "FILE";
    sResInfo *resource_list[1] = {&esp8266_fw_info};
    if (0 > IOT_OTA_ReportResVersion(sg_ota_ctx.ota_handle, 1, resource_list)) {
        Log_e("report RES version %s failed", QCLOUD_IOT_AT_VERSION);
        g_ota_task_running = false;
        HAL_SleepMs(1000);
        IOT_OTA_Destroy(sg_ota_ctx.ota_handle);
        memset(&sg_ota_ctx, 0, sizeof(sg_ota_ctx));
        return eEXEC_ERR;
    }

    return 0;
}
