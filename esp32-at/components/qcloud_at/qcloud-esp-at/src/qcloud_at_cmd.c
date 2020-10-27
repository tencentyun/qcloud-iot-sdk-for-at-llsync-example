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

#include <stdarg.h>
#include "string.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_system.h"
#include "esp_at.h"
#include "at_interface.h"
#include "at_default_config.h"
#include "esp_spi_flash.h"
#include "esp_wifi.h"

#include "qcloud_at_cmd.h"
#include "qcloud_at_wifi.h"
#include "qcloud_at_mqtt.h"
#include "qcloud_at_board.h"
#include "qcloud_at_flash.h"

#include "ble_qiot_export.h"

#define MAX_LOG_LEN  (512)
#define MAX_SSID_LEN (32)
#define MAX_PSW_LEN  (32)
#define MIN_PSW_LEN  (8)

void at_cmd_printf(const char *fmt, ...)
{
    va_list args;
    char    log_buf[MAX_LOG_LEN] = {0};

    va_start(args, fmt);
    vsnprintf(log_buf, MAX_LOG_LEN - 1, fmt, args);
    va_end(args);

    int len          = strlen(log_buf);
    log_buf[len - 1] = '\r';
    log_buf[len]     = '\n';
    log_buf[len + 1] = 0;

    esp_at_port_write_data((uint8_t *)log_buf, len + 1);
}

/******************** Tencent IoT AT commands begin ***********************/
static uint8_t at_version_exec(uint8_t *cmd_name)
{
    at_cmd_printf("Tencent Cloud IoT AT  version: %s\n", QCLOUD_IOT_AT_VERSION);
    at_cmd_printf("Tencent Cloud IoT SDK version: %s\n", QCLOUD_IOT_DEVICE_SDK_VERSION);
    at_cmd_printf("Firmware compile time: %s %s\n", __DATE__, __TIME__);
    at_cmd_printf("Tencent Technology Co. Ltd.\n");

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_module_exec(uint8_t *cmd_name)
{
    uint8_t   mac[6];
    esp_err_t ret = esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
    if (ESP_OK != ret) {
        Log_e("get mac addr failed: %d", ret);
        memset(mac, 0, 6);
    }

    sModuleInfo *pModuleInfo = get_module_info();
    at_cmd_printf("Module HW name: %s\n", pModuleInfo->module_name);
    at_cmd_printf("Module FW version: %s\n", QCLOUD_IOT_AT_VERSION);
    at_cmd_printf("Module Mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    at_cmd_printf("Module FW compiled time: %s %s\n", __DATE__, __TIME__);
    at_cmd_printf("Module Flash size: %dMB\n", pModuleInfo->module_flash_size);

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_restore_test(uint8_t *cmd_name)
{
    at_cmd_printf("%s: CLEAR CONFIG AND RESET\n", cmd_name);
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_restore_exec(uint8_t *cmd_name)
{
    if (is_mqtt_task_running()) {
        Log_e("MQTT task is running\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");

    clear_dev_info();
    clear_prd_info();
    clear_fw_info();

    esp_restart();
    return ESP_AT_RESULT_CODE_OK;
}

/**************** Tencent IoT WiFi&Utils AT commands ***************/
static uint8_t at_startsmart_test(uint8_t *cmd_name)
{
    at_cmd_printf("%s: CMD FOR START SMARTCONFIG\n", cmd_name);
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_startsmart_exec(uint8_t *cmd_name)
{
    /* check state */
    if (is_mqtt_task_running()) {
        Log_e("MQTT task is running\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");

    /* command execution */
    int ret = start_smartconfig();
    if (ret) {
        at_cmd_printf("+TCSTARTSMART:FAIL,%d\n", ret);
    } else {
        at_cmd_printf("+TCSTARTSMART:OK\n");
    }

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_stopsmart_test(uint8_t *cmd_name)
{
    at_cmd_printf("%s:CMD TO STOP SMARTCONFIG\n", (char *)cmd_name);
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_stopsmart_exec(uint8_t *cmd_name)
{
    /* check state */
    if (is_mqtt_task_running()) {
        Log_e("MQTT task is running\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    stop_smartconfig();
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_sap_test(uint8_t *cmd_name)
{
    at_cmd_printf("%s=<ssid>[,<pwd>,<ch>]\n", cmd_name);
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_sap_query(uint8_t *cmd_name)
{
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_sap_setup(uint8_t para_num)
{
    /* check state */
    if (is_mqtt_task_running()) {
        Log_e("MQTT task is running\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* parameters parsing */
    int32_t  cnt  = 0;
    uint8_t *ssid = NULL;
    uint8_t *psw  = NULL;
    int32_t  ch   = 0;

    if (esp_at_get_para_as_str(cnt++, &ssid) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (ssid == NULL) {
        Log_e("ssid invalid, %u\n", para_num);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    size_t len = strlen((char *)ssid);
    if (len == 0 || len > MAX_SSID_LEN) {
        Log_e("ssid oversize\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt < para_num) {
        if (esp_at_get_para_as_str(cnt++, &psw) != ESP_AT_PARA_PARSE_RESULT_OK) {
            return ESP_AT_RESULT_CODE_ERROR;
        }

        len = strlen((char *)psw);
        if (len < MIN_PSW_LEN || len > MAX_PSW_LEN) {
            Log_e("psw oversize\n");
            at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
        }

        if (cnt < para_num) {
            if (esp_at_get_para_as_digit(cnt++, &ch) != ESP_AT_PARA_PARSE_RESULT_OK) {
                return ESP_AT_RESULT_CODE_ERROR;
            }

            if (ch < 0 || ch > 13) {
                Log_e("ch out of range: %d\n", ch);
                at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
                return ESP_AT_RESULT_CODE_PROCESS_DONE;
            }
        }
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    esp_at_response_result(ESP_AT_RESULT_CODE_OK);

    /* command execution */
    int ret = start_softAP((char *)ssid, (char *)psw, ch);
    if (ret) {
        at_cmd_printf("+TCSAP:FAIL,%d\n", ret);
    } else {
        at_cmd_printf("+TCSAP:OK\n");
    }

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_stopsap_test(uint8_t *cmd_name)
{
    at_cmd_printf("%s:CMD TO STOP SOFTAP\n", (char *)cmd_name);
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_stopsap_exec(uint8_t *cmd_name)
{
    if (is_mqtt_task_running()) {
        Log_e("MQTT task is running\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    stop_softAP();
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_log_test(uint8_t *cmd_name)
{
    at_cmd_printf("%s: <log_level>\n", cmd_name);
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_log_query(uint8_t *cmd_name)
{
    at_cmd_printf("%s: %d\n", cmd_name, IOT_Log_Get_Level());
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_log_setup(uint8_t para_num)
{
    int32_t cnt = 0, psw, log_level;

    if (esp_at_get_para_as_digit(cnt++, &psw) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (esp_at_get_para_as_digit(cnt++, &log_level) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (cnt != para_num) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (psw != 0x052075CC) {
        IOT_Log_Set_Level(eLOG_ERROR);
        return ESP_AT_RESULT_CODE_OK;
    }

    switch (log_level) {
        case eLOG_DISABLE:
        case eLOG_ERROR:
        case eLOG_WARN:
        case eLOG_INFO:
        case eLOG_DEBUG:
            IOT_Log_Set_Level(log_level);
            break;

        default:
            at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    return ESP_AT_RESULT_CODE_OK;
}

#ifdef CONFIG_FREERTOS_USE_TRACE_FACILITY
static void _print_task_stats()
{
    const size_t bytes_per_task   = 40; /* see vTaskList description */
    char *       task_list_buffer = malloc(uxTaskGetNumberOfTasks() * bytes_per_task);
    if (task_list_buffer == NULL) {
        HAL_Printf("failed to allocate buffer for vTaskList output\r\n");
        return;
    }

    vTaskList(task_list_buffer);
    HAL_Printf("Task Name\tStatus\tPrio\tStack\tTask#\r\n");
    HAL_Printf("%s\r\n", task_list_buffer);
    free(task_list_buffer);
    return;
}
#endif

static uint8_t at_ntp_query(uint8_t *cmd_name)
{
#ifdef CONFIG_FREERTOS_USE_TRACE_FACILITY
    _print_task_stats();
#endif

    at_cmd_printf("Current system time: %ld\n", HAL_Timer_current_sec());
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_ntp_setup(uint8_t para_num)
{
    /* parameters parsing */
    int32_t  cnt          = 0;
    uint8_t *time_zone    = NULL;
    uint8_t *ntp_server   = NULL;

    if (esp_at_get_para_as_str(cnt++, &time_zone) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_str(cnt++, &ntp_server) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");
    setup_sntp((char *)time_zone, (char *)ntp_server);

    at_cmd_printf("+NTP:%d\n", HAL_Timer_current_sec());

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_ntp_exec(uint8_t *cmd_name)
{
    setup_sntp(NULL, NULL);

    at_cmd_printf("+NTP:%d\n", HAL_Timer_current_sec());

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

/**************** Tencent IoT MQTT&OTA AT commands begin ***************/

static int calc_check(unsigned char *Bytes, int len)
{
    int i, result;
    for (result = Bytes[0], i = 1; i < len; i++) {
        result ^= Bytes[i];
    }
    return result;
}

static uint8_t at_dev_info_test(uint8_t *cmd_name)
{
    at_cmd_printf("%s:\"TLS_MODE(1)\",\"PRODUCT_ID\",\"DEVICE_NAME\",\"DEVICE_SECRET_BCC\",\"PRODUCT_REGION\"\n", cmd_name);

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_dev_info_query(uint8_t *cmd_name)
{
    uint8_t  Ret = ESP_AT_RESULT_CODE_OK;
    sDevInfo devinfo;

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    devinfo.magic_header = 0xfeedbeef;
    if (0 == load_dev_info(__FILE__, &devinfo)) {
        int bcc = calc_check((unsigned char *)devinfo.device_secret, strlen(devinfo.device_secret));
        at_cmd_printf("%s:%u,\"%s\",\"%s\",%d,\"%s\"\n", cmd_name, devinfo.TLS_mode, 
                devinfo.product_id, devinfo.device_name,bcc,devinfo.product_region);
    } else {
        at_cmd_printf("+CME ERROR:%d\n", eFLASH_ERR);
        Ret = ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    return Ret;
}

static uint8_t at_dev_info_setup(uint8_t para_num)
{
    /* check state */
    if (is_mqtt_task_running()) {
        Log_e("MQTT task is running\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* parameters parsing */
    int32_t  cnt           = 0, TLS_mode;
    uint8_t *product_id    = NULL;
    uint8_t *device_name   = NULL;
    uint8_t *device_secret = NULL;
    uint8_t *region = (uint8_t *)DEFAULT_HOST_REGION;

    if (esp_at_get_para_as_digit(cnt++, &TLS_mode) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (TLS_mode != 1) {
        Log_e("only support TLS mode 1");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_str(cnt++, &product_id) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    size_t len = strlen((char *)product_id);
    if (len == 0 || len > MAX_SIZE_OF_PRODUCT_ID) {
        Log_e("product_id oversize");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_str(cnt++, &device_name) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    len = strlen((char *)device_name);
    if (len == 0 || len > MAX_SIZE_OF_DEVICE_NAME) {
        Log_e("device_name oversize");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_str(cnt++, &device_secret) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    len = strlen((char *)device_secret);
    if (len == 0 || len > MAX_SIZE_OF_DEVICE_SECRET) {
        Log_e("device_secret oversize");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt < para_num) {
        if (esp_at_get_para_as_str(cnt++, &region) != ESP_AT_PARA_PARSE_RESULT_OK) {
            at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
        }

        len = strlen((char *)region);
        if (len == 0 || len > MAX_SIZE_OF_PRODUCT_REGION) {
            Log_e("product region oversize");
            at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
        }
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");

    /* command execution */
    sDevInfo devinfo, rdevinfo;
    uint8_t  Ret = ESP_AT_RESULT_CODE_OK;

    memset((char *)&devinfo, 0, sizeof(sDevInfo));
    devinfo.TLS_mode = TLS_mode;
    strncpy(devinfo.product_id, (char *)product_id, MAX_SIZE_OF_PRODUCT_ID);
    strncpy(devinfo.device_name, (char *)device_name, MAX_SIZE_OF_DEVICE_NAME);
    strncpy(devinfo.device_secret, (char *)device_secret, MAX_SIZE_OF_DEVICE_SECRET);
    strncpy(devinfo.product_region, (char *)region, MAX_SIZE_OF_PRODUCT_REGION);
    devinfo.magic_header  = VALID_MAGIC_CODE;
    rdevinfo.magic_header = 0xfeedbeef;
    if (0 == load_dev_info(__FILE__, &rdevinfo)) {
        /* only do flash saving if devinfo is different */
        if (0 != memcmp(&rdevinfo, &devinfo, sizeof(sDevInfo))) {
            if (save_dev_info(&devinfo)) {
                Log_e("save dev info failed");
                Ret = eFLASH_ERR;
            } else {
                Log_i("save dev info success");
            }
        }
    } else {
        /* something wrong, save it anyway*/
        if (save_dev_info(&devinfo)) {
            Log_e("save dev info failed");
            Ret = eFLASH_ERR;
        } else {
            Log_i("save dev info success");
        }
    }

    if (Ret) {
        at_cmd_printf("+TCDEVINFOSET:FAIL,%d\n", Ret);
    } else {
        at_cmd_printf("+TCDEVINFOSET:OK\n");
    }

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_prd_info_test(uint8_t *cmd_name)
{
    at_cmd_printf("%s:\"TLS_MODE(1)\",\"PRODUCT_ID\",\"PRODUCT_SECRET_BCC\",\"DEVICE_NAME\",\"PRODUCT_REGION\"\n", cmd_name);

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_prd_info_query(uint8_t *cmd_name)
{
    uint8_t  Ret = ESP_AT_RESULT_CODE_OK;
    sPrdInfo prdinfo;

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    prdinfo.magic_header = 0xfeedbeef;
    if (0 == load_prd_info(__FILE__, &prdinfo)) {
        int bcc = calc_check((unsigned char *)prdinfo.product_secret, strlen(prdinfo.product_secret));
        at_cmd_printf("%s:%u,\"%s\",%d,\"%s\",\"%s\"\n", cmd_name, prdinfo.TLS_mode, prdinfo.product_id, bcc,
                      prdinfo.device_name, prdinfo.product_region);
    } else {
        at_cmd_printf("+CME ERROR:%d\n", eFLASH_ERR);
        Ret = ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    return Ret;
}

static uint8_t at_prd_info_setup(uint8_t para_num)
{
    /* check state */
    if (is_mqtt_task_running()) {
        Log_e("MQTT task is running\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* parameters parsing */
    int32_t  cnt            = 0, TLS_mode;
    uint8_t *product_id     = NULL;
    uint8_t *device_name    = NULL;
    uint8_t *product_secret = NULL;
    uint8_t *region         = (uint8_t *)DEFAULT_HOST_REGION;

    if (esp_at_get_para_as_digit(cnt++, &TLS_mode) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (TLS_mode != 1) {
        Log_e("only support TLS mode 1\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_str(cnt++, &product_id) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    size_t len = strlen((char *)product_id);
    if (len == 0 || len > MAX_SIZE_OF_PRODUCT_ID) {
        Log_e("product_id oversize\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_str(cnt++, &product_secret) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    len = strlen((char *)product_secret);
    if (len == 0 || len > MAX_SIZE_OF_PRODUCT_SECRET) {
        Log_e("product_secret oversize\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_str(cnt++, &device_name) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    len = strlen((char *)device_name);
    if (len == 0 || len > MAX_SIZE_OF_DEVICE_NAME) {
        Log_e("device_name oversize\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt < para_num) {
        if (esp_at_get_para_as_str(cnt++, &region) != ESP_AT_PARA_PARSE_RESULT_OK) {
            at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
        }

        len = strlen((char *)region);
        if (len == 0 || len > MAX_SIZE_OF_PRODUCT_REGION) {
            Log_e("product region oversize");
            at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
        }
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");

    /* command execution */
    sPrdInfo prdinfo, rprdinfo;
    uint8_t  Ret = ESP_AT_RESULT_CODE_OK;

    memset((char *)&prdinfo, 0, sizeof(sPrdInfo));
    prdinfo.TLS_mode = TLS_mode;
    strncpy(prdinfo.product_id, (char *)product_id, MAX_SIZE_OF_PRODUCT_ID);
    strncpy(prdinfo.device_name, (char *)device_name, MAX_SIZE_OF_DEVICE_NAME);
    strncpy(prdinfo.product_secret, (char *)product_secret, MAX_SIZE_OF_PRODUCT_SECRET);
    strncpy(prdinfo.product_region, (char *)region, MAX_SIZE_OF_PRODUCT_REGION);
    prdinfo.magic_header = VALID_MAGIC_CODE;

    rprdinfo.magic_header = 0xfeedbeef;
    if (0 == load_prd_info(__FILE__, &rprdinfo)) {
        /* only do flash saving if info is different */
        if (0 != memcmp(&prdinfo, &rprdinfo, sizeof(sPrdInfo))) {
            if (save_prd_info(&prdinfo)) {
                Log_e("save prd info failed");
                Ret = eFLASH_ERR;
            } else {
                Log_i("save prd info success");
            }
        }
    } else {
        /* something wrong, save it anyway*/
        if (save_prd_info(&prdinfo)) {
            Log_e("save prd info failed");
            Ret = eFLASH_ERR;
        } else {
            Log_i("save prd info success");
        }
    }

    if (Ret) {
        at_cmd_printf("+TCPRDINFOSET:FAIL,%d\n", Ret);
    } else {
        at_cmd_printf("+TCPRDINFOSET:OK\n");
    }

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_dev_register_test(uint8_t *cmd_name)
{
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_dev_register(uint8_t *cmd_name)
{
    /* check state */
    if (is_mqtt_task_running()) {
        Log_e("MQTT task is running\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");

    /* command execution */
    DeviceInfo devinfo;
    memset((char *)&devinfo, 0, sizeof(DeviceInfo));

    sPrdInfo prdinfo;
    prdinfo.magic_header = 0xfeedbeef;
    if (0 == load_prd_info(__FILE__, &prdinfo)) {
        strncpy(devinfo.product_id, (char *)prdinfo.product_id, MAX_SIZE_OF_PRODUCT_ID);
        strncpy(devinfo.device_name, (char *)prdinfo.device_name, MAX_SIZE_OF_DEVICE_NAME);
        strncpy(devinfo.product_secret, (char *)prdinfo.product_secret, MAX_SIZE_OF_PRODUCT_SECRET);
        strncpy(devinfo.product_region, (char *)prdinfo.product_region, MAX_SIZE_OF_PRODUCT_REGION);
    } else {
        Log_e("load prd info from flash err");
        at_cmd_printf("+TCDEVREG:FAIL,%d\n", eFLASH_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    int Ret = ESP_AT_RESULT_CODE_OK;
    Ret     = do_dyn_reg_dev((void *)&devinfo);

    if (Ret) {
        Log_e("dynamic register device failed: %d", Ret);
        at_cmd_printf("+TCDEVREG:FAIL,%d\n", Ret);
    } else {
        sDevInfo rdevinfo;
        memset((char *)&rdevinfo, 0, sizeof(sDevInfo));
        rdevinfo.TLS_mode = prdinfo.TLS_mode;
        strncpy(rdevinfo.product_id, (char *)devinfo.product_id, MAX_SIZE_OF_PRODUCT_ID);
        strncpy(rdevinfo.device_name, (char *)devinfo.device_name, MAX_SIZE_OF_DEVICE_NAME);
        strncpy(rdevinfo.device_secret, (char *)devinfo.device_secret, MAX_SIZE_OF_DEVICE_SECRET);
        strncpy(rdevinfo.product_region, (char *)prdinfo.product_region, MAX_SIZE_OF_PRODUCT_REGION);

        rdevinfo.magic_header = VALID_MAGIC_CODE;
        if (save_dev_info(&rdevinfo)) {
            Log_e("save dev info failed");
            Ret = eFLASH_ERR;
            at_cmd_printf("+TCDEVREG:FAIL,%d\n", Ret);
        } else {
            Log_i("save dev info success");
            at_cmd_printf("+TCDEVREG:OK\n");
        }
    }

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_mqtt_conn_test(uint8_t *cmd_name)
{
    at_cmd_printf(
        "+TCMQTTCONN:<TLSMODE_SELECTED>,<CMDTIMEOUT_VALUE(%d-%dms)>,<KEEPALIVE>(60-690s),"
        "<CLEAN_SESSION>(0/1),<RECONNECT>(0/1)\n",
        MIN_COMMAND_TIMEOUT, MAX_COMMAND_TIMEOUT);

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_mqtt_conn_query(uint8_t *cmd_name)
{
    uint8_t        Ret = ESP_AT_RESULT_CODE_OK;
    MQTTInitParams conn_params;

    if (0 == get_mqtt_conn_parameters(&conn_params)) {
        at_cmd_printf("+TCMQTTCONN:%u,%u,%u,%u,%u\n", 1, conn_params.command_timeout,
                      conn_params.keep_alive_interval_ms / 1000, conn_params.clean_session,
                      conn_params.auto_connect_enable);
    } else {
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        Ret = ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    return Ret;
}

static uint8_t at_mqtt_conn_setup(uint8_t para_num)
{
    /* check state */
    if (is_mqtt_task_running()) {
        Log_e("MQTT task is running\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* parameters parsing */
    uint8_t cnt = 0;
    int32_t TLS_mode, command_timeout_ms, keep_alive_interval, clean_session, auto_connect_enable;

    if (esp_at_get_para_as_digit(cnt++, &TLS_mode) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (TLS_mode != 1) {
        Log_e("only support TLS mode 1\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, (int32_t *)&command_timeout_ms) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (command_timeout_ms < MIN_COMMAND_TIMEOUT || command_timeout_ms > MAX_COMMAND_TIMEOUT) {
        Log_e("command timeout invalid %d\n", command_timeout_ms);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, (int32_t *)&keep_alive_interval) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (keep_alive_interval < 60 || keep_alive_interval > 690) {
        Log_e("keep_alive_interval invalid %d\n", keep_alive_interval);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, (int32_t *)&clean_session) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (clean_session != 0 && clean_session != 1) {
        Log_e("clean_session invalid %d\n", clean_session);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, (int32_t *)&auto_connect_enable) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (auto_connect_enable != 0 && auto_connect_enable != 1) {
        Log_e("auto_connect_enable invalid %d\n", auto_connect_enable);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");

    /* command execution */
    MQTTInitParams conn_params = DEFAULT_MQTTINIT_PARAMS;
    sDevInfo       rdevinfo;

    conn_params.command_timeout        = command_timeout_ms;
    conn_params.keep_alive_interval_ms = keep_alive_interval * 1000;
    conn_params.clean_session          = clean_session;
    conn_params.auto_connect_enable    = auto_connect_enable;

    rdevinfo.magic_header = 0xfeedbeef;
    if (0 == load_dev_info(__FILE__, &rdevinfo)) {
        conn_params.product_id    = rdevinfo.product_id;
        conn_params.device_name   = rdevinfo.device_name;
        conn_params.device_secret = rdevinfo.device_secret;
        conn_params.product_region = rdevinfo.product_region;
    } else {
        Log_e("load dev info from flash err\n");
        at_cmd_printf("+TCMQTTCONN:FAIL,%d\n", eFLASH_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    int err_code = do_mqtt_connect(&conn_params);
    if (err_code) {
        at_cmd_printf("+TCMQTTCONN:FAIL,%d\n", err_code);
    } else {
        at_cmd_printf("+TCMQTTCONN:OK\n");
    }

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_mqtt_dis_conn_test(uint8_t *cmd_name)
{
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_mqtt_dis_conn(uint8_t *cmd_name)
{
    uint8_t Ret = ESP_AT_RESULT_CODE_OK;
    int     err_code;

    err_code = do_mqtt_disconnect();
    if (err_code) {
        at_cmd_printf("+CME ERROR:%d\n", err_code);
        Ret = ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    return Ret;
}

static uint8_t at_mqtt_pub_test(uint8_t *cmd_name)
{
    at_cmd_printf("+TCMQTTPUB: \"TOPIC_NAME(maxlen %d)\", \"QOS(0/1)\",\"PAYLOAD\"\n", MAX_SIZE_OF_CLOUD_TOPIC);

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_mqtt_pub_setup(uint8_t para_num)
{
    /* check state */
    if (!get_mqtt_connect_state()) {
        Log_e("MQTT is NOT connected\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /*  enable this cmd as FW updating might be too time-consuming
        if (is_fw_downloading()) {
            Log_e("firmware is downloading\n");
            at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
        }
    */

    /* parameters parsing */
    int32_t  cnt     = 0, qos;
    uint8_t *topic   = NULL;
    uint8_t *payload = NULL;

    if (para_num != 3) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (esp_at_get_para_as_str(cnt++, &topic) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    size_t len = strlen((char *)topic);
    if (len == 0 || len > MAX_SIZE_OF_CLOUD_TOPIC) {
        Log_e("topic name oversize\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, &qos) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (qos != QOS0 && qos != QOS1) {
        Log_e("Invalid QoS level %d", qos);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_str(cnt++, &payload) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    len = strlen((char *)payload);
    if (len == 0) {
        Log_e("topic payload is null\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");

    /* command execution */
    int err_code = do_mqtt_pub_msg((char *)topic, qos, (char *)payload, len);
    if (err_code) {
        at_cmd_printf("+TCMQTTPUB:FAIL,%d\n", err_code);
    } else {
        at_cmd_printf("+TCMQTTPUB:OK\n");
    }

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

#define MAX_SIZE_OF_PUBL_PAYLOAD 2048

static uint8_t at_mqtt_publ_test(uint8_t *cmd_name)
{
    at_cmd_printf("%s: \"TOPIC_NAME(maxlen %d)\", \"QOS(0/1)\",\"LEN(1-%d)\"\n", (char *)cmd_name,
                    MAX_SIZE_OF_CLOUD_TOPIC, MAX_SIZE_OF_PUBL_PAYLOAD);

    return ESP_AT_RESULT_CODE_OK;
}

static SemaphoreHandle_t g_publ_sync_sema = NULL;

static void wait_data_callback(void)
{
    xSemaphoreGive(g_publ_sync_sema);
}

/**
 * return value:
 *   0 = timeout;
 *   -1 = quit or payload length less than expected;
 *   payload_len: success
 */
static int32_t read_publ_payload(uint8_t *payload_buf, int32_t payload_len)
{
#define PUBL_READ_PAYLOAD_TIMEOUT 20000  // wait 20 seconds
    /* to read long message from UART */
    vSemaphoreCreateBinary(g_publ_sync_sema);
    xSemaphoreTake(g_publ_sync_sema, PUBL_READ_PAYLOAD_TIMEOUT / portTICK_PERIOD_MS);

    esp_at_port_write_data((uint8_t *)">\r\n", strlen(">\r\n"));

    esp_at_port_enter_specific(wait_data_callback);
    int32_t read_size = 0;
    while (xSemaphoreTake(g_publ_sync_sema, PUBL_READ_PAYLOAD_TIMEOUT / portTICK_PERIOD_MS)) {
        int32_t len = esp_at_port_read_data(payload_buf + read_size, payload_len - read_size);
        if (len > 0)
            read_size += len;
        else
            Log_w("esp_at_port_read_data failed: %d", len);

        // Log_d("read len: %d read size: %d payload len: %d", len, read_size, payload_len);
        if (read_size == payload_len) {
            /* read the terminal "\r\n" */
            uint8_t temp[4] = {0};
            len             = esp_at_port_read_data(temp, 2);
            if (len < 2) {
                /* wait a short time for the terminal */
                xSemaphoreTake(g_publ_sync_sema, 1000 / portTICK_PERIOD_MS);
                esp_at_port_read_data(temp + len, 2 - len);
            }

            if ((temp[1] != '\n') || (temp[0] != '\r')) {
                /* this is error as terminal not correct */
                Log_e("esp_at_port_read_data invalid end: %d %d %s", len, read_size, temp);
                read_size = -1;
            }

            break;
        } else if (payload_buf[read_size - 1] == '\n' && payload_buf[read_size - 2] == '\r') {
            /* incomplete */
            Log_e("esp_at_port_read_data incomplete: %d", read_size);
            break;
        } else if (strstr((char *)payload_buf, "+++\r\n")) {
            /* +++ for quit */
            Log_e("esp_at_port_read_data user teminated: %d", read_size);
            break;
        }
    }

    if (read_size != payload_len) {
        Log_e("read error: read size: %d payload len: %d", read_size, payload_len);
        if (IOT_Log_Get_Level() >= eLOG_INFO)
            HAL_Printf(">>>incomplete payload: <%s>\n", payload_buf);
    }

    esp_at_port_exit_specific();
    vSemaphoreDelete(g_publ_sync_sema);
    return read_size;
}

static void clean_escapes(uint8_t *payload_buf, int32_t payload_len)
{
    int i = 0, j = 0;
    while (payload_buf[i] && i < (payload_len - 1)) {
        // only clean "\"" and "\,"
        if ((payload_buf[i] == '\\') && (payload_buf[i + 1] == '"' || payload_buf[i + 1] == ',')) {
            // workaroud: replace with space
            payload_buf[i] = ' ';

            if (payload_buf[i + 1] == '"') {
                j++;

                // swap space next to double quotes
                if (!(j % 2)) {
                    int8_t temp        = payload_buf[i];
                    payload_buf[i]     = payload_buf[i + 1];
                    payload_buf[i + 1] = temp;
                }
            }
            i += 2;
        } else {
            i++;
        }
    }
}

static uint8_t at_mqtt_publ_setup(uint8_t para_num)
{
    /* check state */
    if (!get_mqtt_connect_state()) {
        Log_e("MQTT is NOT connected\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* parameters parsing */
    int32_t  cnt   = 0, qos, payload_len;
    uint8_t *topic = NULL;

    if (para_num != 3) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (esp_at_get_para_as_str(cnt++, &topic) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    size_t len = strlen((char *)topic);
    if (len == 0 || len > MAX_SIZE_OF_CLOUD_TOPIC) {
        Log_e("topic name oversize\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, &qos) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (qos != QOS0 && qos != QOS1) {
        Log_e("invalid QoS level %d", qos);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, &payload_len) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (payload_len <= 0 || payload_len > MAX_SIZE_OF_PUBL_PAYLOAD) {
        Log_e("topic payload oversize\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    uint8_t *payload_buf = malloc(payload_len + 1);
    if (payload_buf == NULL) {
        Log_e("memory malloc failed\n");
        at_cmd_printf("+CME ERROR:%d\n", eMEM_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }
    memset(payload_buf, 0, payload_len + 1);

    at_cmd_printf("OK\n");

    if (payload_len == read_publ_payload(payload_buf, payload_len)) {
        // at_cmd_printf("OK\n");
    } else {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        free(payload_buf);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* workaround JSON escapes */
    clean_escapes(payload_buf, payload_len);

    /* command execution */
    int err_code = do_mqtt_pub_msg((char *)topic, qos, (char *)payload_buf, payload_len);
    if (err_code) {
        at_cmd_printf("+TCMQTTPUBL:FAIL,%d\n", err_code);
    } else {
        at_cmd_printf("+TCMQTTPUBL:OK\n");
    }

    free(payload_buf);
    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_mqtt_pubraw_setup(uint8_t para_num)
{
    /* check state */
    if (!get_mqtt_connect_state()) {
        Log_e("MQTT is NOT connected\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* parameters parsing */
    int32_t  cnt   = 0, qos, payload_len;
    uint8_t *topic = NULL;

    if (para_num != 3) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (esp_at_get_para_as_str(cnt++, &topic) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    size_t len = strlen((char *)topic);
    if (len == 0 || len > MAX_SIZE_OF_CLOUD_TOPIC) {
        Log_e("topic name oversize\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, &qos) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (qos != QOS0 && qos != QOS1) {
        Log_e("invalid QoS level %d", qos);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, &payload_len) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (payload_len <= 0 || payload_len > MAX_SIZE_OF_PUBL_PAYLOAD) {
        Log_e("topic payload oversize\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    uint8_t *payload_buf = malloc(payload_len + 1);
    if (payload_buf == NULL) {
        Log_e("memory malloc failed\n");
        at_cmd_printf("+CME ERROR:%d\n", eMEM_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }
    memset(payload_buf, 0, payload_len + 1);

    at_cmd_printf("OK\n");

    if (payload_len == read_publ_payload(payload_buf, payload_len)) {
        // at_cmd_printf("OK\n");
    } else {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        free(payload_buf);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* command execution */
    int err_code = do_mqtt_pub_msg((char *)topic, qos, (char *)payload_buf, payload_len);
    if (err_code) {
        at_cmd_printf("+TCMQTTPUBRAW:FAIL,%d\n", err_code);
    } else {
        at_cmd_printf("+TCMQTTPUBRAW:OK\n");
    }

    free(payload_buf);
    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_mqtt_sub_test(uint8_t *cmd_name)
{
    at_cmd_printf("+TCMQTTSUB:\"TOPIC_NAME(maxlen %d)\",\"QOS(0/1)\"\n", MAX_SIZE_OF_CLOUD_TOPIC);

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_mqtt_sub_query(uint8_t *cmd_name)
{
    get_mqtt_sub_list();

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_mqtt_sub_setup(uint8_t para_num)
{
    /* check state */
    if (!get_mqtt_connect_state()) {
        Log_e("MQTT is NOT connected\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* parameters parsing */
    int32_t  cnt   = 0, qos;
    uint8_t *topic = NULL;

    if (para_num != 2) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (esp_at_get_para_as_str(cnt++, &topic) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    size_t len = strlen((char *)topic);
    if (len == 0 || len > MAX_SIZE_OF_CLOUD_TOPIC) {
        Log_e("topic name oversize\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, &qos) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (qos != QOS0 && qos != QOS1) {
        Log_e("invalid QoS level %d", qos);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");

    /* command execution */
    int err_code = do_mqtt_sub_msg((char *)topic, qos);
    if (err_code) {
        at_cmd_printf("+TCMQTTSUB:FAIL,%d\n", err_code);
    } else {
        at_cmd_printf("+TCMQTTSUB:OK\n");
    }

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_mqtt_unsub_test(uint8_t *cmd_name)
{
    at_cmd_printf("+TCMQTTUNSUB:\"TOPIC_NAME\"\n");

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_mqtt_unsub_query(uint8_t *cmd_name)
{
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_mqtt_unsub_setup(uint8_t para_num)
{
    /* check state */
    if (!get_mqtt_connect_state()) {
        Log_e("MQTT is NOT connected\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* parameters parsing */
    int32_t  cnt   = 0;
    uint8_t *topic = NULL;

    if (esp_at_get_para_as_str(cnt++, &topic) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (topic == NULL) {
        Log_e("topic name invalid, %u\n", para_num);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    size_t len = strlen((char *)topic);
    if (len == 0 || len > MAX_SIZE_OF_CLOUD_TOPIC) {
        Log_e("topic name oversize\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");

    /* command execution */
    int err_code = do_mqtt_unsub_msg((char *)topic);
    if (err_code) {
        at_cmd_printf("+TCMQTTUNSUB:FAIL,%d\n", err_code);
    } else {
        at_cmd_printf("+TCMQTTUNSUB:OK\n");
    }

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_mqtt_state_test(uint8_t *cmd_name)
{
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_mqtt_state_query(uint8_t *cmd_name)
{
    at_cmd_printf("+TCMQTTSTATE:%d\n", get_mqtt_connect_state());
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_mqtt_server_test(uint8_t *cmd_name)
{
    at_cmd_printf("%s:\"MQTT SERVER IP\"\n", cmd_name);

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_mqtt_server_query(uint8_t *cmd_name)
{
    char *pString = NULL;

    pString = get_mqtt_test_server_ip();
    if(pString != NULL)
    {
        at_cmd_printf("+TCMQTTSRV:%s\n", pString);
    }
    else
    {
        at_cmd_printf("+TCMQTTSRV:NULL\n");
    }
    
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_mqtt_server_setup(uint8_t para_num)
{
    if (is_mqtt_task_running()) {
        Log_e("MQTT task is running\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* parameters parsing */
    int32_t  cnt       = 0;
    uint8_t *server_ip = NULL;

    if (esp_at_get_para_as_str(cnt++, &server_ip) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
        ;
    }

    if (server_ip == NULL) {
        Log_e("server_ip invalid, %u\n", para_num);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");

    /* command execution */
    if (0 != set_mqtt_test_server_ip((char *)server_ip)) {
        at_cmd_printf("+TCMQTTSRV:FAIL\n");
    } else {
        at_cmd_printf("+TCMQTTSRV:OK\n");
    }

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_module_info_test(uint8_t *cmd_name)
{
    at_cmd_printf(
        "%s:\"MODULE NAME\",\"FLASH_SIZE (2/4)\",\"WIFI LED GPIO\",\"FW BASE ADDR\",\"FW MAX SIZE\",\"RESERVED\"\n",
        cmd_name);

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_module_info_query(uint8_t *cmd_name)
{
    uint8_t      Ret         = ESP_AT_RESULT_CODE_OK;
    sModuleInfo *pModuleInfo = get_module_info();

    at_cmd_printf("%s:\"%s\",%u,%u,%u,%u,%u\n", cmd_name, pModuleInfo->module_name, pModuleInfo->module_flash_size,
                  pModuleInfo->wifi_led_gpio, pModuleInfo->ota_base_addr, pModuleInfo->ota_max_size,
                  pModuleInfo->use_fixed_connid);

    return ESP_AT_RESULT_CODE_OK;

    return Ret;
}
static uint8_t at_module_info_setup(uint8_t para_num)
{
    /* check state */
    if (is_mqtt_task_running()) {
        Log_e("MQTT task is running\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* parameters parsing */
    int32_t  cnt         = 0, flash_size, wifi_led_gpio, ota_base_addr, ota_max_size, use_fixed_connid;
    uint8_t *module_name = NULL;

    if (para_num != 6) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (esp_at_get_para_as_str(cnt++, &module_name) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    size_t len = strlen((char *)module_name);
    if (len == 0 || len > MAX_SIZE_OF_MODULE_NAME) {
        Log_e("module_name oversize\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, &flash_size) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (flash_size != 2 && flash_size != 4) {
        Log_e("only support flash size 2MB or 4MB\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, &wifi_led_gpio) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    /* ESP8266 GPIO range: 0-16*/
    if (wifi_led_gpio > 16) {
        Log_e("invalid gpio value %u\n", wifi_led_gpio);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, &ota_base_addr) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (ota_base_addr % SPI_FLASH_SEC_SIZE || ota_base_addr < OTA_FW_START_FLASH_ADDR) {
        Log_e("invalid ota_base_addr value 0x%x\n", ota_base_addr);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, &ota_max_size) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    // this limit only for 2MB FLASH
    if (flash_size == 2 && ota_max_size > OTA_FW_MAX_FLASH_SIZE) {
        Log_e("invalid ota_max_size value 0x%x\n", ota_max_size);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_digit(cnt++, &use_fixed_connid) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }
    at_cmd_printf("OK\n");

    /* command execution */
    sModuleInfo module_info;
    memset((char *)&module_info, 0, sizeof(sModuleInfo));
    module_info.magic_header      = VALID_MAGIC_CODE;
    module_info.module_flash_size = flash_size;
    module_info.wifi_led_gpio     = wifi_led_gpio;
    module_info.ota_base_addr     = ota_base_addr;
    module_info.ota_max_size      = ota_max_size;
    module_info.use_fixed_connid  = use_fixed_connid;
    strncpy(module_info.module_name, (char *)module_name, MAX_SIZE_OF_MODULE_NAME);

    uint8_t Ret = ESP_AT_RESULT_CODE_OK;
    if (0 == save_module_info(&module_info)) {
        Log_i("save module info success\n");
    } else {
        Log_e("save module info to flash err\n");
        Ret = eFLASH_ERR;
    }

    if (Ret) {
        at_cmd_printf("+TCMODINFOSET:FAIL,%d\n", Ret);
    } else {
        at_cmd_printf("+TCMODINFOSET:OK\n");
    }

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

/******************* FW OTA command ****************************/
static char     g_user_fw_version[MAX_SIZE_OF_FW_VERSION + 1] = {0};
static uint32_t g_fw_fetched_bytes                            = 0;
static uint32_t g_fw_size_bytes                               = 0;
static bool g_ota_enable = false;

static uint8_t at_ota_set_test(uint8_t *cmd_name)
{
    at_cmd_printf("+TCOTASET:1(ENABLE)/0(DISABLE),\"FW_version\"\n");

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_ota_set_query(uint8_t *cmd_name)
{
    at_cmd_printf("+TCOTASET:%d,\"%s\"\n", g_ota_enable ? 1 : 0, g_user_fw_version);
    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_ota_set_setup(uint8_t para_num)
{
    /* parameters parsing */
    int32_t  cnt     = 0, ctrl;
    uint8_t *version = NULL;

    if (esp_at_get_para_as_digit(cnt++, &ctrl) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (ctrl != 0 && ctrl != 1) {
        Log_e("ctrl invalid %d\n", ctrl);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_str(cnt++, &version) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    size_t len = strlen((char *)version);
    if (len == 0 || len > 32) {
        Log_e("version name oversize\n");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (ctrl) {
        g_ota_enable = true;

        /* check state */
        if (!get_mqtt_connect_state()) {
            Log_e("MQTT is NOT connected\n");
            at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
        }

        if (is_fw_downloading()) {
            Log_e("firmware is downloading\n");
            at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
        }
    } else {
        g_ota_enable = false;
    }

    at_cmd_printf("OK\n");

    /* command execution */
    strncpy(g_user_fw_version, (char *)version, MAX_SIZE_OF_FW_VERSION);
    int err_code = do_fw_ota_update(g_ota_enable, g_user_fw_version);
    if (err_code) {
        at_cmd_printf("+TCOTASET:FAIL,%d\n", err_code);
    } else {
        at_cmd_printf("+TCOTASET:OK\n");
    }

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_fw_info_test(uint8_t *cmd_name)
{
    at_cmd_printf("+TCFWINFO:\"FW_VERSION\",\"FW_SIZE\",\"FW_MD5\",\"FW_MAX_SIZE_OF_MODULE\"\n");

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_fw_info_query(uint8_t *cmd_name)
{
    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }
    sOTAFirmwareInfo fw_info;

    if (load_fw_info(&fw_info)) {
        at_cmd_printf("+CME ERROR:%d\n", eFLASH_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (fw_info.fw_state != OTA_FW_MCU_VALID) {
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    g_fw_size_bytes = fw_info.fw_size;
    /* reset the FW read index */
    g_fw_fetched_bytes = 0;

    at_cmd_printf("OK\n");

    at_cmd_printf("+TCFWINFO:\"%s\",%u,\"%s\",%u\n", fw_info.fw_version, fw_info.fw_size, fw_info.fw_md5,
                  fw_info.fw_max_size_of_module);

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_read_fw_data_test(uint8_t *cmd_name)
{
    at_cmd_printf("+TCREADFWDATA:\"LEN_FOR_READ\"\n");

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_read_fw_data_setup(uint8_t para_num)
{
    /* check state */
    if (is_fw_downloading()) {
        Log_e("firmware is downloading\n");
        at_cmd_printf("+CME ERROR:%d\n", eDEALING_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (!g_fw_size_bytes) {
        sOTAFirmwareInfo fw_info;

        if (load_fw_info(&fw_info)) {
            Log_e("load fw info failed.\n");
            at_cmd_printf("+CME ERROR:%d\n", eFLASH_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
        }

        if (fw_info.fw_state != OTA_FW_MCU_VALID) {
            at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
        }

        g_fw_size_bytes = fw_info.fw_size;
        if (g_fw_size_bytes == 0) {
            Log_e("firmware size is zero\n");
            at_cmd_printf("+CME ERROR:%d\n", eFIRMWARE_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
        }
    }

    if (g_fw_fetched_bytes == g_fw_size_bytes) {
        Log_e("firmware is read completely.\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* parameters parsing */
    int32_t cnt = 0, read_size_bytes;

    if (esp_at_get_para_as_digit(cnt++, &read_size_bytes) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (read_size_bytes > SPI_FLASH_SEC_SIZE) {
        Log_e("read_size_bytes oversize %d\n", read_size_bytes);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");

    /* command execution */
    uint32_t alloc_bytes;

    if ((g_fw_fetched_bytes + read_size_bytes) > g_fw_size_bytes)
        read_size_bytes = g_fw_size_bytes - g_fw_fetched_bytes;

    if (read_size_bytes % 4) {
        /* rounded to be word aligned */
        alloc_bytes = read_size_bytes + 4 - (read_size_bytes % 4) + 20;
    } else
        alloc_bytes = read_size_bytes + 20;

    char hdr_buf[20] = {0};
    HAL_Snprintf(hdr_buf, sizeof(hdr_buf), "+TCREADFWDATA:%u,", read_size_bytes);
    size_t hdr_len = strlen(hdr_buf);

    uint8_t *buf = malloc(alloc_bytes);
    if (buf == NULL) {
        Log_e("malloc %u failed.\n", alloc_bytes);
        at_cmd_printf("+CME ERROR:%d\n", eMEM_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }
    memset(buf, 0, alloc_bytes);

    if (read_fw_from_flash(buf, alloc_bytes, g_fw_fetched_bytes, g_fw_size_bytes)) {
        at_cmd_printf("+CME ERROR:%d\n", eFLASH_ERR);
        free(buf);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    esp_at_port_write_data((uint8_t *)hdr_buf, hdr_len);
    esp_at_port_write_data((uint8_t *)buf, read_size_bytes);
    esp_at_port_write_data((uint8_t *)"\r\n", strlen("\r\n"));

#if 0
    char *buf_byte = (char *)buf;
    int i;
    for(i=0; i<read_size_bytes; i++) {    
        if (!(i%32))
            printf("\n");
        printf("%02x ", buf_byte[i]);       
    }
#endif

    fflush(stdout);

    g_fw_fetched_bytes += read_size_bytes;

    free(buf);

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_gw_bind_test(uint8_t *cmd_name)
{
    at_cmd_printf("%s:\"MODE\",\"PRODUCT_ID\",\"DEVICE_NAME\",\"DEVICE_SECRET\"\n", cmd_name);

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_gw_bind_setup(uint8_t para_num)
{
    /* check state */
    if (!get_mqtt_connect_state()) {
        Log_e("MQTT is NOT connected\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* parameters parsing */
    int32_t  cnt           = 0, mode;
    uint8_t *product_id    = NULL;
    uint8_t *device_name   = NULL;
    uint8_t *device_secret = NULL;

    if (esp_at_get_para_as_digit(cnt++, &mode) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (mode != 0 && mode != 1) {
        Log_e("invalid mode %d", mode);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_str(cnt++, &product_id) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    size_t len = strlen((char *)product_id);
    if (len == 0 || len > MAX_SIZE_OF_PRODUCT_ID) {
        Log_e("product_id oversize");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_str(cnt++, &device_name) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    len = strlen((char *)device_name);
    if (len == 0 || len > MAX_SIZE_OF_DEVICE_NAME) {
        Log_e("device_name oversize");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (mode == 0) {
        if (esp_at_get_para_as_str(cnt++, &device_secret) != ESP_AT_PARA_PARSE_RESULT_OK) {
            at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
        }

        len = strlen((char *)device_secret);
        if (len == 0 || len > MAX_SIZE_OF_DEVICE_SECRET) {
            Log_e("device_secret oversize");
            at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
            return ESP_AT_RESULT_CODE_PROCESS_DONE;
        }
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");

    /* command execution */
    int err_code = do_gw_bind_subdev(mode, (char *)product_id, (char *)device_name, (char *)device_secret);
    if (err_code) {
        at_cmd_printf("+TCGWBIND:FAIL,%d\n", err_code);
    } else {
        at_cmd_printf("+TCGWBIND:OK\n");
    }

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

static uint8_t at_gw_online_test(uint8_t *cmd_name)
{
    at_cmd_printf("%s:\"MODE\",\"PRODUCT_ID\",\"DEVICE_NAME\"\n", cmd_name);

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_gw_online_query(uint8_t *cmd_name)
{
    get_online_subdev_list();

    return ESP_AT_RESULT_CODE_OK;
}

static uint8_t at_gw_online_setup(uint8_t para_num)
{
    /* check state */
    if (!get_mqtt_connect_state()) {
        Log_e("MQTT is NOT connected\n");
        at_cmd_printf("+CME ERROR:%d\n", eSTATE_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    /* parameters parsing */
    int32_t  cnt           = 0, mode;
    uint8_t *product_id    = NULL;
    uint8_t *device_name   = NULL;

    if (esp_at_get_para_as_digit(cnt++, &mode) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    if (mode != 0 && mode != 1) {
        Log_e("invalid mode %d", mode);
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_str(cnt++, &product_id) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    size_t len = strlen((char *)product_id);
    if (len == 0 || len > MAX_SIZE_OF_PRODUCT_ID) {
        Log_e("product_id oversize");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (esp_at_get_para_as_str(cnt++, &device_name) != ESP_AT_PARA_PARSE_RESULT_OK) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    len = strlen((char *)device_name);
    if (len == 0 || len > MAX_SIZE_OF_DEVICE_NAME) {
        Log_e("device_name oversize");
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }

    at_cmd_printf("OK\n");

    /* command execution */
    int err_code = do_gw_online_subdev(mode, (char *)product_id, (char *)device_name);
    if (err_code) {
        at_cmd_printf("+TCGWONLINE:FAIL,%d\n", err_code);
    } else {
        at_cmd_printf("+TCGWONLINE:OK\n");
    }

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

extern float sg_ch20_ppm_value;
static uint8_t at_report_setup(uint8_t para_num)
{
    /* parameters parsing */
    int32_t  cnt           = 0;
    uint8_t *ch20_ppm_value = NULL;

    if (esp_at_get_para_as_str(cnt++, &ch20_ppm_value) != ESP_AT_PARA_PARSE_RESULT_OK) {
        return ESP_AT_RESULT_CODE_ERROR;
    }

    at_cmd_printf("OK\n");
    if (cnt != para_num) {
        at_cmd_printf("+CME ERROR:%d\n", ePARA_ERR);
        return ESP_AT_RESULT_CODE_PROCESS_DONE;
    }
    at_cmd_printf("+TCREPORT:OK\n");
    sg_ch20_ppm_value = atof((const char*)ch20_ppm_value);

    printf("ch20_ppm_value %.3f\n", sg_ch20_ppm_value);
    ble_event_report_property();

    return ESP_AT_RESULT_CODE_PROCESS_DONE;
}

/**************** Tencent IoT MQTT&OTA AT commands end ***************/

static esp_at_cmd_struct at_qcloud_cmd[] = {

    /**************** Tencent IoT WiFi&Utils AT commands ***************/
    {"+TCSTARTSMART", at_startsmart_test, NULL, NULL, at_startsmart_exec},
    {"+TCSTOPSMART", at_stopsmart_test, NULL, NULL, at_stopsmart_exec},
    {"+TCSAP", at_sap_test, at_sap_query, at_sap_setup, NULL},
    {"+TCSTOPSAP", at_stopsap_test, NULL, NULL, at_stopsap_exec},
    //{"+TCJAP", at_jap_test, at_jap_query, at_jap_setup, NULL},
    {"+TCMODULE", NULL, NULL, NULL, at_module_exec},
    {"+TCVER", NULL, NULL, NULL, at_version_exec},
    {"+TCRESTORE", at_restore_test, NULL, NULL, at_restore_exec},
    {"+TCMODINFOSET", at_module_info_test, at_module_info_query, at_module_info_setup, NULL},
    {"+TCMQTTSRV", at_mqtt_server_test, at_mqtt_server_query, at_mqtt_server_setup, NULL},
    /**************** Tencent IoT MQTT&OTA AT commands ***************/
    {"+TCPRDINFOSET", at_prd_info_test, at_prd_info_query, at_prd_info_setup, NULL},
    {"+TCDEVINFOSET", at_dev_info_test, at_dev_info_query, at_dev_info_setup, NULL},
    {"+TCDEVREG", at_dev_register_test, NULL, NULL, at_dev_register},
    {"+TCMQTTCONN", at_mqtt_conn_test, at_mqtt_conn_query, at_mqtt_conn_setup, NULL},
    {"+TCMQTTDISCONN", at_mqtt_dis_conn_test, NULL, NULL, at_mqtt_dis_conn},
    {"+TCMQTTPUB", at_mqtt_pub_test, NULL, at_mqtt_pub_setup, NULL},
    {"+TCMQTTPUBL", at_mqtt_publ_test, NULL, at_mqtt_publ_setup, NULL},
    {"+TCMQTTPUBRAW", at_mqtt_publ_test, NULL, at_mqtt_pubraw_setup, NULL},
    {"+TCMQTTSUB", at_mqtt_sub_test, at_mqtt_sub_query, at_mqtt_sub_setup, NULL},
    {"+TCMQTTUNSUB", at_mqtt_unsub_test, at_mqtt_unsub_query, at_mqtt_unsub_setup, NULL},
    {"+TCMQTTSTATE", at_mqtt_state_test, at_mqtt_state_query, NULL, NULL},
    {"+TCOTASET", at_ota_set_test, at_ota_set_query, at_ota_set_setup, NULL},
    {"+TCFWINFO", at_fw_info_test, at_fw_info_query, NULL, NULL},
    {"+TCREADFWDATA", at_read_fw_data_test, NULL, at_read_fw_data_setup, NULL},
    {"+TCGWBIND", at_gw_bind_test, NULL, at_gw_bind_setup, NULL},
    {"+TCGWONLINE", at_gw_online_test, at_gw_online_query, at_gw_online_setup, NULL},
    {"+TCGWBIND", at_gw_bind_test, NULL, at_gw_bind_setup, NULL},
    {"+TCREPORT", NULL, NULL, at_report_setup, NULL},
/**************** Tencent IoT MQTT&OTA AT commands end ***************/
#ifdef ENABLE_TEST_COMMANDS
    {"+NTP", NULL, at_ntp_query, at_ntp_setup, at_ntp_exec},
    {"+TCLOG", at_log_test, at_log_query, at_log_setup, NULL},
#endif
};

bool qcloud_iot_at_cmd_regist(void)
{
    printf("%s\r\n", QCLOUD_IOT_AT_VERSION);
    IOT_Log_Set_Level(eLOG_ERROR);
    init_flash_addr();
    board_init();

    if (!esp_at_custom_cmd_array_regist(at_qcloud_cmd, sizeof(at_qcloud_cmd) / sizeof(at_qcloud_cmd[0]))) {
        Log_e("regist qcloud AT cmd failed\n");
        return false;
    }

    return true;
}
