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
#include "esp_ota_ops.h"
#include "esp_partition.h"

#include "qcloud_iot_export.h"
#include "qcloud_iot_import.h"
#include "gateway_common.h"

#include "qcloud_at_cmd.h"
#include "qcloud_at_mqtt.h"
#include "qcloud_at_flash.h"
#include "qcloud_at_board.h"

#define MQTT_CLIENT_TASK_NAME        "mqtt_client_task"
#define MQTT_CLIENT_TASK_STACK_BYTES 4096
#define MQTT_CLIENT_TASK_PRIO        3

static void *         g_mqtt_client = NULL;
TaskHandle_t          g_mqtt_task;
static MQTTInitParams g_init_params = DEFAULT_MQTTINIT_PARAMS;

static bool g_mqtt_task_running = false;
static bool g_cmd_processing    = false;

static int  g_ret_code                             = 0;
static char g_mqtt_test_server_ip[HOST_STR_LENGTH] = {0};
static void *sg_gw_client = NULL;

// support both raw IP and host URL
int set_mqtt_test_server_ip(char *server_ip)
{
    if (server_ip != NULL && strlen(server_ip) > 0) {
        memset(g_mqtt_test_server_ip, 0, sizeof(g_mqtt_test_server_ip));
        strncpy(g_mqtt_test_server_ip, server_ip, sizeof(g_mqtt_test_server_ip) - 1);
        Log_w("MQTT server has been set to %s", g_mqtt_test_server_ip);
        return 0;
    }

    return 1;
}

char *get_mqtt_test_server_ip(void)
{
    if (strlen(g_mqtt_test_server_ip))
        return g_mqtt_test_server_ip;
    else
        return NULL;
}

static void _on_message_callback(void *pClient, MQTTMessage *message, void *userData)
{
    if (message == NULL) {
        Log_e("msg null");
        return;
    }

    if (message->topic_len == 0 && message->payload_len == 0) {
        Log_e("length zero");
        return;
    }

    Log_d("recv msg topic: %s, len: %u", message->ptopic, message->payload_len);

#ifdef CONFIG_FREERTOS_USE_TRACE_FACILITY
    // TaskStatus_t task_status;
    // vTaskGetInfo(NULL, &task_status, pdTRUE, eRunning);
    // Log_i(">>>>> task %s stack left: %u, free heap: %u", task_status.pcTaskName, task_status.usStackHighWaterMark,
    // esp_get_free_heap_size());
#endif

#define AT_MQTTPUB_FIX_LEN 30
    uint32_t at_topic_len = message->topic_len + message->payload_len + AT_MQTTPUB_FIX_LEN;
    char *   buf          = (char *)HAL_Malloc(at_topic_len);
    if (buf == NULL) {
        Log_e("malloc %u bytes failed, topic: %s", at_topic_len, message->ptopic);
        return;
    }

    memset(buf, 0, at_topic_len);
    HAL_Snprintf(buf, at_topic_len, "+TCMQTTRCVPUB:\"%s\",%d,\"", message->ptopic, message->payload_len);
    size_t len = strlen(buf);
    memcpy(buf + len, message->payload, message->payload_len);
    buf[len + message->payload_len]     = '\"';
    buf[len + message->payload_len + 1] = '\r';
    buf[len + message->payload_len + 2] = '\n';
    buf[len + message->payload_len + 3] = 0;

    esp_at_port_write_data((uint8_t *)buf, strlen(buf));

    HAL_Free(buf);
#undef AT_MQTTPUB_FIX_LEN

    return;
}

static void _mqtt_event_handler(void *pclient, void *handle_context, MQTTEventMsg *msg)
{
    MQTTMessage *mqtt_messge = NULL;
    uintptr_t    packet_id   = (uintptr_t)msg->msg;

    switch (msg->event_type) {
        case MQTT_EVENT_UNDEF:
            Log_w("undefined event occur.");
            break;

        case MQTT_EVENT_DISCONNECT:
            Log_w("MQTT disconnect.");
            at_cmd_printf("+TCMQTTDISCON,%d\n", QCLOUD_ERR_MQTT_NO_CONN);
            set_wifi_led_state(LED_OFF);
            break;

        case MQTT_EVENT_RECONNECT:
            Log_i("MQTT reconnect.");
            at_cmd_printf("+TCMQTTRECONNECTED\n");
            set_wifi_led_state(LED_ON);
            break;

        case MQTT_EVENT_PUBLISH_RECVEIVED:
            mqtt_messge = (MQTTMessage *)msg->msg;
            Log_w("topic message arrived without any handler: %s", mqtt_messge->ptopic);
            break;

        case MQTT_EVENT_SUBCRIBE_SUCCESS:
            g_cmd_processing = false;
            g_ret_code       = QCLOUD_RET_SUCCESS;
            Log_i("subscribe success, packet-id=%u", (unsigned int)packet_id);
            break;

        case MQTT_EVENT_SUBCRIBE_TIMEOUT:
            g_cmd_processing = false;
            g_ret_code       = QCLOUD_ERR_MQTT_REQUEST_TIMEOUT;
            Log_e("subscribe wait ack timeout, packet-id=%u", (unsigned int)packet_id);
            break;

        case MQTT_EVENT_SUBCRIBE_NACK:
            g_cmd_processing = false;
            g_ret_code       = QCLOUD_ERR_MQTT_SUB;
            Log_e("subscribe nack, packet-id=%u", (unsigned int)packet_id);
            break;

        case MQTT_EVENT_UNSUBCRIBE_SUCCESS:
            g_cmd_processing = false;
            g_ret_code       = QCLOUD_RET_SUCCESS;
            Log_i("unsubscribe success, packet-id=%u", (unsigned int)packet_id);
            break;

        case MQTT_EVENT_UNSUBCRIBE_TIMEOUT:
            g_cmd_processing = false;
            g_ret_code       = QCLOUD_ERR_MQTT_REQUEST_TIMEOUT;
            Log_e("unsubscribe timeout, packet-id=%u", (unsigned int)packet_id);
            break;

        case MQTT_EVENT_UNSUBCRIBE_NACK:
            g_cmd_processing = false;
            g_ret_code       = QCLOUD_ERR_MQTT_UNSUB_FAIL;
            Log_e("unsubscribe nack, packet-id=%u", (unsigned int)packet_id);
            break;

        case MQTT_EVENT_PUBLISH_SUCCESS:
            g_cmd_processing = false;
            g_ret_code       = QCLOUD_RET_SUCCESS;
            Log_i("publish success, packet-id=%u", (unsigned int)packet_id);
            break;

        case MQTT_EVENT_PUBLISH_TIMEOUT:
            g_cmd_processing = false;
            g_ret_code       = QCLOUD_ERR_MQTT_REQUEST_TIMEOUT;
            Log_e("publish timeout, packet-id=%u", (unsigned int)packet_id);
            break;

        case MQTT_EVENT_PUBLISH_NACK:
            g_cmd_processing = false;
            g_ret_code       = QCLOUD_ERR_FAILURE;
            Log_e("publish nack, packet-id=%u", (unsigned int)packet_id);
            break;

        default:
            Log_i("Should NOT arrive here.");
            break;
    }
}

static void _mqtt_client_task(void *pvParameters)
{
    int             rc;
    MQTTInitParams *mqtt_conn_param = (MQTTInitParams *)pvParameters;

    if (mqtt_conn_param == NULL) {
        Log_e("mqtt_conn_param is null!");
        goto end_of_task;
    }

    Log_i("task start");

    mqtt_conn_param->event_handle.h_fp    = _mqtt_event_handler;
    mqtt_conn_param->event_handle.context = NULL;

    if (strlen(g_mqtt_test_server_ip))
        mqtt_conn_param->mqtt_test_server_ip = g_mqtt_test_server_ip;
    else
        mqtt_conn_param->mqtt_test_server_ip = NULL;

    g_mqtt_client = IOT_MQTT_Construct(mqtt_conn_param);
    if (g_mqtt_client != NULL) {
        Log_i("Cloud Device Construct Success");
        g_ret_code       = QCLOUD_RET_SUCCESS;
        g_cmd_processing = false;
        set_wifi_led_state(LED_ON);
    } else {
        Log_e("Cloud Device Construct Failed");
        g_ret_code       = IOT_MQTT_GetErrCode();
        g_cmd_processing = false;
        goto end_of_task;
    }

#ifdef CONFIG_FREERTOS_USE_TRACE_FACILITY
    TaskStatus_t task_status;
    vTaskGetInfo(NULL, &task_status, pdTRUE, eRunning);
    Log_i(">>>>> task %s stack left: %u, free heap: %u", task_status.pcTaskName, task_status.usStackHighWaterMark,
          esp_get_free_heap_size());
#endif

    /* the parameters might be changed after construct */
    g_init_params.command_timeout        = mqtt_conn_param->command_timeout;
    g_init_params.keep_alive_interval_ms = mqtt_conn_param->keep_alive_interval_ms;
    g_init_params.clean_session          = mqtt_conn_param->clean_session;
    g_init_params.auto_connect_enable    = mqtt_conn_param->auto_connect_enable;

    IOT_MQTT_SetLoopStatus(g_mqtt_client, true);
    do {
        if (!g_mqtt_task_running) {
            Log_w("MQTT Disconnect by user!");
            at_cmd_printf("+TCMQTTDISCON,%d\n", QCLOUD_RET_MQTT_MANUALLY_DISCONNECTED);
            set_wifi_led_state(LED_OFF);
            break;
        }

        rc = qcloud_iot_mqtt_yield(g_mqtt_client, 500);

        if (rc == QCLOUD_ERR_MQTT_ATTEMPTING_RECONNECT) {
            at_cmd_printf("+TCMQTTRECONNECTING\n");
            HAL_SleepMs(1000);
            continue;
        } else if (rc == QCLOUD_RET_MQTT_MANUALLY_DISCONNECTED || rc == QCLOUD_ERR_MQTT_NO_CONN ||
                   rc == QCLOUD_ERR_MQTT_RECONNECT_TIMEOUT) {
            // wait for OTA finished
            if (is_fw_downloading()) {
                Log_w("qcloud_iot_mqtt_yield error: %d but OTA is going on!", rc);
                HAL_SleepMs(1000);
                continue;
            }

            Log_e("task exit with error: %d", rc);
            at_cmd_printf("+TCMQTTDISCON,%d\n", rc);
            break;
        } else if (rc != QCLOUD_RET_SUCCESS && rc != QCLOUD_RET_MQTT_RECONNECTED) {
            Log_e("IOT_MQTT_Yield return with error: %d", rc);
        }

        HAL_SleepMs(200);

    } while (g_mqtt_client != NULL);

end_of_task:

    if (g_mqtt_client != NULL) {
        do_fw_ota_update(false, NULL);
        if (sg_gw_client) {
            IOT_Gateway_Destroy(sg_gw_client);
            sg_gw_client = NULL;
        }
        IOT_MQTT_Destroy(&g_mqtt_client);
        g_mqtt_client = NULL;
    }

    g_mqtt_task_running = false;
    Log_w("task going to be deleted");

#ifdef CONFIG_FREERTOS_USE_TRACE_FACILITY
    vTaskGetInfo(NULL, &task_status, pdTRUE, eRunning);
    Log_i(">>>>> task %s stack left: %u, free heap: %u", task_status.pcTaskName, task_status.usStackHighWaterMark,
          esp_get_free_heap_size());
#endif

    vTaskDelete(NULL);

    return;
}

int do_mqtt_connect(MQTTInitParams *mqtt_conn_param)
{
    int ret;

    if (g_mqtt_client != NULL) {
        Log_w("MQTT connected already!");
        return eSTATE_ERR;
    }

    if (mqtt_conn_param == NULL) {
        Log_e("mqtt_conn_param is null!");
        return ePARA_ERR;
    }

    g_mqtt_task_running = true;

    ret = xTaskCreate(_mqtt_client_task, MQTT_CLIENT_TASK_NAME, MQTT_CLIENT_TASK_STACK_BYTES, mqtt_conn_param,
                      MQTT_CLIENT_TASK_PRIO, &g_mqtt_task);
    if (ret != pdPASS) {
        Log_e("mqtt create mqtt client task failed: %s", ret);
        g_mqtt_task_running = false;
        return eEXEC_ERR;
    }

    g_cmd_processing = true;
    Timer timer;
    InitTimer(&timer);
    countdown_ms(&timer, mqtt_conn_param->command_timeout);

    do {
        if (g_cmd_processing == false)
            return g_ret_code;

        HAL_SleepMs(200);

    } while (!expired(&timer));

    return eTIME_OUT_ERR;
}

int do_mqtt_disconnect()
{
    if (g_mqtt_client == NULL) {
        Log_w("MQTT NOT connected yet!");
        return eSTATE_ERR;
    }

    g_mqtt_task_running = false;
    Timer timer;
    InitTimer(&timer);
    countdown_ms(&timer, g_init_params.command_timeout);

    do {
        if (g_mqtt_client == NULL)
            return 0;

        HAL_SleepMs(200);

    } while (!expired(&timer));

    return eTIME_OUT_ERR;
}

int do_mqtt_pub_msg(char *topic_name, int QoS, char *topic_payload, size_t payload_len)
{
    if (g_mqtt_client == NULL) {
        Log_e("MQTT NOT connected yet!");
        return eSTATE_ERR;
    }

    PublishParams pub_params = DEFAULT_PUB_PARAMS;
    pub_params.qos           = QoS;
    pub_params.payload       = topic_payload;
    pub_params.payload_len   = payload_len;

    int rc = IOT_MQTT_Publish(g_mqtt_client, topic_name, &pub_params);
    if (rc < 0) {
        Log_e("MQTT publish failed %d", rc);
        return rc;
    }

    if (QoS == QOS0)
        return 0;

    /* wait for puback */
    g_cmd_processing = true;
    Timer timer;
    InitTimer(&timer);
    countdown_ms(&timer, g_init_params.command_timeout);

    do {
        if (g_cmd_processing == false)
            return g_ret_code;

        HAL_SleepMs(200);

    } while (!expired(&timer));

    return eTIME_OUT_ERR;
}

int do_mqtt_sub_msg(char *topic_name, int QoS)
{
    if (g_mqtt_client == NULL) {
        Log_e("MQTT NOT connected yet!");
        return eSTATE_ERR;
    }

    SubscribeParams sub_params    = DEFAULT_SUB_PARAMS;
    sub_params.on_message_handler = _on_message_callback;
    sub_params.qos                = QoS;

    int rc = IOT_MQTT_Subscribe(g_mqtt_client, topic_name, &sub_params);
    if (rc < 0) {
        Log_e("MQTT subscribe failed %d", rc);
        return rc;
    }

    /* wait for suback */
    g_cmd_processing = true;
    Timer timer;
    InitTimer(&timer);
    countdown_ms(&timer, g_init_params.command_timeout);

    do {
        if (g_cmd_processing == false)
            return g_ret_code;

        HAL_SleepMs(200);

    } while (!expired(&timer));

    return eTIME_OUT_ERR;
}

int do_mqtt_unsub_msg(char *topic_name)
{
    if (g_mqtt_client == NULL) {
        Log_e("MQTT NOT connected yet!");
        return eSTATE_ERR;
    }

    int rc = IOT_MQTT_Unsubscribe(g_mqtt_client, topic_name);
    if (rc < 0) {
        Log_e("MQTT unsubscribe failed %d", rc);
        return rc;
    }

    /* wait for unsuback */
    g_cmd_processing = true;
    Timer timer;
    InitTimer(&timer);
    countdown_ms(&timer, g_init_params.command_timeout);

    do {
        if (g_cmd_processing == false)
            return g_ret_code;

        HAL_SleepMs(200);

    } while (!expired(&timer));

    return eTIME_OUT_ERR;
}

int get_mqtt_conn_parameters(MQTTInitParams *mqtt_conn_param)
{
    if (mqtt_conn_param == NULL) {
        Log_e("Null pointer");
        return ePARA_ERR;
    }

    memcpy(mqtt_conn_param, &g_init_params, sizeof(MQTTInitParams));

    return 0;
}

int get_mqtt_sub_list()
{
    if (g_mqtt_client == NULL) {
        Log_e("MQTT NOT connected yet!");
        return eSTATE_ERR;
    }

    Qcloud_IoT_Client *pClient = (Qcloud_IoT_Client *)g_mqtt_client;
    char *             topic   = NULL;
    int                i;
    for (i = 0; i < MAX_MESSAGE_HANDLERS; i++) {
        topic = (char *)pClient->sub_handles[i].topic_filter;
        if (topic == NULL) {
            continue;
        }
        at_cmd_printf("+TCMQTTSUB:\"%s\",%d\n", topic, pClient->sub_handles[i].qos);
    }

    return 0;
}

int get_mqtt_connect_state()
{
    if (g_mqtt_client == NULL) {
        return 0;
    }

    if (IOT_MQTT_IsConnected(g_mqtt_client))
        return 1;

    return 0;
}

bool is_mqtt_task_running()
{
    return g_mqtt_task_running;
}

void *get_mqtt_client()
{
    return g_mqtt_client;
}

static bool g_reg_task_done = false;
static int  g_reg_task_ret  = QCLOUD_RET_SUCCESS;

static void https_client_task(void *pvParameters)
{
    DeviceInfo *pDevInfo = (DeviceInfo *)pvParameters;

    g_reg_task_ret = IOT_DynReg_Device(pDevInfo);

    g_reg_task_done = true;

    vTaskDelete(NULL);
}

int do_dyn_reg_dev(void *pDevInfo)
{
    g_reg_task_done = false;
    /* we need a seperate task as it requires HTTPS connection*/
    int ret = xTaskCreate(https_client_task, "https_client_task", 10240, pDevInfo, 5, NULL);
    if (ret != pdPASS) {
        Log_e("create tcp_client_task failed: %d", ret);
        return eEXEC_ERR;
    }

    Timer timer;
    InitTimer(&timer);
    countdown_ms(&timer, 10000);

    do {
        if (g_reg_task_done)
            return g_reg_task_ret;

        HAL_SleepMs(200);

    } while (!expired(&timer));

    return eTIME_OUT_ERR;
}

// for reply code, pls check https://cloud.tencent.com/document/product/634/45960
#define GATEWAY_RC_REPEAT_BIND 809

int do_gw_bind_subdev(int mode, char *product_id, char *device_name, char *device_secret)
{
    if (sg_gw_client == NULL) {
        sg_gw_client = IOT_Gateway_Construct(NULL, g_mqtt_client);
        if (sg_gw_client == NULL) {
            Log_e("IOT_Gateway_Construct failed");
            return QCLOUD_ERR_GATEWAY_CLIENT_INVALID;
        }
    }

    GatewayParam gw_param;
    DeviceInfo *dev = IOT_MQTT_GetDeviceInfo(g_mqtt_client);
    gw_param.product_id = dev->product_id;
    gw_param.device_name = dev->device_name;
    DeviceInfo sub_dev = {0};
    strncpy(sub_dev.product_id, product_id, MAX_SIZE_OF_PRODUCT_ID);
    strncpy(sub_dev.device_name, device_name, MAX_SIZE_OF_DEVICE_NAME);
    if (mode == 0)
        strncpy(sub_dev.device_secret, device_secret, MAX_SIZE_OF_DEVICE_SECRET);

    int rc;    

    if (mode == 0) {
        // do this outside to avoid stack overflow
        long timestamp;
        rc = IOT_Get_SysTime(g_mqtt_client, &timestamp);
        if (QCLOUD_RET_SUCCESS != rc) {
            Log_e("get system time fail: %d", rc);
            return QCLOUD_ERR_FAILURE;
        }
        rc = IOT_Gateway_Subdev_Bind(sg_gw_client, &gw_param, &sub_dev, timestamp);

        // consider repeat bind as success
        if (rc == GATEWAY_RC_REPEAT_BIND)
            rc = QCLOUD_RET_SUCCESS;
    } else {
        rc = IOT_Gateway_Subdev_Unbind(sg_gw_client, &gw_param, &sub_dev);
    }

    return rc;
}

int do_gw_online_subdev(int mode, char *product_id, char *device_name)
{
    if (sg_gw_client == NULL) {
        sg_gw_client = IOT_Gateway_Construct(NULL, g_mqtt_client);
        if (sg_gw_client == NULL) {
            Log_e("IOT_Gateway_Construct failed");
            return -1;
        }
    }

    GatewayParam gw_param;
    DeviceInfo *dev = IOT_MQTT_GetDeviceInfo(g_mqtt_client);
    gw_param.product_id = dev->product_id;
    gw_param.device_name = dev->device_name;
    gw_param.subdev_product_id = product_id;
    gw_param.subdev_device_name = device_name;
    int rc;
    if (mode == 0)
        rc = IOT_Gateway_Subdev_Online(sg_gw_client, &gw_param);
    else
        rc = IOT_Gateway_Subdev_Offline(sg_gw_client, &gw_param);

    return rc;
}

int get_online_subdev_list(void)
{
    if (sg_gw_client == NULL) {
        return 0;
    }

    Gateway *gw = (Gateway *)sg_gw_client;
    SubdevSession *session = gw->session_list;

    /* session is exist */
    while (session) {
        if (session->session_status == SUBDEV_SEESION_STATUS_ONLINE) {
            at_cmd_printf("+TCGWONLINE:\"%s,%s\"\n", session->product_id, session->device_name);
        }
        session = session->next;
    }

    return 0;
}
