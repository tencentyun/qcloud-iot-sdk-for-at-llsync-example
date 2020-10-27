/*
 * Copyright (c) 2020 Tencent Cloud. All rights reserved.

 * Licensed under the MIT License (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://opensource.org/licenses/MIT

 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <string.h>
#include <time.h>
#include <unistd.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "cJSON.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/apps/sntp.h"

#include "qcloud_iot_export.h"
#include "qcloud_iot_import.h"
#include "utils_hmac.h"
#include "utils_base64.h"

#include "wifi_config_internal.h"
#include "qcloud_at_cmd.h"
#include "qcloud_at_wifi.h"
#include "qcloud_at_mqtt.h"
#include "qcloud_at_board.h"
#include "qcloud_at_flash.h"

/* task control flags and counters */
static bool sg_mqtt_task_run = false;
static bool sg_comm_task_run = false;
static bool sg_log_task_run  = false;

static int sg_mqtt_task_cnt = 0;
static int sg_comm_task_cnt = 0;
static int sg_log_task_cnt  = 0;

/* wifi config state flag */
static bool sg_wifi_config_success = false;
static bool sg_token_received      = false;

//============================ MQTT communication functions begin ===========================//

#define MAX_TOKEN_LENGTH 32
static char sg_token_str[MAX_TOKEN_LENGTH + 1] = {0};
static char sg_region_str[MAX_SIZE_OF_PRODUCT_REGION + 1] = {"ap-guangzhou"};
static DeviceInfo sg_device_info = {0};

typedef struct TokenHandleData {
    bool sub_ready;
    bool send_ready;
    int  reply_code;
} TokenHandleData;

static int _load_device_info(DeviceInfo *dev_info)
{
    sDevInfo devinfo;
    devinfo.magic_header = 0xfeedbeef;
    int ret              = load_dev_info(__FILE__, &devinfo);
    if (ret) {
        Log_e("Load device info from flash error");

        sPrdInfo prdinfo;
        prdinfo.magic_header = 0xfeedbeef;
        ret = load_prd_info(__FILE__, &prdinfo);
        if ( ret ) {
            Log_e("load prd info from flash err");
            PUSH_LOG("get device info error");            
            return ret;
        }

        memset(dev_info, 0, sizeof(devinfo));
        strncpy(dev_info->product_id, (char *)prdinfo.product_id, MAX_SIZE_OF_PRODUCT_ID);
        strncpy(dev_info->device_name, (char *)prdinfo.device_name, MAX_SIZE_OF_DEVICE_NAME);
        strncpy(dev_info->product_secret, (char *)prdinfo.product_secret, MAX_SIZE_OF_PRODUCT_SECRET);
        strncpy(dev_info->product_region, (char *)prdinfo.product_region, MAX_SIZE_OF_PRODUCT_REGION);
    } else {
        memset(dev_info, 0, sizeof(devinfo));
        strncpy(dev_info->product_id, (char *)devinfo.product_id, MAX_SIZE_OF_PRODUCT_ID);
        strncpy(dev_info->device_name, (char *)devinfo.device_name, MAX_SIZE_OF_DEVICE_NAME);
        strncpy(dev_info->device_secret, (char *)devinfo.device_secret, MAX_SIZE_OF_DEVICE_SECRET);
        strncpy(dev_info->product_region, (char *)devinfo.product_region, MAX_SIZE_OF_PRODUCT_REGION);
    }

    return 0;
}

static void _mqtt_event_handler(void *pclient, void *handle_context, MQTTEventMsg *msg)
{
    MQTTMessage *    mqtt_messge = (MQTTMessage *)msg->msg;
    uintptr_t        packet_id   = (uintptr_t)msg->msg;
    TokenHandleData *app_data    = (TokenHandleData *)handle_context;

    switch (msg->event_type) {
        case MQTT_EVENT_DISCONNECT:
            Log_w("MQTT disconnect");
            PUSH_LOG("MQTT disconnect");
            break;

        case MQTT_EVENT_RECONNECT:
            Log_i("MQTT reconnected");
            PUSH_LOG("MQTT reconnected");
            break;

        case MQTT_EVENT_PUBLISH_RECVEIVED:
            Log_i("unhandled msg arrived: topic=%s", mqtt_messge->ptopic);
            break;

        case MQTT_EVENT_SUBCRIBE_SUCCESS:
            Log_d("mqtt topic subscribe success");
            app_data->sub_ready = true;
            break;

        case MQTT_EVENT_SUBCRIBE_TIMEOUT:
            Log_i("mqtt topic subscribe timeout");
            app_data->sub_ready = false;
            break;

        case MQTT_EVENT_SUBCRIBE_NACK:
            Log_i("mqtt topic subscribe NACK");
            app_data->sub_ready = false;
            break;

        case MQTT_EVENT_PUBLISH_SUCCESS:
            Log_i("publish success, packet-id=%u", (unsigned int)packet_id);
            app_data->send_ready = true;
            break;

        case MQTT_EVENT_PUBLISH_TIMEOUT:
            Log_i("publish timeout, packet-id=%u", (unsigned int)packet_id);
            app_data->send_ready = false;
            break;

        case MQTT_EVENT_PUBLISH_NACK:
            Log_i("publish nack, packet-id=%u", (unsigned int)packet_id);
            app_data->send_ready = false;
            break;

        default:
            Log_i("unknown event type: %d", msg->event_type);
            break;
    }
}

// callback when MQTT msg arrives
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

    Log_i("recv msg topic: %s", message->ptopic);

    uint32_t msg_topic_len = message->payload_len + 4;
    char *   buf           = (char *)HAL_Malloc(msg_topic_len);
    if (buf == NULL) {
        Log_e("malloc %u bytes failed", msg_topic_len);
        return;
    }

    memset(buf, 0, msg_topic_len);
    memcpy(buf, message->payload, message->payload_len);
    Log_i("msg payload: %s", buf);

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        Log_e("Parsing JSON Error");
        push_error_log(ERR_TOKEN_REPLY, ERR_APP_CMD_JSON_FORMAT);
    } else {
        cJSON *code_json = cJSON_GetObjectItem(root, "code");
        if (code_json) {
            TokenHandleData *app_data = (TokenHandleData *)userData;
            app_data->reply_code      = code_json->valueint;
            Log_d("token reply code = %d", code_json->valueint);

            if (app_data->reply_code) {
                Log_e("token reply error: %d", code_json->valueint);
                PUSH_LOG("token reply error: %d", code_json->valueint);
                push_error_log(ERR_TOKEN_REPLY, app_data->reply_code);
            }
        } else {
            Log_e("Parsing reply code Error");
            push_error_log(ERR_TOKEN_REPLY, ERR_APP_CMD_JSON_FORMAT);
        }

        cJSON_Delete(root);
    }

    HAL_Free(buf);
}

// subscrib MQTT topic
static int _subscribe_topic_wait_result(void *client, DeviceInfo *dev_info, TokenHandleData *app_data)
{
    char topic_name[128] = {0};
    // int size = HAL_Snprintf(topic_name, sizeof(topic_name), "%s/%s/data", dev_info->product_id,
    // dev_info->device_name);
    int size = HAL_Snprintf(topic_name, sizeof(topic_name), "$thing/down/service/%s/%s", dev_info->product_id,
                            dev_info->device_name);
    if (size < 0 || size > sizeof(topic_name) - 1) {
        Log_e("topic content length not enough! content size:%d  buf size:%d", size, (int)sizeof(topic_name));
        return QCLOUD_ERR_FAILURE;
    }
    SubscribeParams sub_params    = DEFAULT_SUB_PARAMS;
    sub_params.qos                = QOS0;
    sub_params.on_message_handler = _on_message_callback;
    sub_params.user_data          = (void *)app_data;
    int rc                        = IOT_MQTT_Subscribe(client, topic_name, &sub_params);
    if (rc < 0) {
        Log_e("MQTT subscribe failed: %d", rc);
        return rc;
    }

    int wait_cnt = 2;
    while (!app_data->sub_ready && (wait_cnt-- > 0)) {
        // wait for subscription result
        rc = IOT_MQTT_Yield(client, 1000);
        if (rc) {
            Log_e("MQTT error: %d", rc);
            return rc;
        }
    }

    if (wait_cnt > 0) {
        return QCLOUD_RET_SUCCESS;
    } else {
        Log_w("wait for subscribe result timeout!");
        return QCLOUD_ERR_FAILURE;
    }
}

// publish MQTT msg
static int _publish_token_msg(void *client, DeviceInfo *dev_info, char *token_str)
{
    char topic_name[128] = {0};
    // int size = HAL_Snprintf(topic_name, sizeof(topic_name), "%s/%s/data", dev_info->product_id,
    // dev_info->device_name);
    int size = HAL_Snprintf(topic_name, sizeof(topic_name), "$thing/up/service/%s/%s", dev_info->product_id,
                            dev_info->device_name);
    if (size < 0 || size > sizeof(topic_name) - 1) {
        Log_e("topic content length not enough! content size:%d  buf size:%d", size, (int)sizeof(topic_name));
        return QCLOUD_ERR_FAILURE;
    }

    PublishParams pub_params = DEFAULT_PUB_PARAMS;
    pub_params.qos           = QOS1;

    char topic_content[256] = {0};
    size                    = HAL_Snprintf(topic_content, sizeof(topic_content),
                        "{\"method\":\"app_bind_token\",\"clientToken\":\"%s-%u\",\"params\": {\"token\":\"%s\"}}",
                        dev_info->device_name, HAL_GetTimeMs(), token_str);
    if (size < 0 || size > sizeof(topic_content) - 1) {
        Log_e("payload content length not enough! content size:%d  buf size:%d", size, (int)sizeof(topic_content));
        return QCLOUD_ERR_MALLOC;
    }

    pub_params.payload     = topic_content;
    pub_params.payload_len = strlen(topic_content);

    return IOT_MQTT_Publish(client, topic_name, &pub_params);
}

// send token data via mqtt publishing
static int _send_token_wait_reply(void *client, DeviceInfo *dev_info, TokenHandleData *app_data)
{
    int ret      = 0;
    int wait_cnt = 20;

    // for smartconfig, we need to wait for the token data from app
    while (!sg_token_received && (wait_cnt-- > 0)) {
        IOT_MQTT_Yield(client, 1000);
        Log_i("wait for token data...");
    }

    if (!sg_token_received) {
        Log_e("Wait for token data timeout");
        PUSH_LOG("Wait for token data timeout");
        return ERR_TOKEN_RECV;
    }

    // compare region of user and region of product
    if (strncmp(dev_info->product_region, sg_region_str, MAX_SIZE_OF_PRODUCT_REGION)) {
        Log_e("Region fault: %s != %s", dev_info->product_region, sg_region_str);
        PUSH_LOG("Region fault: %s != %s", dev_info->product_region, sg_region_str);
        return ERR_REGION_FAULT;
    }

    wait_cnt = 3;
publish_token:
    ret = _publish_token_msg(client, dev_info, sg_token_str);
    if (ret < 0 && (wait_cnt-- > 0)) {
        Log_e("Client publish token failed: %d", ret);
        if (is_wifi_sta_connected() && IOT_MQTT_IsConnected(client)) {
            IOT_MQTT_Yield(client, 500);
        } else {
            Log_e("Wifi or MQTT lost connection! Wait and retry!");
            IOT_MQTT_Yield(client, 2000);
        }
        goto publish_token;
    }

    if (ret < 0) {
        Log_e("pub token failed: %d", ret);
        PUSH_LOG("pub token failed: %d", ret);
        return ret;
    }

    wait_cnt = 5;
    while (!app_data->send_ready && (wait_cnt-- > 0)) {
        IOT_MQTT_Yield(client, 1000);
        Log_i("wait for token sending result...");
    }

    ret = 0;
    if (!app_data->send_ready) {
        Log_e("pub token timeout");
        PUSH_LOG("pub token timeout");
        ret = QCLOUD_ERR_MQTT_UNKNOWN;
    }

    return ret;
}

// get the device info or do device dynamic register
static int _get_reg_dev_info(DeviceInfo *dev_info)
{
    if (strlen(dev_info->product_id) == 0 || 
            strlen(dev_info->device_name) == 0) {
        return -1;    
    }

    if (strlen(dev_info->device_secret) == 0 && 
            strlen(dev_info->product_secret) != 0) {

        int ret = IOT_DynReg_Device(dev_info);
        if (ret) {
            Log_e("dynamic register device failed: %d", ret);
            PUSH_LOG("dynamic register device failed: %d", ret);
            return ret;
        }

        sDevInfo devinfo = {0};
        devinfo.TLS_mode = 1;
        strncpy(devinfo.product_id, dev_info->product_id, MAX_SIZE_OF_PRODUCT_ID);
        strncpy(devinfo.device_name, dev_info->device_name, MAX_SIZE_OF_DEVICE_NAME);
        strncpy(devinfo.device_secret, dev_info->device_secret, MAX_SIZE_OF_DEVICE_SECRET);
        strncpy(devinfo.product_region, (char *)dev_info->product_region, MAX_SIZE_OF_PRODUCT_REGION);

        devinfo.magic_header = VALID_MAGIC_CODE;
        if (save_dev_info(&devinfo)) {
            Log_e("save dev info failed");
            PUSH_LOG("save dev info failed");
            return eFLASH_ERR;
        } else {
            Log_i("save dev info success");

            // delay a while
            HAL_SleepMs(500);
        }

    }

    return QCLOUD_RET_SUCCESS;
}

// setup mqtt connection and return client handle
static void *_setup_mqtt_connect(DeviceInfo *dev_info, TokenHandleData *app_data)
{
    MQTTInitParams init_params       = DEFAULT_MQTTINIT_PARAMS;
    init_params.device_name          = dev_info->device_name;
    init_params.product_id           = dev_info->product_id;
    init_params.device_secret        = dev_info->device_secret;
    init_params.product_region       = dev_info->product_region;
    init_params.event_handle.h_fp    = _mqtt_event_handler;
    init_params.event_handle.context = (void *)app_data;
    init_params.mqtt_test_server_ip  = get_mqtt_test_server_ip();

    void *client = IOT_MQTT_Construct(&init_params);
    if (client != NULL) {
        return client;
    }

    // construct failed, give it another try
    if (is_wifi_sta_connected()) {
        Log_e("Cloud Device Construct Failed: %d! Try one more time!", IOT_MQTT_GetErrCode());
        HAL_SleepMs(1000);
    } else {
        Log_e("Wifi lost connection! Wait and retry!");
        HAL_SleepMs(2000);
    }

    client = IOT_MQTT_Construct(&init_params);
    if (client != NULL) {
        return client;
    }

    return NULL;
}

int mqtt_send_token(void)
{
    // get the device info or do device dynamic register
    DeviceInfo *dev_info = &sg_device_info;
    int        ret = _get_reg_dev_info(dev_info);
    if (ret) {
        Log_e("Get device info failed: %d", ret);
        PUSH_LOG("Get device info failed: %d", ret);
        push_error_log(ERR_DEVICE_INFO, ret);
        return ret;
    }

    // token handle data
    TokenHandleData app_data;
    app_data.sub_ready  = false;
    app_data.send_ready = false;
    app_data.reply_code = 404;

    // mqtt connection
    void *client = _setup_mqtt_connect(dev_info, &app_data);
    if (client == NULL) {
        ret = IOT_MQTT_GetErrCode();
        Log_e("Device %s/%s connect failed: %d", dev_info->product_id, dev_info->device_name, ret);
        PUSH_LOG("Device %s/%s connect failed: %d", dev_info->product_id, dev_info->device_name, ret);
        push_error_log(ERR_MQTT_CONNECT, ret);
        return ret;
    } else {
        Log_i("Device %s/%s connect success", dev_info->product_id, dev_info->device_name, ret);
        PUSH_LOG("Device %s/%s connect success", dev_info->product_id, dev_info->device_name, ret);
    }

    // subscribe token reply topic
    ret = _subscribe_topic_wait_result(client, dev_info, &app_data);
    if (ret < 0) {
        Log_w("Subscribe topic failed: %d", ret);
        PUSH_LOG("Subscribe topic failed: %d", ret);
    }

    // publish token msg and wait for reply
    int retry_cnt = 2;
    do {
        ret = _send_token_wait_reply(client, dev_info, &app_data);

        IOT_MQTT_Yield(client, 1000);
    } while (ret && ret != ERR_REGION_FAULT && retry_cnt-- && sg_mqtt_task_run);

    if (ret) {
        switch (ret) {
            case ERR_TOKEN_RECV:
            case ERR_REGION_FAULT:
                push_error_log(ret, QCLOUD_ERR_INVAL);
                break;
            default:
                push_error_log(ERR_TOKEN_SEND, ret);
                break;
        }
    }

    IOT_MQTT_Destroy(&client);

    // sleep 5 seconds to avoid frequent MQTT connection
    if (ret == 0)
        HAL_SleepMs(5000);

    return ret;
}
//============================ MQTT communication functions end ===========================//

//============================ Qcloud app TCP/UDP functions begin ===========================//

/* reply data to app/mini program
 * return -1, error and can not proceed
 * return 1,  error but can proceed
 * return 0,  everything all right
 */
static int app_reply_dev_info(comm_peer_t *peer)
{
    int ret;
    cJSON *reply_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(reply_json, "cmdType", (int)CMD_DEVICE_REPLY);
    cJSON_AddStringToObject(reply_json, "productId", sg_device_info.product_id);
    cJSON_AddStringToObject(reply_json, "deviceName", sg_device_info.device_name);
    cJSON_AddStringToObject(reply_json, "productRegion", sg_device_info.product_region);
    cJSON_AddStringToObject(reply_json, "protoVersion", WIFI_CONFIG_PROTO_VERSION);

    char json_str[256] = {0};
    if (0 == cJSON_PrintPreallocated(reply_json, json_str, sizeof(json_str), 0)) {
        cJSON_Delete(reply_json);
        Log_e("cJSON_PrintPreallocated failed!");
        PUSH_LOG("cJSON_PrintPreallocated failed!");
        push_error_log(ERR_APP_CMD, ERR_JSON_PRINT);
        return 1;
    }
    /* append msg delimiter */
    strcat(json_str, "\r\n");
    cJSON_Delete(reply_json);

    int udp_resend_cnt = 3;
udp_resend:
    ret = sendto(peer->socket_id, json_str, strlen(json_str), 0, peer->socket_addr, peer->addr_len);
    if (ret < 0) {
        Log_e("send error: %s", strerror(errno));
        PUSH_LOG("send error: %s", strerror(errno));
        push_error_log(ERR_SOCKET_SEND, errno);
        return 1;
    }
    /* UDP packet could be lost, send it again */
    /* NOT necessary for TCP */
    if (peer->socket_addr != NULL && --udp_resend_cnt) {
        HAL_SleepMs(1000);
        goto udp_resend;
    }

    HAL_Printf("Report dev info: %s", json_str);
    return 0;
}

static int app_handle_recv_data(comm_peer_t *peer, char *pdata, int len)
{
    int    ret;
    cJSON *root = cJSON_Parse(pdata);
    if (!root) {
        Log_e("JSON Err: %s", cJSON_GetErrorPtr());
        PUSH_LOG("JSON Err: %s", cJSON_GetErrorPtr());
        app_send_error_log(peer, CUR_ERR, ERR_APP_CMD, ERR_APP_CMD_JSON_FORMAT);
        return -1;
    }

    cJSON *cmd_json = cJSON_GetObjectItem(root, "cmdType");
    if (cmd_json == NULL) {
        Log_e("Invalid cmd JSON: %s", pdata);
        PUSH_LOG("Invalid cmd JSON: %s", pdata);
        cJSON_Delete(root);
        app_send_error_log(peer, CUR_ERR, ERR_APP_CMD, ERR_APP_CMD_JSON_FORMAT);
        return -1;
    }

    cJSON *region_json = cJSON_GetObjectItem(root, "region");
    if (region_json) {
        memset(sg_region_str, 0, sizeof(sg_region_str));
        strncpy(sg_region_str, region_json->valuestring, MAX_SIZE_OF_PRODUCT_REGION);
    }

    int cmd = cmd_json->valueint;
    switch (cmd) {
        /* Token only for smartconfig  */
        case CMD_TOKEN_ONLY: {
            cJSON *token_json = cJSON_GetObjectItem(root, "token");

            if (token_json) {
                memset(sg_token_str, 0, sizeof(sg_token_str));
                strncpy(sg_token_str, token_json->valuestring, MAX_TOKEN_LENGTH);
                sg_token_received = true;
                cJSON_Delete(root);

                app_reply_dev_info(peer);

                /* 1: Everything OK and we've finished the job */
                return 1;
            } else {
                cJSON_Delete(root);
                Log_e("invlaid token: %s", pdata);
                PUSH_LOG("invlaid token: %s", pdata);
                app_send_error_log(peer, CUR_ERR, ERR_APP_CMD, ERR_APP_CMD_AP_INFO);
                return -1;
            }
        } break;

        /* SSID/PW/TOKEN for softAP */
        case CMD_SSID_PW_TOKEN: {
            cJSON *ssid_json  = cJSON_GetObjectItem(root, "ssid");
            cJSON *psw_json   = cJSON_GetObjectItem(root, "password");
            cJSON *token_json = cJSON_GetObjectItem(root, "token");

            if (ssid_json && psw_json && token_json) {
                memset(sg_token_str, 0, sizeof(sg_token_str));
                strncpy(sg_token_str, token_json->valuestring, MAX_TOKEN_LENGTH);
                sg_token_received = true;

                app_reply_dev_info(peer);

                // sleep a while before changing to STA mode
                HAL_SleepMs(1000);

                Log_i("STA to connect SSID:%s PASSWORD:%s", ssid_json->valuestring, psw_json->valuestring);
                PUSH_LOG("SSID:%s|PSW:%s|TOKEN:%s", ssid_json->valuestring, psw_json->valuestring,
                         token_json->valuestring);
                ret = wifi_sta_connect(ssid_json->valuestring, psw_json->valuestring);
                if (ret) {
                    Log_e("wifi_sta_connect failed: %d", ret);
                    PUSH_LOG("wifi_sta_connect failed: %d", ret);
                    push_error_log(ERR_WIFI_AP_STA, ret);
                    cJSON_Delete(root);
                    return -1;
                }
                cJSON_Delete(root);

                /* return 1 as device alreay switch to STA mode and unable to recv cmd anymore
                 * 1: Everything OK and we've finished the job */
                return 1;
            } else {
                cJSON_Delete(root);
                Log_e("invlaid ssid/password/token!");
                PUSH_LOG("invlaid ssid/password/token!");
                app_send_error_log(peer, CUR_ERR, ERR_APP_CMD, ERR_APP_CMD_AP_INFO);
                return -1;
            }
        } break;

        case CMD_LOG_QUERY:
            ret = app_send_dev_log(peer);
            Log_i("app_send_dev_log ret: %d", ret);
            return 1;

        default: {
            cJSON_Delete(root);
            Log_e("invalid cmd: %s", pdata);
            PUSH_LOG("invalid cmd: %s", pdata);
            app_send_error_log(peer, CUR_ERR, ERR_APP_CMD, ERR_APP_CMD_JSON_FORMAT);
        } break;
    }

    return -1;
}

static void udp_server_task(void *pvParameters)
{
    int  ret, server_socket = -1;
    char addr_str[128] = {0};
    sg_comm_task_cnt++;

    /* stay longer than 5 minutes to handle error log */
    uint32_t server_count = WAIT_CNT_5MIN_SECONDS / SELECT_WAIT_TIME_SECONDS + 5;

    struct sockaddr_in server_addr;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(APP_SERVER_PORT);
    inet_ntoa_r(server_addr.sin_addr, addr_str, sizeof(addr_str) - 1);

    server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (server_socket < 0) {
        Log_e("socket failed: errno %d", errno);
        PUSH_LOG("socket failed: errno %d", errno);
        push_error_log(ERR_SOCKET_OPEN, errno);
        goto end_of_task;
    }

    ret = bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0) {
        Log_e("bind failed: errno %d", errno);
        PUSH_LOG("bind failed: errno %d", errno);
        push_error_log(ERR_SOCKET_BIND, errno);
        goto end_of_task;
    }

    Log_i("UDP server socket listening...");
    fd_set      sets;
    comm_peer_t peer_client = {
        .socket_id   = server_socket,
        .socket_addr = NULL,
        .addr_len    = 0,
    };

    int select_err_cnt = 0;
    int recv_err_cnt   = 0;
    while (sg_comm_task_run && --server_count) {
        FD_ZERO(&sets);
        FD_SET(server_socket, &sets);
        struct timeval timeout;
        timeout.tv_sec  = SELECT_WAIT_TIME_SECONDS;
        timeout.tv_usec = 0;

        int ret = select(server_socket + 1, &sets, NULL, NULL, &timeout);
        if (ret > 0) {
            select_err_cnt = 0;
            struct sockaddr_in source_addr;
            uint               addrLen        = sizeof(source_addr);
            char               rx_buffer[256] = {0};

            int len = recvfrom(server_socket, rx_buffer, sizeof(rx_buffer) - 1, MSG_DONTWAIT,
                               (struct sockaddr *)&source_addr, &addrLen);

            // Error occured during receiving
            if (len < 0) {
                recv_err_cnt++;
                Log_w("recvfrom error: %d, cnt: %d", errno, recv_err_cnt);
                if (recv_err_cnt > 3) {
                    Log_e("recvfrom error: %d, cnt: %d", errno, recv_err_cnt);
                    PUSH_LOG("recvfrom error: %d, cnt: %d", errno, recv_err_cnt);
                    push_error_log(ERR_SOCKET_RECV, errno);
                    break;
                }
                continue;
            }
            // Connection closed
            else if (len == 0) {
                recv_err_cnt = 0;
                Log_w("Connection is closed by peer");
                PUSH_LOG("Connection is closed by peer");
                continue;
            }
            // Data received
            else {
                recv_err_cnt = 0;
                // Get the sender's ip address as string
                inet_ntoa_r(((struct sockaddr_in *)&source_addr)->sin_addr.s_addr, addr_str, sizeof(addr_str) - 1);
                rx_buffer[len] = 0;
                Log_i("Received %d bytes from <%s:%u> msg: %s", len, addr_str, source_addr.sin_port, rx_buffer);
                PUSH_LOG("%s", rx_buffer);
                peer_client.socket_addr = (struct sockaddr *)&source_addr;
                peer_client.addr_len    = sizeof(source_addr);

                // send error log here, otherwise no chance for previous error
                get_and_post_error_log(&peer_client);

                ret = app_handle_recv_data(&peer_client, rx_buffer, len);
                if (ret == 1) {
                    Log_w("Finish app cmd handle");
                    PUSH_LOG("Finish app cmd handle");
                }
                break;

                // only one round of data recv/send
                //get_and_post_error_log(&peer_client);
                //continue;
            }
        } else if (0 == ret) {
            select_err_cnt = 0;
            Log_d("wait for read...");
            if (peer_client.socket_addr != NULL) {
                get_and_post_error_log(&peer_client);
            }
            continue;
        } else {
            select_err_cnt++;
            Log_w("select-recv error: %d, cnt: %d", errno, select_err_cnt);
            if (select_err_cnt > 3) {
                Log_e("select-recv error: %d, cnt: %d", errno, select_err_cnt);
                PUSH_LOG("select-recv error: %d, cnt: %d", errno, select_err_cnt);
                push_error_log(ERR_SOCKET_SELECT, errno);
                break;
            }
            HAL_SleepMs(500);
        }
    }

end_of_task:
    if (server_socket != -1) {
        Log_w("Shutting down UDP server socket");
        shutdown(server_socket, 0);
        close(server_socket);
    }

    sg_comm_task_run = false;
    Log_i("UDP server task quit");

#ifdef CONFIG_FREERTOS_USE_TRACE_FACILITY
    TaskStatus_t task_status;
    vTaskGetInfo(NULL, &task_status, pdTRUE, eRunning);
    Log_i(">>>>> task %s stack left: %u, free heap: %u", task_status.pcTaskName, task_status.usStackHighWaterMark,
          esp_get_free_heap_size());
#endif

    sg_comm_task_cnt--;
    vTaskDelete(NULL);
}

static void softAP_mqtt_task(void *pvParameters)
{
    uint8_t  led_state    = 0;
    uint32_t server_count = WIFI_CONFIG_WAIT_TIME_MS / SOFT_AP_BLINK_TIME_MS;
    sg_mqtt_task_cnt++;

    while (sg_mqtt_task_run && (--server_count)) {
        int state = wifi_wait_event(SOFT_AP_BLINK_TIME_MS);
        if (state == EVENT_WIFI_CONNECTED) {
            Log_d("WiFi Connected to ap");
            set_wifi_led_state(LED_ON);

            int ret = mqtt_send_token();
            if (ret) {
                at_cmd_printf("+TCSAP:WIFI_CONNECT_FAILED,%u,%d\n", ERR_MQTT_CONNECT, ret);
                Log_e("SoftAP: WIFI_MQTT_CONNECT_FAILED: %d", ret);
                PUSH_LOG("SoftAP: WIFI_MQTT_CONNECT_FAILED: %d", ret);
                set_wifi_led_state(LED_OFF);
            } else {
                Log_i("SoftAP: WIFI_MQTT_CONNECT_SUCCESS");
                PUSH_LOG("SoftAP: WIFI_MQTT_CONNECT_SUCCESS");
                set_wifi_led_state(LED_ON);
                sg_wifi_config_success = true;
                at_cmd_printf("+TCSAP:WIFI_CONNECT_SUCCESS\n");
            }

            break;
        } else if (state == EVENT_WIFI_DISCONNECTED) {
            // reduce the wait time as it meet disconnect
            server_count = WIFI_CONFIG_HALF_TIME_MS / SOFT_AP_BLINK_TIME_MS;
            Log_i("disconnect event! wait count change to %d", server_count);

        } else {
            led_state = (~led_state) & 0x01;
            set_wifi_led_state(led_state);
        }

        // check comm server task state
        if (!sg_comm_task_run && !sg_token_received) {
            Log_e("comm server task error!");
            PUSH_LOG("comm server task error");
            set_wifi_led_state(LED_OFF);
            at_cmd_printf("+TCSAP:WIFI_CONNECT_FAILED,%u,%d\n", ERR_OS_TASK, ERR_COMM_TASK_ERR);
            break;
        }
    }

    if (server_count == 0 && !sg_wifi_config_success) {
        Log_w("SoftAP: TIMEOUT");
        PUSH_LOG("SoftAP: TIMEOUT");
        push_error_log(ERR_BD_STOP, ERR_SC_EXEC_TIMEOUT);
        at_cmd_printf("+TCSAP:WIFI_CONNECT_FAILED,%u,%d\n", ERR_BD_STOP, ERR_SC_EXEC_TIMEOUT);
        set_wifi_led_state(LED_OFF);
    }

    wifi_stop_softap();
    save_error_log();

    sg_comm_task_run = false;
    sg_mqtt_task_run = false;
    Log_i("softAP mqtt task quit");

    if (!sg_wifi_config_success)
        start_log_softAP();

#ifdef CONFIG_FREERTOS_USE_TRACE_FACILITY
    TaskStatus_t task_status;
    vTaskGetInfo(NULL, &task_status, pdTRUE, eRunning);
    Log_i(">>>>> task %s stack left: %u, free heap: %u", task_status.pcTaskName, task_status.usStackHighWaterMark,
          esp_get_free_heap_size());
#endif

    sg_mqtt_task_cnt--;
    vTaskDelete(NULL);
}

int start_softAP(const char *ssid, const char *psw, uint8_t ch)
{
    sg_log_task_run = false;
    sg_mqtt_task_run = false;
    sg_comm_task_run = false;

    while (sg_comm_task_cnt > 0 || sg_mqtt_task_cnt > 0 || sg_log_task_cnt > 0) {
        Log_w("Wait for last config finish: %d %d %d", sg_comm_task_cnt, sg_mqtt_task_cnt, sg_log_task_cnt);
        sg_log_task_run = false;
        sg_mqtt_task_run = false;
        sg_comm_task_run = false;
        HAL_SleepMs(1000);
    }

    init_dev_log_queue();
    init_error_log_queue();
    Log_i("enter softAP mode");
    PUSH_LOG("start softAP: %s", ssid);

    sg_wifi_config_success = false;
    sg_token_received      = false;
    memset(sg_token_str, 0, sizeof(sg_token_str));

    int ret = _load_device_info(&sg_device_info);
    if (ret) {
        Log_e("load device info failed: %d", ret);
        PUSH_LOG("load device info failed: %d", ret);
        push_error_log(ERR_DEVICE_INFO, ret);
        ret = ERR_DEVICE_INFO;
        goto err_exit;
    }

    ret = wifi_ap_init(ssid, psw, ch);
    if (ret) {
        Log_e("wifi_ap_init failed: %d", ret);
        PUSH_LOG("wifi_ap_init failed: %d", ret);
        push_error_log(ERR_WIFI_AP_INIT, ret);
        ret = ERR_WIFI_AP_INIT;
        goto err_exit;
    }

    ret = wifi_start_running();
    if (ret) {
        Log_e("wifi_start_running failed: %d", ret);
        PUSH_LOG("wifi_start_running failed: %d", ret);
        push_error_log(ERR_WIFI_START, ret);
        ret = ERR_WIFI_START;
        goto err_exit;
    }

    sg_comm_task_run = true;
    ret = xTaskCreate(udp_server_task, COMM_SERVER_TASK_NAME, COMM_SERVER_TASK_STACK_BYTES, NULL, COMM_SERVER_TASK_PRIO,
                      NULL);
    if (ret != pdPASS) {
        Log_e("create comm_server_task failed: %d", ret);
        PUSH_LOG("create comm_server_task failed: %d", ret);
        push_error_log(ERR_OS_TASK, ret);
        ret = ERR_OS_TASK;
        goto err_exit;
    }

    sg_mqtt_task_run = true;
    ret = xTaskCreate(softAP_mqtt_task, SOFTAP_TASK_NAME, SOFTAP_TASK_STACK_BYTES, NULL, SOFTAP_TASK_PRIO, NULL);
    if (ret != pdPASS) {
        Log_e("create softAP_mqtt_task failed: %d", ret);
        PUSH_LOG("create softAP_mqtt_task failed: %d", ret);
        push_error_log(ERR_OS_TASK, ret);
        ret = ERR_OS_TASK;
        goto err_exit;
    }

    return 0;

err_exit:

    wifi_stop_softap();
    save_error_log();

    sg_mqtt_task_run = false;
    sg_comm_task_run = false;

    if (!sg_wifi_config_success) {
        HAL_SleepMs(SELECT_WAIT_TIME_SECONDS*1000);
        start_log_softAP();
    }

    return ret;
}

void stop_softAP(void)
{
    Log_w("Stop softAP");

    if (!sg_wifi_config_success) {
        push_error_log(ERR_BD_STOP, ERR_SC_AT_STOP);
        PUSH_LOG("softAP stopped by user!");
    }

    sg_mqtt_task_run = false;
    sg_comm_task_run = false;
    sg_log_task_run  = false;

    set_wifi_led_state(LED_OFF);
    wifi_stop_softap();
}

static void smartconfig_mqtt_task(void *parm)
{
    uint32_t wait_count = WIFI_CONFIG_WAIT_TIME_MS / SMART_CONFIG_BLINK_TIME_MS;
    uint8_t  led_state  = 0;
    int      ret;
    sg_mqtt_task_cnt++;

    while (sg_mqtt_task_run && (--wait_count)) {
        int state = wifi_wait_event(SMART_CONFIG_BLINK_TIME_MS);

        if (state == EVENT_WIFI_CONNECTED) {
            Log_d("WiFi Connected to AP");
            set_wifi_led_state(LED_ON);

            ret = mqtt_send_token();
            if (ret) {
                at_cmd_printf("+TCSTARTSMART:WIFI_CONNECT_FAILED,%u,%d\n", ERR_MQTT_CONNECT, ret);
                Log_e("SmartConfig: WIFI_MQTT_CONNECT_FAILED: %d", ret);
                PUSH_LOG("SmartConfig: WIFI_MQTT_CONNECT_FAILED: %d", ret);
                set_wifi_led_state(LED_OFF);
            } else {
                Log_i("SmartConfig: WIFI_MQTT_CONNECT_SUCCESS");
                PUSH_LOG("SmartConfig: WIFI_MQTT_CONNECT_SUCCESS");
                set_wifi_led_state(LED_ON);
                sg_wifi_config_success = true;
                at_cmd_printf("+TCSTARTSMART:WIFI_CONNECT_SUCCESS\n");
            }

            break;
        } else if (state == EVENT_SMARTCONFIG_STOP) {
            /* recv smartconfig stop event before connected */
            Log_w("smartconfig over");
            PUSH_LOG("smartconfig over");
            push_error_log(ERR_BD_STOP, ERR_SC_APP_STOP);
            set_wifi_led_state(LED_OFF);
            at_cmd_printf("+TCSTARTSMART:WIFI_CONNECT_FAILED,%u,%d\n", ERR_BD_STOP, ERR_SC_APP_STOP);
            break;
        } else if (state == EVENT_WIFI_DISCONNECTED) {
            // reduce the wait time as it meet disconnect
            wait_count = WIFI_CONFIG_HALF_TIME_MS / SMART_CONFIG_BLINK_TIME_MS;
            Log_i("disconnect event! wait count change to %d", wait_count);

        } else {
            led_state = (~led_state) & 0x01;
            set_wifi_led_state(led_state);
        }

        // check comm server task state
        if (!sg_comm_task_run && !sg_token_received) {
            Log_e("comm server task error!");
            PUSH_LOG("comm server task error");
            set_wifi_led_state(LED_OFF);
            at_cmd_printf("+TCSTARTSMART:WIFI_CONNECT_FAILED,%u,%d\n", ERR_OS_TASK, ERR_COMM_TASK_ERR);
            break;
        }
    }

    if (wait_count == 0 && !sg_wifi_config_success) {
        Log_w("SmartConfig: TIMEOUT");
        PUSH_LOG("SmartConfig: TIMEOUT");
        push_error_log(ERR_BD_STOP, ERR_SC_EXEC_TIMEOUT);
        at_cmd_printf("+TCSTARTSMART:WIFI_CONNECT_FAILED,%u,%d\n", ERR_BD_STOP, ERR_SC_EXEC_TIMEOUT);
        set_wifi_led_state(LED_OFF);
    }

    wifi_stop_smartconfig();
    save_error_log();

    sg_comm_task_run = false;
    sg_mqtt_task_run = false;
    Log_i("smartconfig task quit");

    if (!sg_wifi_config_success)
        start_log_softAP();

#ifdef CONFIG_FREERTOS_USE_TRACE_FACILITY
    TaskStatus_t task_status;
    vTaskGetInfo(NULL, &task_status, pdTRUE, eRunning);
    Log_i(">>>>> task %s stack left: %u, free heap: %u", task_status.pcTaskName, task_status.usStackHighWaterMark,
          esp_get_free_heap_size());
#endif

    sg_mqtt_task_cnt--;
    vTaskDelete(NULL);
}

int start_smartconfig(void)
{
    sg_log_task_run = false;
    sg_mqtt_task_run = false;
    sg_comm_task_run = false;

    while (sg_comm_task_cnt > 0 || sg_mqtt_task_cnt > 0 || sg_log_task_cnt > 0) {
        Log_w("Wait for last config finish: %d %d %d", sg_comm_task_cnt, sg_mqtt_task_cnt, sg_log_task_cnt);
        sg_log_task_run = false;
        sg_mqtt_task_run = false;
        sg_comm_task_run = false;
        HAL_SleepMs(1000);
    }

    init_dev_log_queue();
    init_error_log_queue();
    Log_d("Enter smartconfig");
    PUSH_LOG("Enter smartconfig");

    sg_wifi_config_success = false;
    sg_token_received      = false;
    memset(sg_token_str, 0, sizeof(sg_token_str));

    int ret = _load_device_info(&sg_device_info);
    if (ret) {
        Log_e("load device info failed: %d", ret);
        PUSH_LOG("load device info failed: %d", ret);
        push_error_log(ERR_DEVICE_INFO, ret);
        ret = ERR_DEVICE_INFO;
        goto err_exit;
    }

    ret = wifi_sta_init();
    if (ret) {
        Log_e("wifi_sta_init failed: %d", ret);
        PUSH_LOG("wifi_sta_init failed: %d", ret);
        push_error_log(ERR_WIFI_STA_INIT, ret);
        ret = ERR_WIFI_STA_INIT;
        goto err_exit;
    }

    ret = wifi_start_running();
    if (ret) {
        Log_e("wifi_start_running failed: %d", ret);
        PUSH_LOG("wifi_start_running failed: %d", ret);
        push_error_log(ERR_WIFI_START, ret);
        ret = ERR_WIFI_START;
        goto err_exit;
    }

    ret = wifi_start_smartconfig();
    if (ret) {
        Log_e("start smartconfig failed: %d", ret);
        PUSH_LOG("start smartconfig failed: %d", ret);
        push_error_log(ERR_SC_START, ret);
        ret = ERR_SC_START;
        goto err_exit;
    }

    sg_comm_task_run = true;
    ret = xTaskCreate(udp_server_task, COMM_SERVER_TASK_NAME, COMM_SERVER_TASK_STACK_BYTES, NULL, COMM_SERVER_TASK_PRIO,
                      NULL);
    if (ret != pdPASS) {
        Log_e("create udp_server_task failed: %d", ret);
        PUSH_LOG("create udp_server_task failed: %d", ret);
        push_error_log(ERR_OS_TASK, ret);
        ret = ERR_OS_TASK;
        goto err_exit;
    }

    sg_mqtt_task_run = true;
    ret              = xTaskCreate(smartconfig_mqtt_task, SMARTCONFIG_TASK_NAME, SMARTCONFIG_TASK_STACK_BYTES, NULL,
                      SMARTCONFIG_TASK_PRIO, NULL);
    if (ret != pdPASS) {
        Log_e("create smartconfig_mqtt_task failed: %d", ret);
        PUSH_LOG("create smartconfig_mqtt_task failed: %d", ret);
        push_error_log(ERR_OS_TASK, ret);
        ret = ERR_OS_TASK;
        goto err_exit;
    }

    return 0;

err_exit:

    save_error_log();
    sg_mqtt_task_run = false;
    sg_comm_task_run = false;

    if (!sg_wifi_config_success) {
        HAL_SleepMs(SELECT_WAIT_TIME_SECONDS*1000);
        start_log_softAP();
    }

    return ret;
}

void stop_smartconfig(void)
{
    Log_w("Stop smartconfig");

    if (!sg_wifi_config_success) {
        push_error_log(ERR_BD_STOP, ERR_SC_AT_STOP);
        PUSH_LOG("softAP stopped by user!");
    }

    sg_mqtt_task_run = false;
    sg_comm_task_run = false;
    sg_log_task_run  = false;

    wifi_stop_smartconfig();
    set_wifi_led_state(LED_OFF);
}

void setup_sntp(char *time_zone, char *ntp_server)
{
    sntp_setoperatingmode(SNTP_OPMODE_POLL);

    // for set more sntp server, plz modify macro SNTP_MAX_SERVERS in sntp_opts.h file
    // set sntp server after got ip address, you had better to adjust the sntp server to your area
    if (ntp_server) {
        sntp_setservername(0, ntp_server);
        sntp_setservername(1, "time1.cloud.tencent.com");
        sntp_setservername(2, "cn.pool.ntp.org");
        sntp_setservername(3, "time-a.nist.gov");
    } else {
        sntp_setservername(0, "time1.cloud.tencent.com");
        sntp_setservername(1, "cn.pool.ntp.org");
        sntp_setservername(2, "time-a.nist.gov");
        sntp_setservername(3, "cn.ntp.org.cn");
    }

    sntp_init();

    // wait for time to be set
    time_t    now         = 0;
    struct tm timeinfo    = {0};
    int       retry       = 0;
    const int retry_count = 10;

    while (timeinfo.tm_year < (2019 - 1900) && ++retry < retry_count) {
        Log_d("Waiting for system time to be set... (%d/%d)", retry, retry_count);
        sleep(1);
        time(&now);
        localtime_r(&now, &timeinfo);
    }

    // If not tell, set timezone to China Standard Time
    if (time_zone)
        setenv("TZ", time_zone, 1);
    else
        setenv("TZ", "CST-8", 1);
    tzset();
}

#ifdef WIFI_LOG_UPLOAD
static void log_server_task(void *pvParameters)
{
    int  ret, server_socket = -1;
    char addr_str[128] = {0};
    sg_log_task_cnt++;

    /* stay 6 minutes to handle log */
    uint32_t server_count = 360 / SELECT_WAIT_TIME_SECONDS;

    struct sockaddr_in server_addr;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(LOG_SERVER_PORT);
    inet_ntoa_r(server_addr.sin_addr, addr_str, sizeof(addr_str) - 1);

    server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (server_socket < 0) {
        Log_e("socket failed: errno %d", errno);
        goto end_of_task;
    }

    ret = bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0) {
        Log_e("bind failed: errno %d", errno);
        goto end_of_task;
    }

    Log_i("LOG server socket listening...");
    fd_set      sets;
    comm_peer_t peer_client = {
        .socket_id   = server_socket,
        .socket_addr = NULL,
        .addr_len    = 0,
    };

    int select_err_cnt = 0;
    int recv_err_cnt   = 0;
    while (sg_log_task_run && --server_count) {
        FD_ZERO(&sets);
        FD_SET(server_socket, &sets);
        struct timeval timeout;
        timeout.tv_sec  = SELECT_WAIT_TIME_SECONDS;
        timeout.tv_usec = 0;

        int ret = select(server_socket + 1, &sets, NULL, NULL, &timeout);
        if (ret > 0) {
            select_err_cnt = 0;
            struct sockaddr_in source_addr;
            uint               addrLen        = sizeof(source_addr);
            char               rx_buffer[256] = {0};

            int len = recvfrom(server_socket, rx_buffer, sizeof(rx_buffer) - 1, MSG_DONTWAIT,
                               (struct sockaddr *)&source_addr, &addrLen);

            // Error occured during receiving
            if (len < 0) {
                recv_err_cnt++;
                Log_w("recvfrom error: %d, cnt: %d", errno, recv_err_cnt);
                if (recv_err_cnt > 3) {
                    Log_e("recvfrom error: %d, cnt: %d", errno, recv_err_cnt);
                    break;
                }
                continue;
            }
            // Connection closed
            else if (len == 0) {
                recv_err_cnt = 0;
                Log_w("Connection is closed by peer");
                continue;
            }
            // Data received
            else {
                recv_err_cnt = 0;
                // Get the sender's ip address as string
                inet_ntoa_r(((struct sockaddr_in *)&source_addr)->sin_addr.s_addr, addr_str, sizeof(addr_str) - 1);
                rx_buffer[len] = 0;
                Log_i("Received %d bytes from <%s:%u> msg: %s", len, addr_str, source_addr.sin_port, rx_buffer);

                peer_client.socket_addr = (struct sockaddr *)&source_addr;
                peer_client.addr_len    = sizeof(source_addr);

                if (strncmp(rx_buffer, "{\"cmdType\":3}", 12) == 0) {
                    ret = app_send_dev_log(&peer_client);
                    Log_i("app_send_dev_log ret: %d", ret);
                    break;
                }

                continue;
            }
        } else if (0 == ret) {
            select_err_cnt = 0;
            Log_d("wait for read...");
            continue;
        } else {
            select_err_cnt++;
            Log_w("select-recv error: %d, cnt: %d", errno, select_err_cnt);
            if (select_err_cnt > 3) {
                Log_e("select-recv error: %d, cnt: %d", errno, select_err_cnt);
                break;
            }
            HAL_SleepMs(500);
        }
    }

end_of_task:
    if (server_socket != -1) {
        Log_w("Shutting down LOG server socket");
        shutdown(server_socket, 0);
        close(server_socket);
    }

    // don't destory if mqtt task run
    if (!sg_mqtt_task_run) {
        wifi_stop_softap();
        delete_dev_log_queue();
    }

    sg_log_task_run = false;
    Log_i("LOG server task quit");

#ifdef CONFIG_FREERTOS_USE_TRACE_FACILITY
    TaskStatus_t task_status;
    vTaskGetInfo(NULL, &task_status, pdTRUE, eRunning);
    Log_i(">>>>> task %s stack left: %u, free heap: %u", task_status.pcTaskName, task_status.usStackHighWaterMark,
          esp_get_free_heap_size());
#endif

    sg_log_task_cnt--;
    vTaskDelete(NULL);
}
#endif

int start_log_softAP(void)
{
#ifdef WIFI_LOG_UPLOAD
    Log_i("enter log softAP mode");

    sg_log_task_run = false;

    int ret = wifi_ap_init("ESP-LOG-QUERY", "86013388", 0);
    if (ret) {
        Log_e("wifi_ap_init failed: %d", ret);
        goto err_exit;
    }

    ret = wifi_start_running();
    if (ret) {
        Log_e("wifi_start_running failed: %d", ret);
        goto err_exit;
    }

    sg_log_task_run = true;
    ret = xTaskCreate(log_server_task, "log_server_task", COMM_SERVER_TASK_STACK_BYTES, NULL, COMM_SERVER_TASK_PRIO,
                      NULL);
    if (ret != pdPASS) {
        Log_e("create log_server_task failed: %d", ret);
        goto err_exit;
    }

    return 0;

err_exit:

    wifi_stop_softap();
    delete_dev_log_queue();

    sg_log_task_run = false;
#endif
    return QCLOUD_ERR_FAILURE;
}
//============================ WiFi connect/softAP/smartconfig end ===========================//
