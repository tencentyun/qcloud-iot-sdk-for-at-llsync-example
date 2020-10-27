/*
 * Tencent is pleased to support the open source community by making IoT Hub available.
 * Copyright (C) 2018-2020 THL A29 Limited, a Tencent company. All rights reserved.

 * Licensed under the MIT License (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://opensource.org/licenses/MIT

 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include "gateway_common.h"

#include "lite-utils.h"
#include "mqtt_client.h"
#include "utils_base64.h"
#include "utils_hmac.h"
#include "utils_md5.h"

static bool get_json_type(char *json, char **v)
{
    *v = LITE_json_value_of("type", json);
    return *v == NULL ? false : true;
}

static bool get_json_devices(char *json, char **v)
{
    *v = LITE_json_value_of("payload.devices", json);
    return *v == NULL ? false : true;
}

static bool get_json_result(char *json, int32_t *res)
{
    char *v = LITE_json_value_of("result", json);
    if (v == NULL) {
        return false;
    }
    if (LITE_get_int32(res, v) != QCLOUD_RET_SUCCESS) {
        HAL_Free(v);
        return false;
    }
    HAL_Free(v);
    return true;
}

static bool get_json_product_id(char *json, char **v)
{
    *v = LITE_json_value_of("product_id", json);
    return *v == NULL ? false : true;
}

static bool get_json_device_name(char *json, char **v)
{
    *v = LITE_json_value_of("device_name", json);
    return *v == NULL ? false : true;
}

static void _gateway_message_handler(void *client, MQTTMessage *message, void *user_data)
{
    Gateway *          gateway       = NULL;
    char *             topic         = NULL;
    size_t             topic_len     = 0;
    int                cloud_rcv_len = 0;
    char *             type          = NULL;
    char *             devices = NULL, *devices_strip = NULL;
    char *             product_id                           = NULL;
    char *             device_name                          = NULL;
    int32_t            result                               = 0;
    char               client_id[MAX_SIZE_OF_CLIENT_ID + 1] = {0};
    int                size                                 = 0;

    POINTER_SANITY_CHECK_RTN(client);
    POINTER_SANITY_CHECK_RTN(message);

    gateway = (Gateway *)user_data;
    POINTER_SANITY_CHECK_RTN(gateway);

    topic     = (char *)message->ptopic;
    topic_len = message->topic_len;
    if (NULL == topic || topic_len == 0) {
        Log_e("topic == NULL or topic_len == 0.");
        return;
    }

    if (message->payload_len > GATEWAY_RECEIVE_BUFFER_LEN) {
        Log_e("message->payload_len > GATEWAY_RECEIVE_BUFFER_LEN.");
        return;
    }

    cloud_rcv_len  = Min(GATEWAY_RECEIVE_BUFFER_LEN - 1, message->payload_len);
    char *json_buf = gateway->recv_buf;
    memcpy(gateway->recv_buf, message->payload, cloud_rcv_len);
    json_buf[cloud_rcv_len] = '\0';  // jsmn_parse relies on a string

    Log_d("msg payload: %s", json_buf);

    if (!get_json_type(json_buf, &type)) {
        Log_e("Fail to parse type from msg: %s", json_buf);
        return;
    }

    if (!get_json_devices(json_buf, &devices)) {
        Log_e("Fail to parse devices from msg: %s", json_buf);
        HAL_Free(type);
        return;
    }

    if (devices[0] == '[') {
        devices_strip = devices + 1;
    } else {
        devices_strip = devices;
    }

    if (!get_json_result(devices_strip, &result)) {
        Log_e("Fail to parse result from msg: %s", json_buf);
        HAL_Free(type);
        HAL_Free(devices);
        return;
    }
    if (!get_json_product_id(devices_strip, &product_id)) {
        Log_e("Fail to parse product_id from msg: %s", json_buf);
        HAL_Free(type);
        HAL_Free(devices);
        return;
    }
    if (!get_json_device_name(devices_strip, &device_name)) {
        Log_e("Fail to parse device_name from msg: %s", json_buf);
        HAL_Free(type);
        HAL_Free(devices);
        HAL_Free(product_id);
        return;
    }

    size = HAL_Snprintf(client_id, MAX_SIZE_OF_CLIENT_ID + 1, GATEWAY_CLIENT_ID_FMT, product_id, device_name);
    if (size < 0 || size > MAX_SIZE_OF_CLIENT_ID) {
        Log_e("generate client_id fail.");
        HAL_Free(type);
        HAL_Free(devices);
        HAL_Free(product_id);
        HAL_Free(device_name);
        return;
    }

    if (strncmp(type, GATEWAY_ONLINE_OP_STR, sizeof(GATEWAY_ONLINE_OP_STR) - 1) == 0) {
        if (strncmp(client_id, gateway->gateway_data.online.client_id, size) == 0) {
            Log_i("client_id(%s), online result %d", client_id, result);
            gateway->gateway_data.online.result = result;
        }
    } else if (strncmp(type, GATEWAY_OFFLIN_OP_STR, sizeof(GATEWAY_OFFLIN_OP_STR) - 1) == 0) {
        if (strncmp(client_id, gateway->gateway_data.offline.client_id, size) == 0) {
            Log_i("client_id(%s), offline result %d", client_id, result);
            gateway->gateway_data.offline.result = result;
        }
    } else if (strncmp(type, GATEWAY_BIND_OP_STR, sizeof(GATEWAY_BIND_OP_STR) - 1) == 0) {
        if (strncmp(client_id, gateway->gateway_data.bind.client_id, size) == 0) {
            gateway->gateway_data.bind.result = result;
            Log_i("client_id(%s), bind result %d", client_id, gateway->gateway_data.bind.result);
        }
    } else if (strncmp(type, GATEWAY_UNBIND_OP_STR, sizeof(GATEWAY_UNBIND_OP_STR) - 1) == 0) {
        if (strncmp(client_id, gateway->gateway_data.unbind.client_id, size) == 0) {
            gateway->gateway_data.unbind.result = result;
            Log_i("client_id(%s), unbind result %d", client_id, gateway->gateway_data.unbind.result);
        }
    }

    HAL_Free(type);
    HAL_Free(devices);
    HAL_Free(product_id);
    HAL_Free(device_name);
    return;
}

void _gateway_sub_event_handler(void *pClient, MQTTEventType event_type, void *user_data)
{
    Gateway *gateway = (Gateway *)user_data;

    switch (event_type) {
        case MQTT_EVENT_SUBCRIBE_SUCCESS:
            Log_i("gateway topic sub success");
            gateway->sub_ready = true;
            break;

        case MQTT_EVENT_UNSUBSCRIBE:
            Log_i("topic has been unsubscribed");
            gateway->sub_ready = false;            
            break;
        case MQTT_EVENT_SUBCRIBE_TIMEOUT:
        case MQTT_EVENT_SUBCRIBE_NACK:
            Log_e("gateway topic sub fail");
            gateway->sub_ready = false;            
            break;
        case MQTT_EVENT_CLIENT_DESTROY:
            Log_i("mqtt client has been destroyed");
            gateway->sub_ready = false;
            break;

        default:
            break;
    }

    return;
}


int subscribe_gateway_result_topic(Gateway *gateway, GatewayParam *param)
{
    int             rc                                        = 0;
    int             size                                      = 0;
    char            topic_filter[MAX_SIZE_OF_CLOUD_TOPIC + 1] = {0};
    SubscribeParams subscribe_params                          = DEFAULT_SUB_PARAMS;

    POINTER_SANITY_CHECK(param, QCLOUD_ERR_INVAL);
    STRING_PTR_SANITY_CHECK(param->product_id, QCLOUD_ERR_INVAL);
    STRING_PTR_SANITY_CHECK(param->device_name, QCLOUD_ERR_INVAL);

    // subscribe gateway operation reslut
    size = HAL_Snprintf(topic_filter, MAX_SIZE_OF_CLOUD_TOPIC + 1, GATEWAY_TOPIC_OPERATION_RESULT_FMT,
                        param->product_id, param->device_name);
    if (size < 0 || size > MAX_SIZE_OF_CLOUD_TOPIC) {
        Log_e("buf size < topic length!");
        IOT_FUNC_EXIT_RC(QCLOUD_ERR_FAILURE);
    }

    subscribe_params.on_message_handler = _gateway_message_handler;
    subscribe_params.on_sub_event_handler = _gateway_sub_event_handler;
    subscribe_params.user_data = gateway;
    subscribe_params.qos       = QOS1;
    gateway->sub_ready = false;

    rc = IOT_MQTT_Subscribe(gateway->mqtt, topic_filter, &subscribe_params);
    if (rc < 0) {
        Log_e("subscribe failed: %d", rc);
        IOT_FUNC_EXIT_RC(rc);
    }

    int loop_count = 0;
    while (!gateway->sub_ready) {
        if (loop_count > GATEWAY_LOOP_MAX_COUNT) {
            Log_e("wait for sub time out");
            IOT_FUNC_EXIT_RC(QCLOUD_ERR_FAILURE);
        }

        IOT_Gateway_Yield(gateway, 200);
        loop_count++;
    }

    IOT_FUNC_EXIT_RC(QCLOUD_RET_SUCCESS);
}

SubdevSession *subdev_find_session(Gateway *gateway, char *product_id, char *device_name)
{
    SubdevSession *session = NULL;

    POINTER_SANITY_CHECK(gateway, NULL);
    STRING_PTR_SANITY_CHECK(product_id, NULL);
    STRING_PTR_SANITY_CHECK(device_name, NULL);

    session = gateway->session_list;

    /* session is exist */
    while (session) {
        if (0 == strncmp(session->product_id, product_id, strlen(product_id)) &&
            0 == strncmp(session->device_name, device_name, strlen(device_name))) {
            IOT_FUNC_EXIT_RC(session);
        }
        session = session->next;
    }

    IOT_FUNC_EXIT_RC(NULL);
}

SubdevSession *subdev_add_session(Gateway *gateway, char *product_id, char *device_name)
{
    SubdevSession *session = NULL;

    POINTER_SANITY_CHECK(gateway, NULL);
    STRING_PTR_SANITY_CHECK(product_id, NULL);
    STRING_PTR_SANITY_CHECK(device_name, NULL);

    session = HAL_Malloc(sizeof(SubdevSession));
    if (session == NULL) {
        Log_e("Not enough memory");
        IOT_FUNC_EXIT_RC(NULL);
    }

    memset(session, 0, sizeof(SubdevSession));
    /* add session to list */
    session->next         = gateway->session_list;
    gateway->session_list = session;

    int size = strlen(product_id);
    strncpy(session->product_id, product_id, size);
    session->product_id[size] = '\0';
    size                      = strlen(device_name);
    strncpy(session->device_name, device_name, size);
    session->device_name[size] = '\0';
    session->session_status    = SUBDEV_SEESION_STATUS_INIT;

    IOT_FUNC_EXIT_RC(session);
}

int subdev_remove_session(Gateway *gateway, char *product_id, char *device_name)
{
    SubdevSession *cur_session = NULL;
    SubdevSession *pre_session = NULL;

    POINTER_SANITY_CHECK(gateway, QCLOUD_ERR_FAILURE);
    STRING_PTR_SANITY_CHECK(product_id, QCLOUD_ERR_FAILURE);
    STRING_PTR_SANITY_CHECK(device_name, QCLOUD_ERR_FAILURE);

    pre_session = cur_session = gateway->session_list;

    if (NULL == cur_session) {
        Log_e("session list is empty");
        IOT_FUNC_EXIT_RC(QCLOUD_RET_SUCCESS);
    }

    /* session is exist */
    while (cur_session) {
        if (0 == strncmp(cur_session->product_id, product_id, strlen(product_id)) &&
            0 == strncmp(cur_session->device_name, device_name, strlen(device_name))) {
            if (cur_session == gateway->session_list) {
                gateway->session_list = cur_session->next;
            } else {
                pre_session->next = cur_session->next;
            }
            HAL_Free(cur_session);
            IOT_FUNC_EXIT_RC(QCLOUD_RET_SUCCESS);
        }
        pre_session = cur_session;
        cur_session = cur_session->next;
    }

    IOT_FUNC_EXIT_RC(QCLOUD_ERR_FAILURE);
}

int gateway_publish_sync(Gateway *gateway, char *topic, PublishParams *params, int32_t *result)
{
    int     rc         = 0;
    int     loop_count = 0;
    int32_t res        = *result;

    POINTER_SANITY_CHECK(gateway, QCLOUD_ERR_INVAL);

    rc = IOT_Gateway_Publish(gateway, topic, params);
    if (rc < 0) {
        Log_e("publish fail.");
        IOT_FUNC_EXIT_RC(QCLOUD_ERR_FAILURE);
    }

    /* wait for response */
    while (res == *result) {
        if (loop_count > GATEWAY_LOOP_MAX_COUNT) {
            Log_i("loop max count, time out.");
            IOT_FUNC_EXIT_RC(QCLOUD_ERR_GATEWAY_SESSION_TIMEOUT);
        }

        IOT_Gateway_Yield(gateway, 200);
        loop_count++;
    }

    if (*result != 0) {
        IOT_FUNC_EXIT_RC(QCLOUD_ERR_FAILURE);
    }
    IOT_FUNC_EXIT_RC(QCLOUD_RET_SUCCESS);
}

#ifdef AUTH_MODE_CERT
static int gen_key_from_cert_file(const char *file_path, char *keybuff, int buff_len)
{
    FILE *   fp;
    uint32_t length;
    int ret = QCLOUD_RET_SUCCESS;

    if ((fp = fopen(file_path, "r")) == NULL) {
        Log_e("fail to open cert file %s", file_path);
        return QCLOUD_ERR_FAILURE;
    }

    fseek(fp, 0L, SEEK_END);
    length = ftell(fp);
    uint8_t *data = HAL_Malloc(length + 1);
    if (!data) {
        Log_e("malloc mem err");
        return QCLOUD_ERR_MALLOC;
    }

    fseek(fp, 0, SEEK_SET);
    if (length != fread(data, 1, length, fp)) {
        Log_e("read data len fail");
        ret =  QCLOUD_ERR_FAILURE;
        goto exit;
    }

    utils_md5_str(data, length, (uint8_t *)keybuff);
    Log_d("sign key: %s", keybuff);

exit:

    HAL_Free(data);
    fclose(fp);

    return ret;
}

#endif

int subdev_bind_hmac_sha1_cal(DeviceInfo *pDevInfo, char *signout, int max_signlen, int nonce, long timestamp)
{
    int         text_len, ret;
    size_t      olen                   = 0;
    char *      pSignText            = NULL;
    const char *sign_fmt               = "%s%s;%d;%d"; //${product_id}${device_name};${random};${expiration_time}

    /*format sign data*/
    text_len = strlen(sign_fmt) + strlen(pDevInfo->device_name) + strlen(pDevInfo->product_id) + sizeof(int) +
               sizeof(long) + 10;
    pSignText = HAL_Malloc(text_len);
    if (pSignText == NULL) {
        Log_e("malloc sign source buff fail");
        return QCLOUD_ERR_FAILURE;
    }
    memset(pSignText, 0, text_len);
    HAL_Snprintf((char *)pSignText, text_len, sign_fmt, pDevInfo->product_id, pDevInfo->device_name, nonce, timestamp);

    //gen digest key
    char key[BIND_SIGN_KEY_SIZE + 1] = {0};
#ifdef AUTH_MODE_CERT
    ret = gen_key_from_cert_file(pDevInfo->dev_cert_file_name, key, BIND_SIGN_KEY_SIZE);
    if (QCLOUD_RET_SUCCESS != ret) {
        Log_e("gen key from cert file fail, ret:%d", ret);
        HAL_Free(pSignText);
        return ret;
    }
#else
    strncpy(key, pDevInfo->device_secret, strlen(pDevInfo->device_secret));
#endif

    /*cal hmac sha1*/
    char sign[SUBDEV_BIND_SIGN_LEN] = {0};
    int sign_len = utils_hmac_sha1_hex(pSignText, strlen(pSignText), sign, key, strlen(key));

    /*base64 encode*/
    ret = qcloud_iot_utils_base64encode((uint8_t *)signout, max_signlen, &olen, (const uint8_t *)sign, sign_len);
    HAL_Free(pSignText);

    return (olen > max_signlen) ? QCLOUD_ERR_FAILURE : ret;
}
