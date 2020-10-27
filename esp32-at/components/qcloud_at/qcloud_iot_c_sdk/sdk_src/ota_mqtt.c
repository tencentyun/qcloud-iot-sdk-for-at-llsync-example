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

#ifdef __cplusplus
extern "C" {
#endif

#include "qcloud_iot_export.h"
#include "qcloud_iot_import.h"

#ifdef OTA_MQTT_CHANNEL

#include <string.h>

#include "ota_client.h"

/* OSC, OTA signal channel */
typedef struct {
    void *mqtt;  // MQTT cient

    const char *product_id;
    const char *device_name;

    char                 topic_ota[OTA_MAX_TOPIC_LEN];  // OTA MQTT Topic
    char                 topic_res[OTA_MAX_TOPIC_LEN];  // Resource manage MQTT Topic
    OnOTAMessageCallback ota_callback;
    OnOTAMessageCallback res_callback;

    //	OnOTAEventUsrCallback   event_callback;

    void *context;
    bool  topic_ota_ready;
    bool  topic_res_ready;
} OTA_MQTT_Struct_t;

/* Generate topic name according to @OTATopicType, @productId, @deviceName */
/* and then copy to @buf. */
/* 0, successful; -1, failed */
static int _otamqtt_gen_topic_name(char *buf, size_t bufLen, const char *OTATopicType, const char *productId,
                                   const char *deviceName)
{
    IOT_FUNC_ENTRY;

    int ret;

    if ((0 == strcmp(OTATopicType, "down")) || (0 == strcmp(OTATopicType, "up"))) {  // resource topic
        ret = HAL_Snprintf(buf, bufLen, "$thing/%s/service/%s/%s", OTATopicType, productId, deviceName);
    } else {
        ret = HAL_Snprintf(buf, bufLen, "$ota/%s/%s/%s", OTATopicType, productId, deviceName);
    }

    if (ret >= bufLen)
        IOT_FUNC_EXIT_RC(IOT_OTA_ERR_FAIL);

    if (ret < 0) {
        Log_e("HAL_Snprintf failed");
        IOT_FUNC_EXIT_RC(IOT_OTA_ERR_FAIL);
    }

    IOT_FUNC_EXIT_RC(QCLOUD_RET_SUCCESS);
}

/* report progress of OTA */
static int _otamqtt_publish(OTA_MQTT_Struct_t *handle, const char *topicType, int qos, const char *msg)
{
    IOT_FUNC_ENTRY;

    int           ret;
    char          topic_name[OTA_MAX_TOPIC_LEN];
    PublishParams pub_params = DEFAULT_PUB_PARAMS;

    if (0 == qos) {
        pub_params.qos = QOS0;
    } else {
        pub_params.qos = QOS1;
    }
    pub_params.payload     = (void *)msg;
    pub_params.payload_len = strlen(msg);

    /* inform OTA to topic: "/ota/device/progress/$(product_id)/$(device_name)" */
    ret = _otamqtt_gen_topic_name(topic_name, OTA_MAX_TOPIC_LEN, topicType, handle->product_id, handle->device_name);
    if (ret < 0) {
        Log_e("generate topic name of info failed");
        IOT_FUNC_EXIT_RC(IOT_OTA_ERR_FAIL);
    }

    ret = IOT_MQTT_Publish(handle->mqtt, topic_name, &pub_params);
    if (ret < 0) {
        Log_e("publish to topic: %s failed", topic_name);
        IOT_FUNC_EXIT_RC(IOT_OTA_ERR_OSC_FAILED);
    }

    IOT_FUNC_EXIT_RC(ret);
}

/* callback after OTA topic is subscribed */
/* Parse firmware info (version/URL/file size/MD5) from JSON text */
static void _otamqtt_upgrage_cb(void *pClient, MQTTMessage *message, void *pcontext)
{
    OTA_MQTT_Struct_t *handle = (OTA_MQTT_Struct_t *)pcontext;

    Log_d("topic=%.*s", message->topic_len, message->ptopic);
    Log_i("len=%u, topic_msg=%.*s", message->payload_len, message->payload_len, (char *)message->payload);

    if (NULL != handle->ota_callback) {
        handle->ota_callback(handle->context, message->payload, message->payload_len);
    }
}

/* callback after Resource topic is subscribed */
/* Parse resource info (version/URL/file size/MD5/method) from JSON text */
static void _resmqtt_upgrage_cb(void *pClient, MQTTMessage *message, void *pcontext)
{
    OTA_MQTT_Struct_t *handle = (OTA_MQTT_Struct_t *)pcontext;

    Log_d("topic=%.*s", message->topic_len, message->ptopic);
    Log_d("len=%u, topic_msg=%.*s", message->payload_len, message->payload_len, (char *)message->payload);

    if (NULL != handle->res_callback) {
        handle->res_callback(handle->context, message->payload, message->payload_len);
    }
}

static void _ota_mqtt_sub_event_handler(void *pclient, MQTTEventType event_type, void *user_data)
{
    OTA_MQTT_Struct_t *h_osc = (OTA_MQTT_Struct_t *)user_data;

    switch (event_type) {
        case MQTT_EVENT_SUBCRIBE_SUCCESS:
            Log_d("OTA topic subscribe success");
            h_osc->topic_ota_ready = true;
            break;

        case MQTT_EVENT_SUBCRIBE_TIMEOUT:
            Log_i("OTA topic subscribe timeout");
            h_osc->topic_ota_ready = false;
            break;

        case MQTT_EVENT_SUBCRIBE_NACK:
            Log_i("OTA topic subscribe NACK");
            h_osc->topic_ota_ready = false;
            break;
        case MQTT_EVENT_UNSUBSCRIBE:
            Log_i("OTA topic has been unsubscribed");
            h_osc->topic_ota_ready = false;
            ;
            break;
        case MQTT_EVENT_CLIENT_DESTROY:
            Log_i("mqtt client has been destroyed");
            h_osc->topic_ota_ready = false;
            ;
            break;
        default:
            return;
    }
}

static void _res_mqtt_sub_event_handler(void *pclient, MQTTEventType event_type, void *user_data)
{
    OTA_MQTT_Struct_t *h_osc = (OTA_MQTT_Struct_t *)user_data;

    switch (event_type) {
        case MQTT_EVENT_SUBCRIBE_SUCCESS:
            Log_d("RES topic subscribe success");
            h_osc->topic_res_ready = true;
            break;

        case MQTT_EVENT_SUBCRIBE_TIMEOUT:
            Log_i("RES topic subscribe timeout");
            h_osc->topic_res_ready = false;
            break;

        case MQTT_EVENT_SUBCRIBE_NACK:
            Log_i("RES topic subscribe NACK");
            h_osc->topic_res_ready = false;
            break;
        case MQTT_EVENT_UNSUBSCRIBE:
            Log_i("RES topic has been unsubscribed");
            h_osc->topic_res_ready = false;
            break;
        case MQTT_EVENT_CLIENT_DESTROY:
            Log_i("mqtt client has been destroyed");
            h_osc->topic_res_ready = false;
            break;
        default:
            return;
    }
}

void *qcloud_osc_init(const char *productId, const char *deviceName, void *channel, void *context,
                      OnOTAMessageCallback OTAMsgCb, OnOTAMessageCallback ResMsgCb)
{
    int                ret;
    OTA_MQTT_Struct_t *h_osc = NULL;

    if (NULL == (h_osc = HAL_Malloc(sizeof(OTA_MQTT_Struct_t)))) {
        Log_e("allocate for h_osc failed");
        goto do_exit;
    }

    memset(h_osc, 0, sizeof(OTA_MQTT_Struct_t));
    h_osc->mqtt        = channel;
    h_osc->product_id  = productId;
    h_osc->device_name = deviceName;
    h_osc->context     = context;

    ret = qcloud_osc_sub_ota_topic(h_osc, productId, deviceName, OTAMsgCb);
    if (ret < 0) {
        Log_e("ota mqtt subscribe failed!");
        goto do_exit;
    }

    HAL_SleepMs(100);

    ret = qcloud_osc_sub_resource_topic(h_osc, productId, deviceName, ResMsgCb);
    if (ret < 0) {
        Log_e("ota mqtt subscribe failed!");
        goto do_exit;
    }

    return h_osc;

do_exit:
    if (NULL != h_osc) {
        qcloud_osc_deinit(h_osc);
    }

    return NULL;
}

int qcloud_osc_deinit(void *handle)
{
    IOT_FUNC_ENTRY;

    if (NULL != handle) {
        OTA_MQTT_Struct_t *h_osc = (OTA_MQTT_Struct_t *)handle;

        IOT_MQTT_Unsubscribe(h_osc->mqtt, h_osc->topic_ota);
        IOT_MQTT_Unsubscribe(h_osc->mqtt, h_osc->topic_res);
        HAL_Free(handle);
    }

    IOT_FUNC_EXIT_RC(QCLOUD_RET_SUCCESS);
}

int qcloud_osc_sub_ota_topic(void *handle, const char *productId, const char *deviceName, OnOTAMessageCallback MsgCb)
{
    int                ret;
    OTA_MQTT_Struct_t *h_osc = (OTA_MQTT_Struct_t *)handle;

    /* subscribe the OTA topic: "$ota/update/$(product_id)/$(device_name)" */
    memset(h_osc->topic_ota, '\0', OTA_MAX_TOPIC_LEN);
    ret = _otamqtt_gen_topic_name(h_osc->topic_ota, OTA_MAX_TOPIC_LEN, "update", productId, deviceName);
    if (ret < 0) {
        Log_e("generate topic name of upgrade failed");
        return ret;
    }

    h_osc->ota_callback             = MsgCb;
    SubscribeParams sub_params      = DEFAULT_SUB_PARAMS;
    sub_params.on_message_handler   = _otamqtt_upgrage_cb;
    sub_params.on_sub_event_handler = _ota_mqtt_sub_event_handler;
    sub_params.qos                  = QOS1;
    sub_params.user_data            = h_osc;

    ret = IOT_MQTT_Subscribe(h_osc->mqtt, h_osc->topic_ota, &sub_params);
    if (ret < 0) {
        Log_e("ota mqtt subscribe failed!");
        return ret;
    }

    int wait_cnt = 10;
    while (!h_osc->topic_ota_ready && (wait_cnt > 0)) {
        // wait for subscription result
        IOT_MQTT_Yield(h_osc->mqtt, 500);
        wait_cnt--;
    }

    if (!h_osc->topic_ota_ready) {
        Log_e("ota mqtt subscribe timeout!");
        ret = QCLOUD_ERR_MQTT_REQUEST_TIMEOUT;
    }

    return ret;
}

int qcloud_osc_sub_resource_topic(void *hanlde, const char *productId, const char *deviceName,
                                  OnOTAMessageCallback MsgCb)
{
    int                ret;
    OTA_MQTT_Struct_t *h_osc = (OTA_MQTT_Struct_t *)hanlde;

    /* subscribe the OTA topic: "$ota/update/$(product_id)/$(device_name)" */
    memset(h_osc->topic_res, '\0', OTA_MAX_TOPIC_LEN);
    ret = _otamqtt_gen_topic_name(h_osc->topic_res, OTA_MAX_TOPIC_LEN, "down", productId, deviceName);
    if (ret < 0) {
        Log_e("generate topic name of resource failed");
        return ret;
    }

    h_osc->res_callback             = MsgCb;
    SubscribeParams sub_params      = DEFAULT_SUB_PARAMS;
    sub_params.on_message_handler   = _resmqtt_upgrage_cb;
    sub_params.on_sub_event_handler = _res_mqtt_sub_event_handler;
    sub_params.qos                  = QOS1;
    sub_params.user_data            = h_osc;

    ret = IOT_MQTT_Subscribe(h_osc->mqtt, h_osc->topic_res, &sub_params);
    if (ret < 0) {
        Log_e("ota mqtt subscribe failed!");
        return ret;
    }

    int wait_cnt = 10;
    while (!h_osc->topic_res_ready && (wait_cnt > 0)) {
        // wait for subscription result
        IOT_MQTT_Yield(h_osc->mqtt, 500);
        wait_cnt--;
    }

    if (!h_osc->topic_res_ready) {
        Log_e("res mqtt subscribe timeout!");
        ret = QCLOUD_ERR_MQTT_REQUEST_TIMEOUT;
    }

    return ret;
}

int qcloud_osc_del_resource_file(void *hanlde, const char *file_name, const char *version)
{
    int ret = QCLOUD_RET_SUCCESS;
    Log_w("res delete method is NOT supported!");
    IOT_FUNC_EXIT_RC(ret);
}

/* report progress of OTA */
int qcloud_osc_report_progress(void *handle, const char *msg, const char *topicType)
{
    return _otamqtt_publish(handle, topicType, QOS0, msg);
}

/* report version of OTA firmware */
int qcloud_osc_report_version(void *handle, const char *msg, const char *topicType)
{
    return _otamqtt_publish(handle, topicType, QOS1, msg);
}

/* report upgrade begin of OTA firmware */
int qcloud_osc_report_upgrade_result(void *handle, const char *msg, const char *topicType)
{
    return _otamqtt_publish(handle, topicType, QOS1, msg);
}

#endif

#ifdef __cplusplus
}
#endif