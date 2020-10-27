if (CONFIG_AT_QCLOUD_IOT_COMMAND_SUPPORT)
    set(srcs
            qcloud_iot_c_sdk/platform/HAL_Device_freertos.c
            qcloud_iot_c_sdk/platform/HAL_OS_freertos.c
            qcloud_iot_c_sdk/platform/HAL_TCP_lwip.c
            qcloud_iot_c_sdk/platform/HAL_Timer_freertos.c
            qcloud_iot_c_sdk/platform/HAL_TLS_mbedtls.c)

    list(APPEND srcs
            qcloud_iot_c_sdk/sdk_src/dynreg.c
            qcloud_iot_c_sdk/sdk_src/gateway_api.c
            qcloud_iot_c_sdk/sdk_src/gateway_common.c
            qcloud_iot_c_sdk/sdk_src/json_parser.c
            qcloud_iot_c_sdk/sdk_src/json_token.c
            qcloud_iot_c_sdk/sdk_src/mqtt_client.c
            qcloud_iot_c_sdk/sdk_src/mqtt_client_common.c
            qcloud_iot_c_sdk/sdk_src/mqtt_client_connect.c
            qcloud_iot_c_sdk/sdk_src/mqtt_client_net.c
            qcloud_iot_c_sdk/sdk_src/mqtt_client_publish.c
            qcloud_iot_c_sdk/sdk_src/mqtt_client_subscribe.c
            qcloud_iot_c_sdk/sdk_src/mqtt_client_unsubscribe.c
            qcloud_iot_c_sdk/sdk_src/mqtt_client_yield.c
            qcloud_iot_c_sdk/sdk_src/network_interface.c
            qcloud_iot_c_sdk/sdk_src/network_socket.c
            qcloud_iot_c_sdk/sdk_src/network_tls.c
            qcloud_iot_c_sdk/sdk_src/ota_client.c
            qcloud_iot_c_sdk/sdk_src/ota_fetch.c
            qcloud_iot_c_sdk/sdk_src/ota_lib.c
            qcloud_iot_c_sdk/sdk_src/ota_mqtt.c
            qcloud_iot_c_sdk/sdk_src/qcloud_iot_ca.c
            qcloud_iot_c_sdk/sdk_src/qcloud_iot_device.c
            qcloud_iot_c_sdk/sdk_src/qcloud_iot_log.c
            qcloud_iot_c_sdk/sdk_src/string_utils.c
            qcloud_iot_c_sdk/sdk_src/system_mqtt.c
            qcloud_iot_c_sdk/sdk_src/utils_aes.c
            qcloud_iot_c_sdk/sdk_src/utils_base64.c
            qcloud_iot_c_sdk/sdk_src/utils_getopt.c
            qcloud_iot_c_sdk/sdk_src/utils_hmac.c
            qcloud_iot_c_sdk/sdk_src/utils_httpc.c
            qcloud_iot_c_sdk/sdk_src/utils_list.c
            qcloud_iot_c_sdk/sdk_src/utils_md5.c
            qcloud_iot_c_sdk/sdk_src/utils_ringbuff.c
            qcloud_iot_c_sdk/sdk_src/utils_sha1.c
            qcloud_iot_c_sdk/sdk_src/utils_timer.c)

    list(APPEND srcs
            qcloud-esp-at/src/qcloud_at_board.c
            qcloud-esp-at/src/qcloud_at_flash.c
            qcloud-esp-at/src/qcloud_at_cmd.c
            qcloud-esp-at/src/qcloud_at_mqtt.c
            qcloud-esp-at/src/qcloud_at_mqtt_ota.c)

    list(APPEND srcs
            qcloud-esp-at/src/wifi_config/wifi_config_error_handle.c
            qcloud-esp-at/src/wifi_config/wifi_config_esp.c
            qcloud-esp-at/src/wifi_config/wifi_config_log_handle.c
            qcloud-esp-at/src/wifi_config/qcloud_wifi_config.c)

    list(APPEND srcs esp_qcloud_iot.c)

    set(includes include qcloud_iot_c_sdk/include qcloud_iot_c_sdk/include/exports)
    set(priv_includes qcloud_iot_c_sdk/sdk_src/internal_inc qcloud-esp-at/include qcloud-esp-at/src/wifi_config)
endif ()

idf_component_register(SRCS "${srcs}"
        INCLUDE_DIRS "${includes}"
        PRIV_INCLUDE_DIRS "${priv_includes}"
        REQUIRES mbedtls at spi_flash main)
