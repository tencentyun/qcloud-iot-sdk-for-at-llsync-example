# TODO：esma，support gnu make ？
# Component Makefile
#

ifdef CONFIG_AT_QCLOUD_IOT_COMMAND_SUPPORT
#build options for qcloud-esp-at
#CFLAGS += -DWIFI_ERR_LOG_POST
CFLAGS += -DENABLE_TEST_COMMANDS
#CFLAGS += -DBOARD_IS_WIFI_KIT

COMPONENT_ADD_INCLUDEDIRS := \
    qcloud_iot_c_sdk/include \
    qcloud_iot_c_sdk/include/exports \
    qcloud_iot_c_sdk/sdk_src/internal_inc

COMPONENT_SRCDIRS := \
    qcloud_iot_c_sdk/platform \
    qcloud_iot_c_sdk/sdk_src
endif
