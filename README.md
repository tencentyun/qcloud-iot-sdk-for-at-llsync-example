## 背景介绍
腾讯云物联网发布了官网标准蓝牙协议---[LLSync协议](https://github.com/tencentyun/qcloud-iot-explorer-BLE-sdk-embedded)，本次尝试使用`TencentOS tiny + LLSync`来实现甲醛监测。TOS_EVB_G0开发板搭配的是ESP8266，不支持BLE，所以找了一块ESP32作为BLE芯片使用，TOS_EVB_G0 和 ESP32 之间通过 AT 指令进行通信。

## 硬件

本项目所需要的物品清单有：

- TOS_EVB_G0开发板 x 1
- 英国 Dart 甲醛传感器 x 1
- E53甲醛传感器底板 x 1
- ESP32开发板 x 1

![](https://main.qcloudimg.com/raw/59e59991234d242db524c22772335398.png)

## 硬件连接

TOS_EVB_G0和ESP32使用杜邦线连接，均使用UART0，如下图示。

![](https://main.qcloudimg.com/raw/63f5361155c1433ea3775fd4efb29e6f.jpg)

1. ESP32上使用UART0作为AT口，即TX是GPIO 17，RX是GPIO 16。

## 数据通路

1. Dart 甲醛传感器采集甲醛数据

2. TOS_EVB_G0开发板接收甲醛数据，并通过`AT指令`发送到ESP32

3. ESP32通过AT指令接收甲醛数据，并通过`BLE`发送到腾讯连连小程序

4. 腾讯连连小程序通过网络将数据上报到腾讯云物联网开发平台

![](https://main.qcloudimg.com/raw/fbcd63b23963d4d21359b896b459adf4.jpg)



## 软件代码

#### TOS_EVB_G0代码

TencentOS_tiny 例程中已经有一个甲醛监测的[示例工程](https://github.com/Tencent/TencentOS-tiny/tree/master/board/TencentOS_tiny_EVB_G0/KEIL/mqtt_iot_explorer_tc_ch20_oled)，对源码进行一些修改。改动包括：

1. 屏蔽例程中ESP8266的初始化。
2. 增加新的AT指令 `AT+TCREPORT`上报甲醛数值。
3. 打通 TOS_EVB_G0 和 ESP32 的AT通信。

本仓库中已经上传了改动后的文件，可以直接替换对应文件。

#### ESP32代码

将腾讯云物联网的 [ESP8266 AT SDK](https://cloud.tencent.com/document/product/1081/48366) 修改后适配在 ESP32 上，见`esp32-at/components/qcloud_at`。

参考腾讯云物联网平台的[LLSync SDK接入指引](https://cloud.tencent.com/document/product/1081/48398)，将LLSync的demo移植到ESP32上。代码位于`esp32-at/components/qcloud_at`。

## 示例运行

1. 打开手机蓝牙，启动腾讯连连小程序，连接ESP32，连接成功后可以看到小程序实时收到甲醛数据。

  ![](https://main.qcloudimg.com/raw/4bca129d38e5c1c74fbb624121e064cd.jpg)

2. 登陆腾讯云物联网开发平台控制开，在设备调试页面可以收到小程序上传的数据。

  ![](https://main.qcloudimg.com/raw/e2f59a9e542358c49bd5a53c1c484f73.jpg)


