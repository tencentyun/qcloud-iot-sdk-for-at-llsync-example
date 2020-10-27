## 背景介绍
腾讯云物联网发布了官网标准蓝牙协议---[LLSync协议](https://github.com/tencentyun/qcloud-iot-explorer-BLE-sdk-embedded)，本次尝试使用`TencentOS tiny + LLSync`来实现甲醛监测。TOS_EVB_G0开发板搭配的是ESP8266，不支持BLE，所以找了一块ESP32作为BLE芯片使用，TOS_EVB_G0 和 ESP32 之间通过 AT 指令进行通信。

## 系统设计

#### 数据通路

![](https://main.qcloudimg.com/raw/fbcd63b23963d4d21359b896b459adf4.jpg)
1. Dart 甲醛传感器采集甲醛数据

2. TOS_EVB_G0开发板接收甲醛数据，并通过`AT指令`发送到ESP32

3. ESP32通过AT指令接收甲醛数据，并通过`BLE`发送到腾讯连连小程序

4. 腾讯连连小程序通过网络将数据上报到腾讯云物联网开发平台

   

### 硬件环境

本项目所需要的物品清单有：

- TOS_EVB_G0开发板 x 1
- 英国 Dart 甲醛传感器 x 1
- E53甲醛传感器底板 x 1
- ESP32开发板 x 1

#### 硬件连接

TOS_EVB_G0和ESP32使用杜邦线连接

![](https://main.qcloudimg.com/raw/63f5361155c1433ea3775fd4efb29e6f.jpg)

1. 考虑到TOS_EVB_G0已经使用AT指令和ESP8266通信，TOS_EVB_G0开发板的AT口可以直接复用，绿色是GND。
2. ESP32上使用UART0作为AT口，即TX是GPIO 17，RX是GPIO 16。

## 软件代码

#### TOS_EVB_G0代码

TOS_EVB_G0 上对例程代码 `TencentOS-tiny/board/TencentOS_tiny_EVB_G0/KEIL/mqtt_iot_explorer_tc_ch20_oled`进行简单修改即可，改动包括：

1. 屏蔽例程中ESP8266的初始化。
2. 增加新的AT指令 `AT+TCREPORT`上报甲醛数值。

本仓库中已经上传了改动后的文件，直接替换即可。

#### ESP32代码

将腾讯云物联网的 [ESP8266 AT SDK](https://cloud.tencent.com/document/product/1081/48366) 修改后适配在 ESP32 上，见`esp32-at/componentsqcloud_at`。

将腾讯云物联网的[LLSync SDK](https://cloud.tencent.com/document/product/1081/48398)适配到 ESP32 上，见`esp32-at/componentsqcloud_at`。

## 示例运行

1. ESP32 连接小程序后，小程序可以收到 TOS_EVB_G0 开发板采集到的甲醛数据。

  ![](https://main.qcloudimg.com/raw/4bca129d38e5c1c74fbb624121e064cd.jpg)

2. 物联网开发平台可以收到小程序的数据。

  ![](https://main.qcloudimg.com/raw/e2f59a9e542358c49bd5a53c1c484f73.jpg)

3. 物联网开发平台的数据统计如下图。

  ![](https://main.qcloudimg.com/raw/f9d1146b5e1e639c8b96bbe8a55c10c3.jpg)

  

