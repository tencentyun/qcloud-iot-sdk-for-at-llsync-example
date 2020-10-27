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

#ifndef __QCLOUD_AT_CMD_H__
#define __QCLOUD_AT_CMD_H__

#define QCLOUD_IOT_AT_VERSION "QCloud_AT_ESP32_v1.0.0"

typedef enum _eCmd_Err_Code_ {
    eDEALING_ERR   = 200, /*previous cmd not finished error*/
    eOVER_FLOW_ERR = 201, /*msg packet over size*/
    eTIME_OUT_ERR  = 202, /*input timeout*/
    eCHECK_ERR     = 203, /*progress checked error*/
    ePARA_ERR      = 204, /*parameters error*/
    eFIRMWARE_ERR  = 205, /*Firmware invalid*/
    eMEM_ERR       = 206, /*memory error*/
    eFLASH_ERR     = 207, /*FLASH error*/
    eSTATE_ERR     = 208, /*status not ready*/
    eEXEC_ERR      = 209, /*cmd execution error*/
    eUNKNOW_ERR    = 210, /*unknown error*/
    eOTA_ERR       = 211, /*self-OTA error*/
    eERASE_ERR     = 212, /*FLASH ERASE is going on*/
    eHTTP_ERR      = 213, /*HTTP error*/
} eCmd_Err_Code;

void at_cmd_printf(const char *fmt, ...);

#endif  // __QCLOUD_AT_CMD_H__
