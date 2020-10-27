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

#ifndef __QCLOUD_AT_BOARD_H__
#define __QCLOUD_AT_BOARD_H__

#ifndef GPIO_WIFI_STATE
#define GPIO_WIFI_STATE (2)
#endif

#define GPIO_SET   (1)
#define GPIO_CLEAR (0)

#define LED_ON  GPIO_CLEAR
#define LED_OFF GPIO_SET

void board_init(void);

esp_err_t set_wifi_led_state(uint32_t state);

#endif  //__QCLOUD_AT_BOARD_H__
