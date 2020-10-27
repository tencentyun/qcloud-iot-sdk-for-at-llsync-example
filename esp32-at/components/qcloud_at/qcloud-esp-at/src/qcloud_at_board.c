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

#include "driver/gpio.h"

#include "qcloud_at_board.h"
#include "qcloud_at_flash.h"

uint32_t g_wifi_led_gpio = GPIO_WIFI_STATE;

esp_err_t set_wifi_led_state(uint32_t state)
{
    return gpio_set_level(g_wifi_led_gpio, state);
}

void board_init(void)
{
    gpio_config_t ioconfig;

    g_wifi_led_gpio = get_module_info()->wifi_led_gpio;

    ioconfig.pin_bit_mask = (1ULL << g_wifi_led_gpio);
    ioconfig.intr_type    = GPIO_INTR_DISABLE;
    ioconfig.mode         = GPIO_MODE_OUTPUT;
    ioconfig.pull_up_en   = GPIO_PULLUP_ENABLE;
    gpio_config(&ioconfig);

    set_wifi_led_state(LED_OFF);
}
