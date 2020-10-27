/*
 * ESPRESSIF MIT License
 *
 * Copyright (c) 2019 <ESPRESSIF SYSTEMS (SHANGHAI) PTE LTD>
 *
 * Permission is hereby granted for use on ESPRESSIF SYSTEMS chip only, in which case,
 * it is free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "FreeRTOS.h"

#include "soc/uart_struct.h"

#include "driver/uart.h"

#include "qcloud_iot_at.h"

bool esp_qcloud_at_init(void)
{
    uart_port_t uart_port = UART_NUM_0;
    bool               ret       = true;
    uart_intr_config_t uart_intr = {.intr_enable_mask = UART_RXFIFO_FULL_INT_ENA_M | UART_RXFIFO_TOUT_INT_ENA_M |
                                                        UART_FRM_ERR_INT_ENA_M | UART_RXFIFO_OVF_INT_ENA_M,
                                    .rxfifo_full_thresh       = 60,
                                    .rx_timeout_thresh        = 10,
                                    .txfifo_empty_intr_thresh = 10};

    if (uart_intr_config(uart_port, &uart_intr) != ESP_OK) {
        printf("uart intr config fail\r\n");
        ret = false;
    }

    if (qcloud_iot_at_cmd_regist() == false) {
        printf("regist qcloud iot at cmd fail\r\n");
        ret = false;
    }

    return ret;
}
