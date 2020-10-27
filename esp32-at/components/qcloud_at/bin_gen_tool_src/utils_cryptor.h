/*
 * Tencent is pleased to support the open source community by making IoT Hub available.
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
#ifndef _UTILS_CRYPTOR_H_
#define _UTILS_CRYPTOR_H_

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SIZE_OF_DEVICE_SECRET       (44)
#define MAX_SIZE_OF_CRYPT_PSK           (64)
#define MAX_SIZE_OF_DEVICE_NAME         (48)
#define MAX_SIZE_OF_PRODUCT_ID          (10)

int update_devinfo(int mode, char *product_id, char *device_name, char *device_sec);


#ifdef __cplusplus
}
#endif
#endif //_UTILS_CRYPTOR_H_