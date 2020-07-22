/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _WPA_MSG_SERVICE_H_
#define _WPA_MSG_SERVICE_H_

#include <stdlib.h>
#include "hdf_sbuf.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define WPA_MSG_SERVICE_ID 0x3
#define WAL_MSG_SERVICE_ID 0x4

#define WIFI_WPA_EVENT_MSG 0

int32_t WpaMsgServiceInit(void);
void WpaMsgServiceDeinit(void);
int32_t WifiWpaCmdBlockSyncSend(const uint32_t cmd, struct HdfSBuf *data, struct HdfSBuf *respData);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif


#endif /* end of wpa_msg_sevice.h */
