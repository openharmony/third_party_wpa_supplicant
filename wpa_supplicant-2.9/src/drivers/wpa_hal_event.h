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
 
#ifndef _WPA_HAL_EVENT_H_
#define _WPA_HAL_EVENT_H_

#include <stdint.h>
#include "message_dispatcher.h"
#include "message_datablock.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define EVENT_BUF_OFFSET 8
#define IFNAMSIZ 16

typedef enum {
    WPA_ELOOP_EVENT_NEW_STA = 0,
    WPA_ELOOP_EVENT_DEL_STA,
    WPA_ELOOP_EVENT_RX_MGMT,
    WPA_ELOOP_EVENT_TX_STATUS,
    WPA_ELOOP_EVENT_SCAN_DONE,
    WPA_ELOOP_EVENT_SCAN_RESULT = 5,
    WPA_ELOOP_EVENT_CONNECT_RESULT,
    WPA_ELOOP_EVENT_DISCONNECT,
    WPA_ELOOP_EVENT_MESH_CLOSE,
    WPA_ELOOP_EVENT_NEW_PEER_CANDIDATE,
    WPA_ELOOP_EVENT_REMAIN_ON_CHANNEL = 10,
    WPA_ELOOP_EVENT_CANCEL_REMAIN_ON_CHANNEL,
    WPA_ELOOP_EVENT_CHANNEL_SWITCH,
    WPA_ELOOP_EVENT_EAPOL_RECV,
    WPA_ELOOP_EVENT_TIMEOUT_DISCONN,
    WPA_ELOOP_EVENT_BUTT
} WpaEloopEventType;

int32_t WifiWpaDriverEventProcess(const char *ifname, int32_t cmd, const DataBlock *reqData);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of wpa_hal_event.h */
