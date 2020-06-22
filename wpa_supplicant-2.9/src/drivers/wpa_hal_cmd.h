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

#ifndef _WPA_HAL_CMD_H_
#define _WPA_HAL_CMD_H_

#include <stdint.h>
#include "wpa_hal.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define IFNAMSIZ 16
typedef struct {
    char ifname[IFNAMSIZ + 1];
    uint32_t cmd;
    uint32_t bufLen;
    void *buf;
} IoctlMsgObj;

int32_t WifiWpaEapolPacketSend(const char *ifname, const uint8_t *srcAddr, const uint8_t *dstAddr,
    uint8_t *buf, uint32_t length);
int32_t WifiWpaEapolPacketReceive(const char *ifname, WifiRxEapol *rxEapol);
int32_t WifiWpaEapolEnable(const char *ifname);
int32_t WifiWpaEapolDisable(const char *ifname);

int32_t WifiWpaCmdSetAp(const char *ifname, WifiApSetting *apsettings);
int32_t WifiWpaCmdChangeBeacon(const char *ifname, WifiApSetting *apsettings);
int32_t WifiWpaCmdSendMlme(const char *ifname, WifiMlmeData *mlme);
int32_t WifiWpaCmdNewKey(const char *ifname, WifiKeyExt *keyExt);
int32_t WifiWpaCmdDelKey(const char *ifname, WifiKeyExt *keyExt);
int32_t WifiWpaCmdSetKey(const char *ifname, WifiKeyExt *keyExt);

int32_t WifiWpaCmdSetMode(const char *ifname, WifiSetMode *setMode);
int32_t WifiWpaCmdGetOwnMac(const char *ifname, void *buf, uint32_t len);
int32_t WifiWpaCmdGetHwFeature(const char *ifname, WifiHwFeatureData *hwFeatureData);
int32_t WifiWpaCmdScan(const char *ifname, WifiScan *scan);
int32_t WifiWpaCmdDisconnet(const char *ifname, int32_t reasonCode);
int32_t WifiWpaCmdAssoc(const char *ifname, WifiAssociateParams *assocParams);
int32_t WifiWpaCmdSetMaxStaNum(const char *ifname, void *buf, uint32_t len);
int32_t WifiWpaCmdSetNetdev(const char *ifname, WifiSetNewDev *info);
int32_t WifiWpaCmdStaRemove(const char *ifname, const uint8_t *addr, uint32_t addrLen);
int32_t WifiWpaCmdGetDrvFlags(const char *ifname, void *buf, uint32_t len);
int32_t WifiWpaCmdSendAction(const char *ifname, WifiActionData *actionData);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of wpa_hal_cmd.h */
