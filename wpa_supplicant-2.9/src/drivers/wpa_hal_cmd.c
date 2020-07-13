/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "wpa_hal_cmd.h"
#include "wpa_hal.h"
#include "message_dispatcher.h"
#include "message_datablock.h"
#include "wpa_hal_service.h"
#include "common.h"
#include "driver.h"
#include "securec.h"
#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t WifiWpaEapolPacketSend(const char *ifname, const uint8_t *srcAddr, const uint8_t *dstAddr, uint8_t *buf,
    uint32_t length)
{
    DataBlock data = { 0 };
    uint32_t cmd = WIFI_WPA_CMD_SEND_EAPOL;
    int32_t ret;

    (void)srcAddr;
    (void)dstAddr;
    if (ifname == NULL || buf == NULL) {
        return -EFAIL;
    }

    if (InitDefaultSizeDataBlock(&data) != ME_SUCCESS) {
        wpa_printf(MSG_INFO, "InitDataBlock failed");
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);
    (void)PushbackSegment(&data, buf, length);

    ret = WifiWpaCmdBlockSyncSend(cmd, &data, NULL);
    DeinitDataBlock(&data);
    return ret;
}

int32_t WifiWpaEapolPacketReceive(const char *ifname, WifiRxEapol *rxEapol)
{
    DataBlock respData = { 0 };
    DataBlock data = { 0 };
    uint32_t cmd = WIFI_WPA_CMD_RECEIVE_EAPOL;
    int32_t ret;
    WifiRxEapol eapol = { 0 };

    if (ifname == NULL || rxEapol == NULL) {
        return -EFAIL;
    }

    if (InitDefaultSizeDataBlock(&data) != ME_SUCCESS) {
        wpa_printf(MSG_ERROR, "InitDataBlock failed");
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);

    ret = WifiWpaCmdBlockSyncSend(cmd, &data, &respData);

    DeinitDataBlock(&data);
    if (ret != ME_SUCCESS) {
        wpa_printf(MSG_ERROR, "WifiWpaEapolPacketReceive failed ret = %d", ret);
        goto RELEASE_DATA;
    }
    if (PopNextSegment(&respData, &(eapol.buf), &(eapol.len)) != ME_SUCCESS) {
        ret = -EFAIL;
        wpa_printf(MSG_ERROR, "WifiWpaEapolPacketReceive PopNextSegment failed");
        goto RELEASE_DATA;
    }

    rxEapol->buf = NULL;
    rxEapol->len = 0;
    if (eapol.len != 0) {
        // wpa free
        rxEapol->buf = os_malloc(eapol.len);
        if (rxEapol->buf == NULL) {
            ret = -EFAIL;
            goto RELEASE_DATA;
        }
        if (memcpy_s(rxEapol->buf, eapol.len, eapol.buf, eapol.len) != EOK) {
            wpa_printf(MSG_ERROR, "memcpy failed");
        }
        rxEapol->len = eapol.len;
    }

RELEASE_DATA:
    DeinitDataBlock(&respData);
    return ret;
}

int32_t WifiWpaEapolEnable(const char *ifname)
{
    DataBlock data = { 0 };
    uint32_t cmd = WIFI_WPA_CMD_ENALBE_EAPOL;
    int32_t ret;

    if (ifname == NULL) {
        return -EFAIL;
    }

    if (InitDefaultSizeDataBlock(&data) != ME_SUCCESS) {
        wpa_printf(MSG_INFO, "InitDataBlock failed");
        return -EFAIL;
    }

    (void)PushbackStringSegment(&data, ifname);

    ret = WifiWpaCmdBlockSyncSend(cmd, &data, NULL);
    DeinitDataBlock(&data);

    return ret;
}

int32_t WifiWpaEapolDisable(const char *ifname)
{
    DataBlock data = { 0 };
    uint32_t cmd = WIFI_WPA_CMD_DISABLE_EAPOL;
    int32_t ret;

    if (ifname == NULL) {
        return -EFAIL;
    }

    if (InitDefaultSizeDataBlock(&data) != ME_SUCCESS) {
        wpa_printf(MSG_INFO, "InitDataBlock failed");
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);

    ret = WifiWpaCmdBlockSyncSend(cmd, &data, NULL);
    DeinitDataBlock(&data);

    return ret;
}

int32_t WifiWpaCmdSetAp(const char *ifname, WifiApSetting *apsettings)
{
    DataBlock data = { 0 };
    uint32_t cmd = WIFI_WPA_CMD_SET_AP;
    int32_t ret;

    if (ifname == NULL || apsettings == NULL) {
        return -EFAIL;
    }

    if (InitDefaultSizeDataBlock(&data) != ME_SUCCESS) {
        wpa_printf(MSG_INFO, "InitDataBlock failed");
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);
    (void)PushbackSegment(&data, apsettings, sizeof(WifiApSetting));
    (void)PushbackSegment(&data, apsettings->beaconData.head, apsettings->beaconData.headLen);
    (void)PushbackSegment(&data, apsettings->beaconData.tail, apsettings->beaconData.tailLen);
    (void)PushbackSegment(&data, apsettings->ssid, apsettings->ssidLen);
    (void)PushbackSegment(&data, apsettings->meshSsid, apsettings->meshSsidLen);

    ret = WifiWpaCmdBlockSyncSend(cmd, &data, NULL);
    DeinitDataBlock(&data);

    return ret;
}

int32_t WifiWpaCmdChangeBeacon(const char *ifname, WifiApSetting *apsettings)
{
    DataBlock data = { 0 };
    uint32_t cmd = WIFI_WPA_CMD_CHANGE_BEACON;
    int32_t ret;

    if (ifname == NULL || apsettings == NULL) {
        return -EFAIL;
    }

    if (InitDefaultSizeDataBlock(&data) != ME_SUCCESS) {
        wpa_printf(MSG_INFO, "InitDataBlock failed");
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);
    (void)PushbackSegment(&data, apsettings, sizeof(WifiApSetting));
    (void)PushbackSegment(&data, apsettings->beaconData.head, apsettings->beaconData.headLen);
    (void)PushbackSegment(&data, apsettings->beaconData.tail, apsettings->beaconData.tailLen);
    (void)PushbackSegment(&data, apsettings->ssid, apsettings->ssidLen);
    (void)PushbackSegment(&data, apsettings->meshSsid, apsettings->meshSsidLen);

    ret = WifiWpaCmdBlockSyncSend(cmd, &data, NULL);
    DeinitDataBlock(&data);

    return ret;
}

int32_t WifiWpaCmdSendMlme(const char *ifname, WifiMlmeData *mlme)
{
    DataBlock data = { 0 };
    uint32_t cmd = WIFI_WPA_CMD_SEND_MLME;
    int32_t ret;

    if (ifname == NULL || mlme == NULL) {
        return -EFAIL;
    }

    if (InitDefaultSizeDataBlock(&data) != ME_SUCCESS) {
        wpa_printf(MSG_INFO, "InitDataBlock failed");
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);
    (void)PushbackSegment(&data, mlme, sizeof(WifiMlmeData));
    (void)PushbackSegment(&data, mlme->data, mlme->dataLen);
    (void)PushbackSegment(&data, mlme->cookie, sizeof(*mlme->cookie));

    ret = WifiWpaCmdBlockSyncSend(cmd, &data, NULL);
    DeinitDataBlock(&data);

    return ret;
}

int32_t WifiWpaCmdNewKey(const char *ifname, WifiKeyExt *keyExt)
{
    DataBlock data = { 0 };
    uint32_t cmd = WIFI_WPA_CMD_NEW_KEY;
    int32_t ret;

    if (ifname == NULL || keyExt == NULL) {
        return -EFAIL;
    }

    if (InitDefaultSizeDataBlock(&data) != ME_SUCCESS) {
        wpa_printf(MSG_INFO, "InitDataBlock failed");
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);
    (void)PushbackSegment(&data, keyExt, sizeof(WifiKeyExt));
    if (keyExt->addr == NULL) {
        (void)PushbackSegment(&data, keyExt->addr, 0);
    } else {
        (void)PushbackSegment(&data, keyExt->addr, ETH_ADDR_LEN);
    }
    (void)PushbackSegment(&data, keyExt->key, keyExt->keyLen);
    (void)PushbackSegment(&data, keyExt->seq, keyExt->seqLen);

    ret = WifiWpaCmdBlockSyncSend(cmd, &data, NULL);
    DeinitDataBlock(&data);

    return ret;
}

int32_t WifiWpaCmdDelKey(const char *ifname, WifiKeyExt *keyExt)
{
    DataBlock data = { 0 };
    uint32_t cmd = WIFI_WPA_CMD_DEL_KEY;
    int32_t ret;

    if (ifname == NULL || keyExt == NULL) {
        return -EFAIL;
    }

    if (InitDefaultSizeDataBlock(&data) != ME_SUCCESS) {
        wpa_printf(MSG_INFO, "InitDataBlock failed");
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);
    (void)PushbackSegment(&data, keyExt, sizeof(WifiKeyExt));
    if (keyExt->addr == NULL) {
        (void)PushbackSegment(&data, keyExt->addr, 0);
    } else {
        (void)PushbackSegment(&data, keyExt->addr, ETH_ADDR_LEN);
    }
    (void)PushbackSegment(&data, keyExt->key, keyExt->keyLen);
    (void)PushbackSegment(&data, keyExt->seq, keyExt->seqLen);

    ret = WifiWpaCmdBlockSyncSend(cmd, &data, NULL);
    DeinitDataBlock(&data);

    return ret;
}

int32_t WifiWpaCmdSetKey(const char *ifname, WifiKeyExt *keyExt)
{
    DataBlock data = { 0 };
    uint32_t cmd = WIFI_WPA_CMD_SET_KEY;
    int32_t ret;

    if (ifname == NULL || keyExt == NULL) {
        return -EFAIL;
    }

    if (InitDefaultSizeDataBlock(&data) != ME_SUCCESS) {
        wpa_printf(MSG_INFO, "InitDataBlock failed");
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);
    (void)PushbackSegment(&data, keyExt, sizeof(WifiKeyExt));
    if (keyExt->addr == NULL) {
        (void)PushbackSegment(&data, keyExt->addr, 0);
    } else {
        (void)PushbackSegment(&data, keyExt->addr, ETH_ADDR_LEN);
    }
    (void)PushbackSegment(&data, keyExt->key, keyExt->keyLen);
    (void)PushbackSegment(&data, keyExt->seq, keyExt->seqLen);

    ret = WifiWpaCmdBlockSyncSend(cmd, &data, NULL);
    DeinitDataBlock(&data);

    return ret;
}

int32_t WifiWpaCmdSetMode(const char *ifname, WifiSetMode *setMode)
{
    if (ifname == NULL || setMode == NULL) {
        return -EFAIL;
    }

    DataBlock data = { 0 };
    if (InitDefaultSizeDataBlock(&data)) {
        return -EFAIL;
    }

    (void)PushbackStringSegment(&data, ifname);
    (void)PushbackSegment(&data, setMode, sizeof(*setMode));
    int ret = WifiWpaCmdBlockSyncSend(WIFI_WPA_CMD_SET_MODE, &data, NULL);
    DeinitDataBlock(&data);
    return ret;
}

int32_t WifiWpaCmdGetOwnMac(const char *ifname, void *buf, uint32_t len)
{
    if (ifname == NULL || buf == NULL) {
        return -EFAIL;
    }
    (void)len;
    DataBlock data = { 0 };
    DataBlock reply = { 0 };
    if (InitDefaultSizeDataBlock(&data)) {
        return -EFAIL;
    }

    (void)PushbackStringSegment(&data, ifname);
    int ret = WifiWpaCmdBlockSyncSend(WIFI_WPA_CMD_GET_ADDR, &data, &reply);
    DeinitDataBlock(&data);
    if (ret) {
        return -EFAIL;
    }
    uint32_t replayDataSize = 0;
    uint8_t *replayData = 0;
    ret = PopNextSegment(&reply, &replayData, &replayDataSize);
    if (ret || replayDataSize != ETH_ADDR_LEN) {
        wpa_printf(MSG_ERROR, "WifiWpaCmdGetOwnMac fail or data size mismatch");
        DeinitDataBlock(&reply);
        return -EFAIL;
    }
    if (memcpy_s(buf, len, replayData, replayDataSize) != EOK) {
        wpa_printf(MSG_ERROR, "%s memcpy failed", __func__);
    }
    DeinitDataBlock(&reply);
    return ret;
}

int32_t WifiWpaCmdGetHwFeature(const char *ifname, WifiHwFeatureData *hwFeatureData)
{
    if (ifname == NULL || hwFeatureData == NULL) {
        return -EFAIL;
    }
    DataBlock data = { 0 };
    DataBlock reply = { 0 };
    if (InitDefaultSizeDataBlock(&data)) {
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);
    int ret = WifiWpaCmdBlockSyncSend(WIFI_WPA_CMD_GET_HW_FEATURE, &data, &reply);
    DeinitDataBlock(&data);
    if (ret) {
        return -EFAIL;
    }
    WifiHwFeatureData *respFeaturenData = NULL;
    uint32_t dataSize = 0;
    ret = PopNextSegment(&reply, &respFeaturenData, &dataSize);
    if (ret || dataSize != sizeof(WifiHwFeatureData)) {
        /* reaponse data size mismatch */
        DeinitDataBlock(&reply);
        return -EFAIL;
    }
    if (memcpy_s(hwFeatureData, sizeof(WifiHwFeatureData), respFeaturenData, dataSize) != EOK) {
        wpa_printf(MSG_ERROR, "%s memcpy failed", __func__);
    }
    DeinitDataBlock(&reply);
    return SUCC;
}

int32_t WifiWpaCmdScan(const char *ifname, WifiScan *scan)
{
    int32_t ret;

    if (ifname == NULL || scan == NULL) {
        return -EFAIL;
    }

    DataBlock data = { 0 };
    if (InitDefaultSizeDataBlock(&data)) {
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);
    uint32_t *currentData = (uint8_t *)(data.data) + data.cursor;
    if (scan->bssid == NULL) {
        (void)PushbackSegment(&data, scan->bssid, 0);
    } else {
        (void)PushbackSegment(&data, scan->bssid, ETH_ADDR_LEN);
    }
    (void)PushbackSegment(&data, scan->ssids, sizeof(scan->ssids[0]) * scan->numSsids);
    (void)PushbackSegment(&data, scan->extraIes, scan->extraIesLen);
    (void)PushbackSegment(&data, scan->freqs, sizeof(scan->freqs[0]) * scan->numFreqs);
    (void)PushbackU8Segment(&data, scan->prefixSsidScanFlag);
    (void)PushbackU8Segment(&data, scan->fastConnectFlag);
    ret = WifiWpaCmdBlockSyncSend(WIFI_WPA_CMD_SCAN, &data, NULL);
    DeinitDataBlock(&data);
    return ret;
}

int32_t WifiWpaCmdDisconnet(const char *ifname, int32_t reasonCode)
{
    if (ifname == NULL) {
        return -EFAIL;
    }

    DataBlock data = { 0 };
    if (InitDefaultSizeDataBlock(&data)) {
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);
    (void)PushbackU16Segment(&data, reasonCode);
    int ret = WifiWpaCmdBlockSyncSend(WIFI_WPA_CMD_DISCONNET, &data, NULL);
    DeinitDataBlock(&data);
    return ret;
}

int32_t WifiWpaCmdAssoc(const char *ifname, WifiAssociateParams *assocParams)
{
    if (ifname == NULL || assocParams == NULL) {
        return -EFAIL;
    }
    DataBlock data = { 0 };
    if (InitDefaultSizeDataBlock(&data)) {
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);
    if (assocParams->bssid == NULL) {
        (void)PushbackSegment(&data, assocParams->bssid, 0);
    } else {
        (void)PushbackSegment(&data, assocParams->bssid, ETH_ADDR_LEN);
    }
    (void)PushbackSegment(&data, assocParams->ssid, assocParams->ssidLen);
    (void)PushbackSegment(&data, assocParams->ie, assocParams->ieLen);
    (void)PushbackSegment(&data, assocParams->key, assocParams->keyLen);
    (void)PushbackU8Segment(&data, assocParams->authType);
    (void)PushbackU8Segment(&data, assocParams->privacy);
    (void)PushbackU8Segment(&data, assocParams->keyIdx);
    (void)PushbackU8Segment(&data, assocParams->mfp);
    (void)PushbackU32Segment(&data, assocParams->freq);
    (void)PushbackSegment(&data, assocParams->crypto, sizeof(assocParams->crypto[0]));
    int ret = WifiWpaCmdBlockSyncSend(WIFI_WPA_CMD_ASSOC, &data, NULL);
    DeinitDataBlock(&data);
    return ret;
}

int32_t WifiWpaCmdSetMaxStaNum(const char *ifname, void *buf, uint32_t len)
{
    if (ifname == NULL || buf == NULL) {
        return -EFAIL;
    }
    (void)len;
    return SUCC;
}

int32_t WifiWpaCmdSetNetdev(const char *ifname, WifiSetNewDev *info)
{
    if (ifname == NULL || info == NULL) {
        return -EFAIL;
    }
    DataBlock data = { 0 };

    if (InitDefaultSizeDataBlock(&data)) {
        return -EFAIL;
    }

    (void)PushbackStringSegment(&data, ifname);
    (void)PushbackSegment(&data, info, sizeof(WifiSetNewDev));
    int ret = WifiWpaCmdBlockSyncSend(WIFI_WPA_CMD_SET_NETDEV, &data, NULL);
    DeinitDataBlock(&data);
    return ret;
}

int32_t WifiWpaCmdStaRemove(const char *ifname, const uint8_t *addr, uint32_t addrLen)
{
    if (ifname == NULL || addr == NULL) {
        return -EFAIL;
    }
    DataBlock data = { 0 };
    if (InitDefaultSizeDataBlock(&data)) {
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);
    (void)PushbackSegment(&data, addr, addrLen);
    int ret = WifiWpaCmdBlockSyncSend(WIFI_WPA_CMD_STA_REMOVE, &data, NULL);
    DeinitDataBlock(&data);
    return ret;
}

int32_t WifiWpaCmdSendAction(const char *ifname, WifiActionData *actionData)
{
    if (ifname == NULL || actionData == NULL) {
        return -EFAIL;
    }
    DataBlock data = { 0 };
    if (InitDefaultSizeDataBlock(&data)) {
        return -EFAIL;
    }
    (void)PushbackStringSegment(&data, ifname);
    if (actionData->bssid == NULL) {
        (void)PushbackSegment(&data, actionData->bssid, 0);
    } else {
        (void)PushbackSegment(&data, actionData->bssid, ETH_ADDR_LEN);
    }
    if (actionData->dst == NULL) {
        (void)PushbackSegment(&data, actionData->dst, 0);
    } else {
        (void)PushbackSegment(&data, actionData->dst, ETH_ADDR_LEN);
    }
    if (actionData->src == NULL) {
        (void)PushbackSegment(&data, actionData->src, 0);
    } else {
        (void)PushbackSegment(&data, actionData->src, ETH_ADDR_LEN);
    }
    (void)PushbackSegment(&data, actionData->data, actionData->dataLen);
    int ret = WifiWpaCmdBlockSyncSend(WIFI_WPA_CMD_SEND_ACTION, &data, NULL);
    DeinitDataBlock(&data);
    return ret;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
