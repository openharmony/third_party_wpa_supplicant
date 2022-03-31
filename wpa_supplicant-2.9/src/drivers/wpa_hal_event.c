/*
 * Driver interaction with hdf wifi
 * Copyright (c) 2020 Huawei Device Co., Ltd.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <stdlib.h>
#include <string.h>
#include "utils/common.h"
#include "driver.h"
#include "eloop.h"
#include "l2_packet/l2_packet.h"
#include "wpa_hal.h"
#include "wpa_supplicant_i.h"
#include "securec.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

static void WpaMemFree(void *mem)
{
    if (mem != NULL) {
        free(mem);
    }
}

static inline int IsZeroAddr(const uint8_t *addr, const uint8_t len)
{
    if (len != ETH_ADDR_LEN) {
        return -EFAIL;
    }
    // 0 1 2 3 4 5 : mac index
    return !(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]);
}

static void WifiWpaEventNewStaProcess(void *ctx, void *data)
{
    if (ctx == NULL || data == NULL) {
        return;
    }
    WifiDriverData *drv = (WifiDriverData *)ctx;
    WifiNewStaInfo *staInfo = (WifiNewStaInfo *)data;
    union wpa_event_data event;

    (void)memset_s(&event, sizeof(union wpa_event_data), 0, sizeof(union wpa_event_data));
    if (IsZeroAddr(staInfo->macAddr, ETH_ADDR_LEN)) {
        wpa_supplicant_event(drv->ctx, EVENT_DISASSOC, NULL);
    } else {
        event.assoc_info.reassoc     = staInfo->reassoc;
        event.assoc_info.req_ies     = staInfo->ie;
        event.assoc_info.req_ies_len = staInfo->ieLen;
        event.assoc_info.addr        = staInfo->macAddr;
        wpa_supplicant_event(drv->ctx, EVENT_ASSOC, &event);
    }
    WpaMemFree(staInfo->ie);
    WpaMemFree(staInfo->macAddr);
    WpaMemFree(staInfo);
    wpa_printf(MSG_INFO, "WifiWpaEventNewStaProcess done");
}

static void WifiWpaEventDelStaProcess(void *ctx, void *data)
{
    if (ctx == NULL || data == NULL) {
        return;
    }
    wpa_printf(MSG_INFO, "WifiWpaEventDelStaProcess enter.");
    WifiDriverData *drv = (WifiDriverData *)ctx;
    uint8_t *addr = (uint8_t *)data;
    union wpa_event_data event;
    struct wpa_supplicant *wpa_s = (struct wpa_supplicant *)drv->ctx;
    if (wpa_s == NULL || wpa_s->disconnected == 1) {
        wpa_printf(MSG_INFO, "WifiWpaEventDelStaProcess: already disconnected, return.");
        return;
    }
    (void)memset_s(&event, sizeof(union wpa_event_data), 0, sizeof(union wpa_event_data));
    event.disassoc_info.addr = addr;
    if (drv->ctx != NULL) {
        wpa_supplicant_event(drv->ctx, EVENT_DISASSOC, &event);
        wpa_printf(MSG_INFO, "WifiWpaEventDelStaProcess done.");
    }
    WpaMemFree(addr);
}

static void WifiWpaEventRxMgmtProcess(void *ctx, void *data)
{
    if (ctx == NULL || data == NULL) {
        return;
    }
    WifiDriverData *drv = (WifiDriverData *)ctx;
    WifiRxMgmt *rxMgmt = (WifiRxMgmt *)data;
    union wpa_event_data event;

    (void)memset_s(&event, sizeof(union wpa_event_data), 0, sizeof(union wpa_event_data));
    event.rx_mgmt.frame = rxMgmt->buf;
    event.rx_mgmt.frame_len = rxMgmt->len;
    event.rx_mgmt.ssi_signal = rxMgmt->sigMbm;
    event.rx_mgmt.freq = rxMgmt->freq;

    wpa_supplicant_event(drv->ctx, EVENT_RX_MGMT, &event);
    WpaMemFree(rxMgmt->buf);
    WpaMemFree(rxMgmt);
    wpa_printf(MSG_INFO, "WifiWpaEventRxMgmtProcess done");
}

static void WifiWpaEventTxStatusProcess(void *ctx, void *data)
{
    if (ctx == NULL || data == NULL) {
        return;
    }
    WifiDriverData *drv = (WifiDriverData *)ctx;
    WifiTxStatus *txStatus = (WifiTxStatus *)data;
    uint16_t fc;
    struct ieee80211_hdr *hdr = NULL;
    union wpa_event_data event;

    (void)memset_s(&event, sizeof(union wpa_event_data), 0, sizeof(union wpa_event_data));
    hdr = (struct ieee80211_hdr *)txStatus->buf;
    fc = le_to_host16(hdr->frame_control);
    event.tx_status.type = WLAN_FC_GET_TYPE(fc);
    event.tx_status.stype = WLAN_FC_GET_STYPE(fc);
    event.tx_status.dst = hdr->addr1;
    event.tx_status.data = txStatus->buf;
    event.tx_status.data_len = txStatus->len;
    event.tx_status.ack = (txStatus->ack != FALSE);

    wpa_supplicant_event(drv->ctx, EVENT_TX_STATUS, &event);
    WpaMemFree(txStatus->buf);
    WpaMemFree(txStatus);
    wpa_printf(MSG_INFO, "WifiWpaEventTxStatusProcess done");
}

static void WifiWpaEventScanDoneProcess(void *ctx, void *data)
{
    if (ctx == NULL || data == NULL) {
        return;
    }
    WifiDriverData *drv = (WifiDriverData *)ctx;
    uint32_t *status = (uint32_t *)data;
    if (drv->ctx == NULL) {
        wpa_printf(MSG_ERROR, "%s: ctx is null", __func__);
        goto failed;
    }
    eloop_cancel_timeout(WifiWpaScanTimeout, drv, drv->ctx);
    if (*status != WIFI_SCAN_SUCCESS) {
        goto failed;
    }
    wpa_supplicant_event(drv->ctx, EVENT_SCAN_RESULTS, NULL);
    wpa_printf(MSG_INFO, "WifiWpaEventScanDoneProcess done");

failed:
    WpaMemFree(status);
}

static void WifiWpaEventScanResultProcess(void *ctx, void *data)
{
    if (ctx == NULL || data == NULL) {
        return;
    }
    WifiDriverData *drv = (WifiDriverData *)ctx;
    WifiScanResult *scanResult = (WifiScanResult *)data;
    struct wpa_scan_res *res = NULL;
    errno_t rc;

    wpa_printf(MSG_INFO, "%s: ie_len=%d, beacon_ie_len=%d", __func__, scanResult->ieLen, scanResult->beaconIeLen);
    res = (struct wpa_scan_res *)os_zalloc(sizeof(struct wpa_scan_res) + scanResult->ieLen + scanResult->beaconIeLen);
    if (res == NULL) {
        goto failed;
    }
    res->flags      = scanResult->flags;
    res->freq       = scanResult->freq;
    res->caps       = scanResult->caps;
    res->beacon_int = scanResult->beaconInt;
    res->qual       = 0;
    res->level      = scanResult->level;
    res->level /= 100;  /* mBm to dBm */
    res->age        = 0;
    res->ie_len     = scanResult->ieLen;
    res->beacon_ie_len = scanResult->beaconIeLen;
    rc = memcpy_s(res->bssid, ETH_ADDR_LEN, scanResult->bssid, ETH_ADDR_LEN);
    if (rc != EOK) {
        goto failed;
    }
    rc = memcpy_s(&res[1], scanResult->ieLen, scanResult->ie, scanResult->ieLen);
    if (rc != EOK) {
        goto failed;
    }
    rc = memcpy_s(((uint8_t *)(&res[1]) + scanResult->ieLen), scanResult->beaconIeLen, scanResult->beaconIe, scanResult->beaconIeLen);
    if (rc != EOK) {
        goto failed;
    }
    if (drv->scanNum >= SCAN_AP_LIMIT) {
        wpa_printf(MSG_ERROR, "WifiWpaEventScanResultProcess: drv->scanNum >= SCAN_AP_LIMIT");
        goto failed;
    }
    drv->scanRes[drv->scanNum++] = res;
    WpaMemFree(scanResult->ie);
    WpaMemFree(scanResult->bssid);
    WpaMemFree(scanResult->beaconIe);
    WpaMemFree(scanResult);
    wpa_printf(MSG_INFO, "WifiWpaEventScanResultProcess done");
    return;

failed:
    if (res != NULL) {
        os_free(res);
        res = NULL;
    }
    WpaMemFree(scanResult->ie);
    WpaMemFree(scanResult->bssid);
    WpaMemFree(scanResult->beaconIe);
    WpaMemFree(scanResult);
}

static void WifiWpaEventConnectResultProcess(void *ctx, void *data)
{
    if (ctx == NULL || data == NULL) {
        return;
    }
    WifiDriverData *drv = (WifiDriverData *)ctx;
    WifiConnectResult *result = (WifiConnectResult *)data;
    union wpa_event_data event;
    errno_t rc;

    (void)memset_s(&event, sizeof(union wpa_event_data), 0, sizeof(union wpa_event_data));
    if (result->status != 0) {
        drv->associated = WIFI_DISCONNECT;
        wpa_supplicant_event(drv->ctx, EVENT_DISASSOC, NULL);
    } else {
        drv->associated = WIFI_CONNECT;
        rc = memcpy_s(drv->bssid, ETH_ADDR_LEN, result->bssid, ETH_ALEN);
        if (rc != EOK) {
            goto failed;
        }
        event.assoc_info.req_ies      = result->reqIe;
        event.assoc_info.req_ies_len  = result->reqIeLen;
        event.assoc_info.resp_ies     = result->respIe;
        event.assoc_info.resp_ies_len = result->respIeLen;
        event.assoc_info.addr         = result->bssid;
        event.assoc_info.freq         = result->freq;
        wpa_supplicant_event(drv->ctx, EVENT_ASSOC, &event);
    }
    wpa_printf(MSG_INFO, "WifiWpaEventConnectResultProcess done");

failed:
    WpaMemFree(result->bssid);
    WpaMemFree(result->reqIe);
    WpaMemFree(result->respIe);
    WpaMemFree(result);
}

static void WifiWpaEventDisconnectProcess(void *ctx, void *data)
{
    if (ctx == NULL || data == NULL) {
        return;
    }
    wpa_printf(MSG_INFO, "WifiWpaEventDisconnectProcess enter.");
    WifiDriverData *drv = (WifiDriverData *)ctx;
    WifiDisconnect *result = (WifiDisconnect *)data;
    union wpa_event_data event;
    struct wpa_supplicant *wpa_s = (struct wpa_supplicant *)drv->ctx;
    if (wpa_s == NULL || wpa_s->disconnected == 1) {
        wpa_printf(MSG_INFO, "WifiWpaEventDisconnectProcess: already disconnected, return.");
        return;
    }

    (void)memset_s(&event, sizeof(union wpa_event_data), 0, sizeof(union wpa_event_data));
    drv->associated = WIFI_DISCONNECT;
    event.disassoc_info.reason_code = result->reason;
    event.disassoc_info.ie          = result->ie;
    event.disassoc_info.ie_len      = result->ieLen;
    wpa_supplicant_event(drv->ctx, EVENT_DISASSOC, &event);
    wpa_printf(MSG_INFO, "WifiWpaEventDisconnectProcess done");
    WpaMemFree(result->ie);
    WpaMemFree(result);
}

extern void l2_packet_receive(void *eloop_ctx, void *sock_ctx);
static inline void WifiWpaDriverEventEapolRecvProcess(void *ctx, void *data)
{
    WifiDriverData *drv = (WifiDriverData *)ctx;
    wpa_printf(MSG_INFO, "WifiWpaDriverEventEapolRecvProcess call");
    eloop_register_timeout(0, 0, l2_packet_receive, drv->eapolSock, NULL);
}

static void WifiWpaEventRemainOnChannelProcess(void *ctx, void *data)
{
    if (ctx == NULL || data == NULL) {
        return;
    }
    WifiDriverData *drv = (WifiDriverData *)ctx;
    WifiOnChannel *result = (WifiOnChannel *)data;
    union wpa_event_data event;
    (void)memset_s(&event, sizeof(union wpa_event_data), 0, sizeof(union wpa_event_data));

    event.remain_on_channel.freq = result->freq;
    event.remain_on_channel.duration = result->duration;
    wpa_supplicant_event(drv->ctx, EVENT_REMAIN_ON_CHANNEL, &event);
    wpa_printf(MSG_INFO, "%s done.", __FUNCTION__);
    WpaMemFree(result);
}

static void WifiWpaEventCancelRemainOnChannelProcess(void *ctx, void *data)
{
    if (ctx == NULL || data == NULL) {
        return;
    }
    WifiDriverData *drv = (WifiDriverData *)ctx;
    WifiOnChannel *result = (WifiOnChannel *)data;
    union wpa_event_data event;
    (void)memset_s(&event, sizeof(union wpa_event_data), 0, sizeof(union wpa_event_data));

    event.remain_on_channel.freq = result->freq;
    wpa_supplicant_event(drv->ctx, EVENT_CANCEL_REMAIN_ON_CHANNEL, &event);
    wpa_printf(MSG_INFO, "%s done.", __FUNCTION__);
    WpaMemFree(result);
}
static int32_t AllocAndCopyIe(uint8_t *dstIe, uint32_t ieLen, uint8_t *srcIe)
{
    int32_t ret = 0;
    if (ieLen == 0) {
        dstIe = NULL;
        return SUCC;
    }
    dstIe = (uint8_t *)os_zalloc(ieLen);
    if (dstIe == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        return -EFAIL;
    }
    ret = memcpy_s(dstIe, ieLen, srcIe, ieLen);
    if (ret != SUCC) {
        WpaMemFree(dstIe);
        return -EFAIL;
    }
	return SUCC;
}

void WifiWpaNewStaProcess(WifiDriverData *drv, WifiNewStaInfo *staInfo)
{
    WifiNewStaInfo *copyStaInfo = NULL;
    uint8_t *ie = NULL;
    uint8_t *macAddr = NULL;
    int ret = 0;

    copyStaInfo = (WifiNewStaInfo *)os_zalloc(sizeof(WifiNewStaInfo));
    if (copyStaInfo == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        return;
    }
    ie = (uint8_t *)os_zalloc(staInfo->ieLen);
    if (ie == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        goto failed3;
    }
    ret = memcpy_s(ie, staInfo->ieLen, staInfo->ie, staInfo->ieLen);
    if (ret != SUCC) {
        goto failed2;
    }
    macAddr = (uint8_t *)os_zalloc(ETH_ADDR_LEN);
    if (macAddr == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        goto failed2;
    }
    ret = memcpy_s(macAddr, ETH_ADDR_LEN, staInfo->macAddr, ETH_ADDR_LEN);
    if (ret != SUCC) {
        goto failed1;
    }

    copyStaInfo->reassoc     = staInfo->reassoc;
    copyStaInfo->ie     = ie;
    copyStaInfo->ieLen = staInfo->ieLen;
    copyStaInfo->macAddr        = macAddr;
    eloop_register_timeout(0, 0, WifiWpaEventNewStaProcess, drv, copyStaInfo);
    return;

failed1:
    WpaMemFree(macAddr);
failed2:
    WpaMemFree(ie);
failed3:
    WpaMemFree(copyStaInfo);
}

void WifiWpaDelStaProcess(WifiDriverData *drv, uint8_t *addr)
{
    uint8_t *copyAddr = NULL;
    int ret = 0;

    copyAddr = (uint8_t *)os_zalloc(sizeof(ETH_ADDR_LEN));
    if (copyAddr == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        return;
    }
    ret = memcpy_s(copyAddr, ETH_ADDR_LEN, addr, ETH_ADDR_LEN);
    if (ret != SUCC) {
        WpaMemFree(copyAddr);
        return;
    }
    eloop_register_timeout(0, 0, WifiWpaEventDelStaProcess, drv, copyAddr);
}

void WifiWpaRxMgmtProcess(WifiDriverData *drv, WifiRxMgmt *rxMgmt)
{
    WifiRxMgmt *copyRxMgmt = NULL;
    uint8_t *buf = NULL;
    int ret = 0;

    copyRxMgmt = (WifiRxMgmt *)os_zalloc(sizeof(WifiRxMgmt));
    if (copyRxMgmt == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        return;
    }
    buf = (uint8_t *)os_zalloc(rxMgmt->len);
    if (buf == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        WpaMemFree(copyRxMgmt);
        return;
    }
    ret = memcpy_s(buf, rxMgmt->len, rxMgmt->buf, rxMgmt->len);
    if (ret != SUCC) {
        WpaMemFree(copyRxMgmt);
        WpaMemFree(buf);
        return;
    }
    copyRxMgmt->buf = buf;
    copyRxMgmt->len = rxMgmt->len;
    copyRxMgmt->sigMbm = rxMgmt->sigMbm;
    copyRxMgmt->freq = rxMgmt->freq;
    eloop_register_timeout(0, 0, WifiWpaEventRxMgmtProcess, drv, copyRxMgmt);
}

void WifiWpaTxStatusProcess(WifiDriverData *drv, WifiTxStatus *txStatus)
{
    WifiTxStatus *copyTxStatus = NULL;
    uint8_t *buf = NULL;
    int ret = 0;

    copyTxStatus = (WifiTxStatus *)os_zalloc(sizeof(WifiTxStatus));
    if (copyTxStatus == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        return;
    }
    buf = (uint8_t *)os_zalloc(txStatus->len);
    if (buf == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        WpaMemFree(copyTxStatus);
        return;
    }
    ret = memcpy_s(buf, txStatus->len, txStatus->buf, txStatus->len);
    if (ret != SUCC) {
        WpaMemFree(copyTxStatus);
        WpaMemFree(buf);
        return;
    }
    copyTxStatus->buf = buf;
    copyTxStatus->ack = txStatus->ack;
    copyTxStatus->len = txStatus->len;
    eloop_register_timeout(0, 0, WifiWpaEventTxStatusProcess, drv, copyTxStatus);
}

void WifiWpaScanDoneProcess(WifiDriverData *drv, uint32_t *status)
{
    uint32_t *copyStatus = NULL;
    int ret = 0;

    copyStatus = (uint32_t *)os_zalloc(sizeof(uint32_t));
    if (copyStatus == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        return;
    }
    ret = memcpy_s(copyStatus, sizeof(uint32_t), status, sizeof(uint32_t));
    if (ret != SUCC) {
        WpaMemFree(copyStatus);
        return;
    }
    eloop_register_timeout(0, 0, WifiWpaEventScanDoneProcess, drv, copyStatus);
}

void WifiWpaScanResultProcess(WifiDriverData *drv, WifiScanResult *scanResult)
{
    WifiScanResult *copyScanResult = NULL;
    uint8_t *ie = NULL;
    uint8_t *beaconIe = NULL;
    uint8_t *bssid = NULL;
    int ret = 0;

    copyScanResult = (WifiScanResult *)os_zalloc(sizeof(WifiScanResult));
    if (copyScanResult == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        return;
    }
    bssid = (uint8_t *)os_zalloc(ETH_ADDR_LEN);
    if (bssid == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        goto failed4;
    }
    ret = memcpy_s(bssid, ETH_ADDR_LEN, scanResult->bssid, ETH_ADDR_LEN);
    if (ret != SUCC) {
        goto failed3;
    }

    ie = (uint8_t *)os_zalloc(scanResult->ieLen);
    if (ie == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        goto failed3;
    }
    ret = memcpy_s(ie, scanResult->ieLen, scanResult->ie, scanResult->ieLen);
    if (ret != SUCC) {
        goto failed2;
    }

    beaconIe = (uint8_t *)os_zalloc(scanResult->beaconIeLen);
    if (beaconIe == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        goto failed2;
    }
    ret = memcpy_s(beaconIe, scanResult->beaconIeLen, scanResult->beaconIe, scanResult->beaconIeLen);
    if (ret != SUCC) {
        goto failed1;
    }

    copyScanResult->flags      = scanResult->flags;
    copyScanResult->freq       = scanResult->freq;
    copyScanResult->caps       = scanResult->caps;
    copyScanResult->beaconInt = scanResult->beaconInt;
    copyScanResult->level      = scanResult->level;
    copyScanResult->ieLen     = scanResult->ieLen;
    copyScanResult->beaconIeLen = scanResult->beaconIeLen;
    copyScanResult->bssid = bssid;
    copyScanResult->ie = ie;
    copyScanResult->beaconIe = beaconIe;
    eloop_register_timeout(0, 0, WifiWpaEventScanResultProcess, drv, copyScanResult);
    return;

failed1:
    WpaMemFree(beaconIe);
failed2:
    WpaMemFree(ie);
failed3:
    WpaMemFree(bssid);
failed4:
    WpaMemFree(copyScanResult);
}

void WifiWpaConnectResultProcess(WifiDriverData *drv, WifiConnectResult *result)
{
    WifiConnectResult *copyResult = NULL;
    uint8_t *reqIe = NULL;
    uint8_t *respIe = NULL;
    uint8_t *bssid = NULL;
    int ret = 0;

    copyResult = (WifiConnectResult *)os_zalloc(sizeof(WifiConnectResult));
    if (copyResult == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        return;
    }
    bssid = (uint8_t *)os_zalloc(ETH_ADDR_LEN);
    if (bssid == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        goto failed4;
    }
    ret = memcpy_s(bssid, ETH_ADDR_LEN, result->bssid, ETH_ADDR_LEN);
    if (ret != SUCC) {
        goto failed3;
    }

    reqIe = (uint8_t *)os_zalloc(result->reqIeLen);
    if (reqIe == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        goto failed3;
    }
    ret = memcpy_s(reqIe, result->reqIeLen, result->reqIe, result->reqIeLen);
    if (ret != SUCC) {
        goto failed2;
    }

    respIe = (uint8_t *)os_zalloc(result->respIeLen);
    if (respIe == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        goto failed2;
    }
    ret = memcpy_s(respIe, result->respIeLen, result->respIe, result->respIeLen);
    if (ret != SUCC) {
        goto failed1;
    }

    copyResult->status = result->status;
    copyResult->freq = result->freq;
    copyResult->reqIeLen = result->reqIeLen;
    copyResult->respIeLen = result->respIeLen;
    copyResult->reqIe = reqIe;
    copyResult->respIe = respIe;
    copyResult->bssid = bssid;
    eloop_register_timeout(0, 0, WifiWpaEventConnectResultProcess, drv, copyResult);
    return;

failed1:
    WpaMemFree(respIe);
failed2:
    WpaMemFree(reqIe);
failed3:
    WpaMemFree(bssid);
failed4:
    WpaMemFree(copyResult);
}

void WifiWpaDisconnectProcess(WifiDriverData *drv, WifiDisconnect *result)
{
    WifiDisconnect *copyResult = NULL;
    uint8_t *ie = NULL;
    int32_t ret = 0;

    copyResult = (WifiDisconnect *)os_zalloc(sizeof(WifiDisconnect));
    if (copyResult == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        return;
    }
    ret = AllocAndCopyIe(ie, result->ieLen, result->ie);
    if (ret != SUCC) {
        WpaMemFree(copyResult);
        return;
    }
    copyResult->ie = ie;
    copyResult->ieLen = result->ieLen;
    copyResult->reason = result->reason;
    eloop_register_timeout(0, 0, WifiWpaEventDisconnectProcess, drv, copyResult);
}

void WifiWpaDriverEapolRecvProcess(WifiDriverData *drv, void *data)
{
    eloop_register_timeout(0, 0, WifiWpaDriverEventEapolRecvProcess, drv, data);
}

void WifiWpaRemainOnChannelProcess(WifiDriverData *drv, WifiOnChannel *result)
{
    WifiOnChannel *copyResult = NULL;

    copyResult = (WifiOnChannel *)os_zalloc(sizeof(WifiOnChannel));
    if (copyResult == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        return;
    }
    copyResult->freq = result->freq;
    copyResult->duration = result->duration;
    eloop_register_timeout(0, 0, WifiWpaEventRemainOnChannelProcess, drv, copyResult);
}

void WifiWpaCancelRemainOnChannelProcess(WifiDriverData *drv, WifiOnChannel *result)
{
    WifiOnChannel *copyResult = NULL;

    copyResult = (WifiOnChannel *)os_zalloc(sizeof(WifiOnChannel));
    if (copyResult == NULL) {
        wpa_printf(MSG_ERROR, "%s fail: os_zalloc fail!", __func__);
        return;
    }
    copyResult->freq = result->freq;
    eloop_register_timeout(0, 0, WifiWpaEventCancelRemainOnChannelProcess, drv, copyResult);
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
