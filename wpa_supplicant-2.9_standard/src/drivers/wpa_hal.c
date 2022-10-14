/*
 * Driver interaction with hdf wifi
 * Copyright (c) 2020 Huawei Device Co., Ltd.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "wpa_hal.h"
#include "includes.h"
#include "utils/common.h"
#include "driver.h"
#include "ap/hostapd.h"
#include "l2_packet/l2_packet.h"
#include "eloop.h"
#include "securec.h"
#include <dirent.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

WifiDriverData *g_wifiDriverData = NULL;
enum WifiIfType g_wifiDriverType = WIFI_IFTYPE_UNSPECIFIED;
#define WAIT_LOAD_NETDEVICE 2500
#ifdef CONFIG_OHOS_P2P
uint8_t g_msgInit = TRUE;
#endif

WifiDriverData *GetDrvData()
{
    return g_wifiDriverData;
}

#ifdef CONFIG_OHOS_P2P
#define WPA_MAX_WIFI_DEV_NUM 3

WifiDev* g_wifiDev[WPA_MAX_WIFI_DEV_NUM] = {NULL};

WifiDev* GetWifiDevByName(const char *ifName)
{
    int32_t i;
    if (ifName == NULL) {
        return NULL;
    }
    for (i = 0; i < WPA_MAX_WIFI_DEV_NUM; i++) {
        if ((g_wifiDev[i] != NULL) && (strncmp(g_wifiDev[i]->ifName, ifName, strlen(ifName)) == 0)) {
            g_wifiDev[i]->networkId = i;
            return g_wifiDev[i];
        }
    }
    return NULL;
}

int32_t SetWifiDev(WifiDev *wifiDev)
{
    int32_t i;
    if (wifiDev == NULL) {
        return -EFAIL;
    }
    for (i = 0; i < WPA_MAX_WIFI_DEV_NUM; i++) {
        if ((g_wifiDev[i] != NULL) && (strncmp(g_wifiDev[i]->ifName, wifiDev->ifName, strlen(wifiDev->ifName)) == 0)) {
            g_wifiDev[i] = wifiDev;
            return SUCC;
        } else if (g_wifiDev[i] == NULL) {
            g_wifiDev[i] = wifiDev;
            g_wifiDev[i]->networkId = i;
            return SUCC;
        }
    }
    return -EFAIL;
}

void FreeWifiDev(WifiDev *wifiDev)
{
    int32_t i;
    if (wifiDev == NULL) {
        return;
    }
    for (i = 0; i < WPA_MAX_WIFI_DEV_NUM; i++) {
        if (g_wifiDev[i] == wifiDev) {
            g_wifiDev[i] = NULL;
            break;
        }
    }
    os_free(wifiDev);
    wifiDev = NULL;
}

int32_t CountWifiDevInUse()
{
    int32_t i;
    int32_t count = 0;
    for (i = 0; i < WPA_MAX_WIFI_DEV_NUM; i++) {
        if (g_wifiDev[i] != NULL) {
            count++;
        }
    }
    return count;
}
#endif // CONFIG_OHOS_P2P

static int OnWpaWiFiEvents(uint32_t event, void *data, const char *ifName)
{
    WifiDriverData *drv = NULL;
#ifndef CONFIG_OHOS_P2P
    drv = GetDrvData();
#else
    WifiDev *wifiDev = NULL;
    wifiDev = GetWifiDevByName(ifName);
    if (wifiDev == NULL) {
        wpa_printf(MSG_ERROR, "OnWpaWiFiEvents wifiDev is null\n");
        return -EFAIL;
    }
    drv = wifiDev->priv;
#endif
    (void)ifName;
    wpa_printf(MSG_INFO, "OnWpaWiFiEvents event=%d", event);
    if (drv == NULL || data == NULL) {
        return -EFAIL;
    }
    switch (event) {
        case WIFI_EVENT_NEW_STA:
            WifiWpaNewStaProcess(drv, (WifiNewStaInfo *)data);
            break;
        case WIFI_EVENT_DEL_STA:
            WifiWpaDelStaProcess(drv, (uint8_t *)data);
            break;
        case WIFI_EVENT_RX_MGMT:
            WifiWpaRxMgmtProcess(drv, (WifiRxMgmt *)data);
            break;
        case WIFI_EVENT_TX_STATUS:
            WifiWpaTxStatusProcess(drv, (WifiTxStatus *)data);
            break;
        case WIFI_EVENT_SCAN_DONE:
            WifiWpaScanDoneProcess(drv, (uint32_t *)data);
            break;
        case WIFI_EVENT_SCAN_RESULT:
            WifiWpaScanResultProcess(drv, (WifiScanResult *)data);
            break;
        case WIFI_EVENT_CONNECT_RESULT:
            WifiWpaConnectResultProcess(drv, (WifiConnectResult *)data);
            break;
        case WIFI_EVENT_DISCONNECT:
            WifiWpaDisconnectProcess(drv, (WifiDisconnect *)data);
            break;
        case WIFI_EVENT_EAPOL_RECV:
            WifiWpaDriverEapolRecvProcess(drv, data);
            break;
        case WIFI_EVENT_REMAIN_ON_CHANNEL:
            WifiWpaRemainOnChannelProcess(drv, (WifiOnChannel *)data);
            break;
        case WIFI_EVENT_CANCEL_REMAIN_ON_CHANNEL:
            WifiWpaCancelRemainOnChannelProcess(drv, (WifiOnChannel *)data);
            break;
        default:
            break;
    }

    return SUCC;
}

static int32_t WifiClientInit(const char *ifName)
{
    int32_t ret;

    wpa_printf(MSG_INFO, "WifiClientInit enter.");
    ret = WifiDriverClientInit();
    if (ret != SUCC) {
        wpa_printf(MSG_ERROR, "WifiWpa init msg service failed");
        return ret;
    }
    ret = WifiRegisterEventCallback(OnWpaWiFiEvents, WIFI_KERNEL_TO_WPA_CLIENT, ifName);
    if (ret != SUCC) {
        wpa_printf(MSG_ERROR, "WifiWpa register event listener faild");
    }
    return ret;
}

void WifiClientDeinit(const char *ifName)
{
    WifiUnregisterEventCallback(OnWpaWiFiEvents, WIFI_KERNEL_TO_WPA_CLIENT, ifName);
    WifiDriverClientDeinit();
}

static int32_t WifiWpaGetBssid(void *priv, uint8_t *bssid)
{
    WifiDriverData *drv = priv;
    errno_t rc;
    if ((priv == NULL) || (bssid == NULL)) {
        return -EFAIL;
    }
    if (drv->associated == WIFI_DISCONNECT) {
        wpa_printf(MSG_ERROR, "%s associated status error", __func__);
        return -EFAIL;
    }

    rc = memcpy_s(bssid, ETH_ADDR_LEN, drv->bssid, ETH_ADDR_LEN);
    if (rc != EOK) {
        return -EFAIL;
    }
    return SUCC;
}

static int32_t WifiWpaGetSsid(void *priv, uint8_t *ssid)
{
    WifiDriverData *drv = priv;
    errno_t rc;
    if ((priv == NULL) || (ssid == NULL)) {
        return -EFAIL;
    }
    if (drv->associated == WIFI_DISCONNECT) {
        wpa_printf(MSG_ERROR, "%s associated status error", __func__);
        return -EFAIL;
    }
    rc = memcpy_s(ssid, MAX_SSID_LEN, drv->ssid, drv->ssidLen);
    if (rc != EOK) {
        return -EFAIL;
    }
    return drv->ssidLen;
}

static uint32_t WifiAlgToCipherSuite(enum wpa_alg alg, size_t keyLen)
{
    switch (alg) {
        case WPA_ALG_WEP:
            if (keyLen == WPA_WEP40_KEY_LEN) {
                return RSN_CIPHER_SUITE_WEP40;
            }
            return RSN_CIPHER_SUITE_WEP104;
        case WPA_ALG_TKIP:
            return RSN_CIPHER_SUITE_TKIP;
        case WPA_ALG_CCMP:
            return RSN_CIPHER_SUITE_CCMP;
        case WPA_ALG_GCMP:
            return RSN_CIPHER_SUITE_GCMP;
        case WPA_ALG_CCMP_256:
            return RSN_CIPHER_SUITE_CCMP_256;
        case WPA_ALG_GCMP_256:
            return RSN_CIPHER_SUITE_GCMP_256;
        case WPA_ALG_IGTK:
            return RSN_CIPHER_SUITE_AES_128_CMAC;
        case WPA_ALG_BIP_GMAC_128:
            return RSN_CIPHER_SUITE_BIP_GMAC_128;
        case WPA_ALG_BIP_GMAC_256:
            return RSN_CIPHER_SUITE_BIP_GMAC_256;
        case WPA_ALG_BIP_CMAC_256:
            return RSN_CIPHER_SUITE_BIP_CMAC_256;
        case WPA_ALG_SMS4:
            return RSN_CIPHER_SUITE_SMS4;
        case WPA_ALG_KRK:
            return RSN_CIPHER_SUITE_KRK;
        case WPA_ALG_NONE:
        case WPA_ALG_PMK:
            return 0;
        default:
            return 0;
    }
}

static inline int IsBroadcastAddr(const uint8_t *addr)
{
    // 0 1 2 3 4 5 are mac index
    return (addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff;
}

static void WifiWpaInitAlg(WifiKeyExt *keyExt, enum wpa_alg alg, size_t keyLen)
{
    keyExt->cipher = WifiAlgToCipherSuite(alg, keyLen);
    if ((alg == WPA_ALG_IGTK) || (alg == WPA_ALG_BIP_GMAC_128) || (alg == WPA_ALG_BIP_GMAC_256) ||
        (alg == WPA_ALG_BIP_CMAC_256)) {
        keyExt->defMgmt = TRUE;
    } else {
        keyExt->def = TRUE;
    }
}

static int32_t WifiWpaInitAddr(WifiKeyExt *keyExt, const uint8_t *addr, const enum wpa_alg alg, const int32_t keyIdx,
    const int32_t setTx)
{
    keyExt->type = WIFI_KEYTYPE_BUTT;
    keyExt->defaultTypes = WIFI_KEY_DEFAULT_TYPE_INVALID;
    if (addr != NULL) {
        if (!IsBroadcastAddr(addr)) {
            keyExt->addr = (uint8_t *)os_zalloc(ETH_ADDR_LEN);
            if ((keyExt->addr == NULL) || (memcpy_s(keyExt->addr, ETH_ADDR_LEN, addr, ETH_ADDR_LEN) != EOK)) {
                return -EFAIL;
            }
            if ((alg != WPA_ALG_WEP) && (keyIdx != 0) && (setTx == 0)) {
                keyExt->type = WIFI_KEYTYPE_GROUP;
            }
            keyExt->defaultTypes = WIFI_KEY_DEFAULT_TYPE_UNICAST;
        } else {
            keyExt->addr = NULL;
            keyExt->defaultTypes = WIFI_KEY_DEFAULT_TYPE_MULTICAST;
        }
    }
    if (keyExt->type == WIFI_KEYTYPE_BUTT) {
        keyExt->type = (keyExt->addr != NULL) ? WIFI_KEYTYPE_PAIRWISE : WIFI_KEYTYPE_GROUP;
    }
    return SUCC;
}

static int32_t WifiWpaInitSeq(WifiKeyExt *keyExt, const uint8_t *seq, const size_t seqLen)
{
    keyExt->seqLen = seqLen;
    if ((seq != NULL) && (seqLen != 0)) {
        keyExt->seq = (uint8_t *)os_zalloc(seqLen);
        if ((keyExt->seq == NULL) || (memcpy_s(keyExt->seq, seqLen, seq, seqLen) != EOK)) {
            return -EFAIL;
        }
    }
    return SUCC;
}

static int32_t WifiWpaInitKey(WifiKeyExt *keyExt, const uint8_t *key, const size_t keyLen, const int32_t keyIdx,
    const enum wpa_alg alg)
{
    keyExt->keyLen = keyLen;
    keyExt->keyIdx = keyIdx;
    if ((alg != WPA_ALG_NONE) && (key != NULL) && (keyLen != 0)) {
        keyExt->key = (uint8_t *)os_zalloc(keyLen);
        if ((keyExt->key == NULL) || (memcpy_s(keyExt->key, keyLen, key, keyLen) != EOK)) {
            return -EFAIL;
        }
    }
    return SUCC;
}

static void WifiKeyExtFree(WifiKeyExt **key)
{
    if (key == NULL || *key == NULL) {
        return;
    }

    if ((*key)->addr != NULL) {
        os_free((*key)->addr);
        (*key)->addr = NULL;
    }
    if ((*key)->seq != NULL) {
        os_free((*key)->seq);
        (*key)->seq = NULL;
    }
    if ((*key)->key != NULL) {
        os_free((*key)->key);
        (*key)->key = NULL;
    }

    os_free(*key);
    *key = NULL;
}

static inline int32_t IsApInterface(int32_t mode)
{
    return ((mode) == WIFI_IFTYPE_AP || (mode) == WIFI_IFTYPE_P2P_GO);
}

static int32_t WifiWpaSetKey(const char *ifname, void *priv, enum wpa_alg alg, const uint8_t *addr, int32_t keyIdx,
    int32_t setTx, const uint8_t *seq, size_t seqLen, const uint8_t *key, size_t keyLen)
{
    int32_t ret;
    WifiKeyExt *keyExt = NULL;
    WifiDriverData *drv = priv;

    if ((ifname == NULL) || (priv == NULL)) {
        return -EFAIL;
    }
    if (drv->mode == WIFI_IFTYPE_P2P_DEVICE) {
        return SUCC;
    }

    keyExt = os_zalloc(sizeof(WifiKeyExt));
    if (keyExt == NULL) {
        return -EFAIL;
    }

    WifiWpaInitAlg(keyExt, alg, keyLen);
    if (WifiWpaInitAddr(keyExt, addr, alg, keyIdx, setTx) != SUCC || WifiWpaInitSeq(keyExt, seq, seqLen) != SUCC ||
        WifiWpaInitKey(keyExt, key, keyLen, keyIdx, alg) != SUCC) {
        WifiKeyExtFree(&keyExt);
        wpa_printf(MSG_ERROR, "WifiWpaInitKey failed");
        return -EFAIL;
    }

    if (alg == WPA_ALG_NONE) {
        ret = WifiCmdDelKey(ifname, keyExt);
    } else {
        ret = WifiCmdNewKey(ifname, keyExt);
        if ((ret != SUCC) || (setTx == 0) || (alg == WPA_ALG_NONE)) {
            WifiKeyExtFree(&keyExt);
            return ret;
        }

        if ((IsApInterface(drv->mode)) && (keyExt->addr != NULL) && (!IsBroadcastAddr(keyExt->addr))) {
            WifiKeyExtFree(&keyExt);
            return ret;
        }
        ret = WifiCmdSetKey(ifname, keyExt);
    }

    WifiKeyExtFree(&keyExt);
    return ret;
}

static void WifiWpaReceiveEapol(void *ctx, const uint8_t *srcAddr, const uint8_t *buf, size_t len)
{
    WifiDriverData *drv = ctx;

    if ((ctx == NULL) || (srcAddr == NULL) || (buf == NULL) || (len < sizeof(struct l2_ethhdr))) {
        return;
    }

    drv_event_eapol_rx(drv->ctx, srcAddr, buf + sizeof(struct l2_ethhdr), len - sizeof(struct l2_ethhdr));
    wpa_printf(MSG_INFO, "WifiWpaReceiveEapol done");
}

static void WifiWpaPreInit(const WifiDriverData *drv)
{
    WifiSetMode setMode;
    WifiSetNewDev info;

    if (drv == NULL) {
        return;
    }

    (void)memset_s(&setMode, sizeof(WifiSetMode), 0, sizeof(WifiSetMode));
    (void)memset_s(&info, sizeof(WifiSetNewDev), 0, sizeof(WifiSetNewDev));

    if  (strncmp(drv->iface, "p2p-p2p0-", 9) == 0) {
        info.ifType = WIFI_IFTYPE_P2P_CLIENT;
        setMode.iftype = WIFI_IFTYPE_P2P_CLIENT;
    } else if (strncmp(drv->iface, "p2p0", 4) == 0) {
        info.ifType = WIFI_IFTYPE_P2P_DEVICE;
        setMode.iftype = WIFI_IFTYPE_P2P_DEVICE;
    } else {
        setMode.iftype = WIFI_IFTYPE_STATION;
        info.status = FALSE;
        info.ifType = WIFI_IFTYPE_STATION;
        info.mode = WIFI_PHY_MODE_11N;
        if (WifiCmdSetNetdev(drv->iface, &info) != SUCC) {
            wpa_printf(MSG_ERROR, "%s set netdev failed", __func__);
        }
        if (WifiCmdSetMode((char *)drv->iface, &setMode) != SUCC) {
            wpa_printf(MSG_ERROR, "%s set mode failed", __func__);
        }
    }
}

#ifdef CONFIG_OPEN_HARMONY_PATCH
static void CheckWifiIface(const char *ifName)
{
    DIR *dir;
    struct dirent *dent;
    while (TRUE) {
        dir = opendir("/sys/class/net");
        if (dir == 0) {
            return;
        }
        while ((dent = readdir(dir))) {
            if (dent->d_name[0] == '.') {
                continue;
            }
            if (strcmp(dent->d_name, ifName) == 0) {
                goto out;
            }
            usleep(WAIT_LOAD_NETDEVICE);
        }
    }
out:
    closedir(dir);
}
#endif

static void WifiWpaDeinit(void *priv)
{
    WifiDriverData *drv = NULL;
    WifiSetNewDev info;

    if (priv == NULL) {
        return;
    }

    drv = (WifiDriverData *)priv;
    info.status = FALSE;
    info.ifType = WIFI_IFTYPE_STATION;
    info.mode = WIFI_PHY_MODE_11N;
#ifdef CONFIG_OHOS_P2P
    if  (strncmp(drv->iface, "p2p-p2p0-", 9) == 0) {
        info.ifType = WIFI_IFTYPE_P2P_CLIENT;
    } else if (strncmp(drv->iface, "p2p0", 4) == 0) {
        info.ifType = WIFI_IFTYPE_P2P_DEVICE;
    }
    WifiDev *wifiDev = NULL;
    wifiDev = GetWifiDevByName(drv->iface);
    if (wifiDev == NULL) {
        wpa_printf(MSG_ERROR, "%s: GetWifiDevByName failed.\r\n.", __FUNCTION__);
    }
    FreeWifiDev(wifiDev);
#endif // CONFIG_OHOS_P2P
    eloop_cancel_timeout(WifiWpaScanTimeout, drv, drv->ctx);
    WifiCmdSetNetdev(drv->iface, &info);

    if (drv->eapolSock != NULL) {
        l2_packet_deinit(drv->eapolSock);
    }

#ifdef CONFIG_OHOS_P2P
    WifiUnregisterEventCallback(OnWpaWiFiEvents, WIFI_KERNEL_TO_WPA_CLIENT, drv->iface);
    if (CountWifiDevInUse() == 0) {
        g_msgInit = TRUE;
        os_free(g_wifiDriverData);
        g_wifiDriverData = NULL;
        (void)WifiClientDeinit(drv->iface);
    }
#else
    os_free(g_wifiDriverData);
    g_wifiDriverData = NULL;
    (void)WifiClientDeinit(drv->iface);
#endif //CONFIG_OHOS_P2P

    wpa_printf(MSG_INFO, "WifiWpaDeinit done");
}

static void *WifiWpaInit(void *ctx, const char *ifName)
{
    int32_t ret;
    WifiSetNewDev info;
#ifdef CONFIG_OHOS_P2P
    WifiDev *wifiDev = NULL;
    errno_t rc;
#endif

    if ((ctx == NULL) || (ifName == NULL)) {
        return NULL;
    }

    wpa_printf(MSG_INFO, "%s enter, interface name:%s.", __FUNCTION__, ifName);
    (void)memset_s(&info, sizeof(WifiSetNewDev), 0, sizeof(WifiSetNewDev));
    WifiDriverData *drv = os_zalloc(sizeof(WifiDriverData));
    if (drv == NULL) {
        goto failed;
    }

    drv->ctx = ctx;
    if (memcpy_s(drv->iface, sizeof(drv->iface), ifName, sizeof(drv->iface)) != EOK) {
        goto failed;
    }
#ifdef CONFIG_OHOS_P2P
    if (g_msgInit && (strncmp(drv->iface, "p2p0", 4) == 0)) {
        if (WifiClientInit(drv->iface) != SUCC) {
            goto failed;
        }
        g_msgInit = FALSE;
    }
#endif // CONFIG_OHOS_P2P
    if (strncmp(drv->iface, "wlan0", 5) == 0) {
        if (WifiClientInit(drv->iface) != SUCC) {
            goto failed;
        }
    }
#ifdef CONFIG_OPEN_HARMONY_PATCH
    CheckWifiIface(ifName);
#endif	
    WifiWpaPreInit(drv);

    info.status = TRUE;
    info.ifType = WIFI_IFTYPE_STATION;
    info.mode = WIFI_PHY_MODE_11N;
#ifdef CONFIG_OHOS_P2P
    if  (strncmp(drv->iface, "p2p-p2p0-", 9) == 0) {
        info.ifType = WIFI_IFTYPE_P2P_CLIENT;
    } else if (strncmp(drv->iface, "p2p0", 4) == 0) {
        info.ifType = WIFI_IFTYPE_P2P_DEVICE;
    }
#endif // CONFIG_OHOS_P2P
    ret = WifiCmdSetNetdev(drv->iface, &info);
    if (ret != SUCC) {
        wpa_printf(MSG_ERROR, "WifiWpaInit set netdev faild");
        goto failed;
    }
    drv->eapolSock = l2_packet_init(drv->iface, NULL, ETH_P_EAPOL, WifiWpaReceiveEapol, drv, 1);
    if (drv->eapolSock == NULL) {
        wpa_printf(MSG_ERROR, "WifiWpaInit l2_packet_init faild");
        goto failed;
    }

    if (l2_packet_get_own_addr(drv->eapolSock, drv->ownAddr)) {
        wpa_printf(MSG_ERROR, "l2_packet_get_own_addr faild");
        goto failed;
    }

    g_wifiDriverType = WIFI_IFTYPE_STATION;
#ifdef CONFIG_OHOS_P2P
    wifiDev = (WifiDev *)os_zalloc(sizeof(WifiDev));
    if (wifiDev == NULL) {
        wpa_printf(MSG_ERROR, "%s wifiDev malloc failed.", __FUNCTION__);
        goto failed;
    }
    wifiDev->priv = drv;
    wifiDev->ifNameLen = sizeof(ifName);
    rc = memcpy_s(wifiDev->ifName, sizeof(wifiDev->ifName), drv->iface, sizeof(drv->iface));
    if (rc != EOK) {
        wpa_printf(MSG_ERROR, "%s could not copy wifi device name.", __FUNCTION__);
        goto failed;
    }
    wpa_printf(MSG_ERROR, "%s init done, ifName:%s.", __FUNCTION__, wifiDev->ifName);
    SetWifiDev(wifiDev);
#endif // CONFIG_OHOS_P2P
    g_wifiDriverData = drv;
    return drv;

failed:
#ifdef CONFIG_OHOS_P2P
    FreeWifiDev(wifiDev);
#endif // CONFIG_OHOS_P2P
    WifiWpaDeinit(drv);
    return NULL;
}

static int32_t WifiWpaDeauthenticate(void *priv, const uint8_t *addr, uint16_t reasonCode)
{
    int32_t ret;
    WifiDriverData *drv = priv;

    (void)addr;
    if (priv == NULL) {
        return -EFAIL;
    }

    wpa_printf(MSG_INFO, "WifiWpaDeauthenticate reasonCode = %d", reasonCode);
    ret = WifiCmdDisconnet(drv->iface, reasonCode);
    if (ret == SUCC) {
        drv->associated = WIFI_DISCONNECT;
    }
    return ret;
}

static int32_t WifiWpaDriverAp(WifiDriverData *drv, struct wpa_driver_associate_params *params)
{
    int32_t ret;
    WifiSetMode setMode;
    errno_t rc;

    if ((drv == NULL) || (params == NULL)) {
        wpa_printf(MSG_ERROR, "%s input NULL ptr.", __FUNCTION__);
        return -EFAIL;
    }
    rc = memset_s(&setMode, sizeof(WifiSetMode), 0, sizeof(WifiSetMode));
    if (rc != EOK) {
        wpa_printf(MSG_ERROR, "%s: memset failed.", __FUNCTION__);
        return -EFAIL;
    }
    if (params->p2p) {
        wpa_printf(MSG_INFO, "%s: Setup AP operations for P2P group.(GO).", __FUNCTION__);
        setMode.iftype = WIFI_IFTYPE_P2P_GO;
    } else {
        setMode.iftype = WIFI_IFTYPE_AP;
    }
    rc = memcpy_s(setMode.bssid, ETH_ADDR_LEN, drv->ownAddr, ETH_ADDR_LEN);
    if (rc != EOK) {
        wpa_printf(MSG_ERROR, "%s memcpy failed.", __FUNCTION__);
        return -EFAIL;
    }
    ret = WifiCmdSetMode(drv->iface, &setMode);
    if (ret != SUCC) {
        wpa_printf(MSG_ERROR, "%s: set mode failed.", __FUNCTION__);
        return -EFAIL;
    }
    return SUCC;
}

static int32_t WifiWpaAssocParamsSet(WifiDriverData *drv, struct wpa_driver_associate_params *params,
    WifiAssociateParams *assocParams)
{
    if (params->bssid != NULL) {
        assocParams->bssid = (uint8_t *)os_zalloc(ETH_ADDR_LEN);
        if (assocParams->bssid == NULL) {
            return -EFAIL;
        }
        if (memcpy_s(assocParams->bssid, ETH_ADDR_LEN, params->bssid, ETH_ADDR_LEN) != EOK) {
            return -EFAIL;
        }
    }

    if (params->freq.freq != 0) {
        assocParams->freq = params->freq.freq;
    }
    if (params->ssid_len > MAX_SSID_LEN) {
        params->ssid_len = MAX_SSID_LEN;
    }
    if ((params->ssid != NULL) && (params->ssid_len != 0)) {
        assocParams->ssid = (uint8_t *)os_zalloc(params->ssid_len);
        if (assocParams->ssid == NULL) {
            return -EFAIL;
        }
        assocParams->ssidLen = params->ssid_len;
        if (memcpy_s(assocParams->ssid, assocParams->ssidLen, params->ssid, params->ssid_len) != EOK) {
            return -EFAIL;
        }
        if (memset_s(drv->ssid, MAX_SSID_LEN, 0, MAX_SSID_LEN) != EOK) {
            return -EFAIL;
        }
        if (memcpy_s(drv->ssid, MAX_SSID_LEN, params->ssid, params->ssid_len) != EOK) {
            return -EFAIL;
        }
        drv->ssidLen = params->ssid_len;
    }

    if ((params->wpa_ie != NULL) && (params->wpa_ie_len != 0)) {
        assocParams->ie = (uint8_t *)os_zalloc(params->wpa_ie_len);
        if (assocParams->ie == NULL) {
            return -EFAIL;
        }
        assocParams->ieLen = params->wpa_ie_len;
        if (memcpy_s(assocParams->ie, assocParams->ieLen, params->wpa_ie, params->wpa_ie_len) != EOK) {
            return -EFAIL;
        }
    }

    return SUCC;
}

static uint32_t WifiCipherToCipherSuite(uint32_t cipher)
{
    switch (cipher) {
        case WPA_CIPHER_CCMP_256:
            return RSN_CIPHER_SUITE_CCMP_256;
        case WPA_CIPHER_GCMP_256:
            return RSN_CIPHER_SUITE_GCMP_256;
        case WPA_CIPHER_CCMP:
            return RSN_CIPHER_SUITE_CCMP;
        case WPA_CIPHER_GCMP:
            return RSN_CIPHER_SUITE_GCMP;
        case WPA_CIPHER_TKIP:
            return RSN_CIPHER_SUITE_TKIP;
        case WPA_CIPHER_WEP104:
            return RSN_CIPHER_SUITE_WEP104;
        case WPA_CIPHER_WEP40:
            return RSN_CIPHER_SUITE_WEP40;
        case WPA_CIPHER_GTK_NOT_USED:
            return RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED;
        default:
            return 0;
    }
}

static int32_t WifiWpaAssocParamCryptoSet(const struct wpa_driver_associate_params *params,
    WifiAssociateParams *assocParams)
{
    uint32_t ver = 0;
    uint32_t akm_suites_num = 0;
    uint32_t ciphers_pairwise_num = 0;
    int32_t mgmt = RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X;

    assocParams->crypto = (WifiCryptoSetting *)os_zalloc(sizeof(WifiCryptoSetting));
    if (assocParams->crypto == NULL) {
        return -EFAIL;
    }

    if (params->wpa_proto != 0) {
        if (params->wpa_proto & WPA_PROTO_WPA) {
            ver |= WPA_VERSION_1;
        }
        if (params->wpa_proto & WPA_PROTO_RSN) {
            ver |= WPA_VERSION_2;
        }
        assocParams->crypto->wpaVersions = ver;
    }

    if (params->pairwise_suite != WPA_CIPHER_NONE) {
        assocParams->crypto->ciphersPairwise[ciphers_pairwise_num++] = WifiCipherToCipherSuite(params->pairwise_suite);
        assocParams->crypto->nCiphersPairwise = ciphers_pairwise_num;
    }

    if (params->group_suite != WPA_CIPHER_NONE) {
        assocParams->crypto->cipherGroup = WifiCipherToCipherSuite(params->group_suite);
    }

    if (params->key_mgmt_suite == WPA_KEY_MGMT_PSK || params->key_mgmt_suite == WPA_KEY_MGMT_SAE ||
        params->key_mgmt_suite == WPA_KEY_MGMT_PSK_SHA256) {
        switch (params->key_mgmt_suite) {
            case WPA_KEY_MGMT_PSK_SHA256:
                mgmt = RSN_AUTH_KEY_MGMT_PSK_SHA256;
                break;
            case WPA_KEY_MGMT_SAE:
                mgmt = RSN_AUTH_KEY_MGMT_SAE;
                break;
            case WPA_KEY_MGMT_PSK: /* fall through */
            default:
                mgmt = RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X;
                break;
        }
        assocParams->crypto->akmSuites[akm_suites_num++] = mgmt;
        assocParams->crypto->nAkmSuites = akm_suites_num;
    }

    return SUCC;
}

static void WifiWpaSetConnKeys(const struct wpa_driver_associate_params *wpa_params, WifiAssociateParams *params)
{
    int32_t loop;
    uint8_t privacy;
    errno_t rc;

    if ((wpa_params == NULL) || (params == NULL)) {
        return;
    }

    privacy = 0;
    for (loop = 0; loop < WEP_KEY_NUM; loop++) {
        if (wpa_params->wep_key[loop] == NULL) {
            continue;
        }
        privacy = 1;
        break;
    }

    if ((wpa_params->wps == WPS_MODE_PRIVACY) ||
        ((wpa_params->pairwise_suite != 0) && (wpa_params->pairwise_suite != WPA_CIPHER_NONE))) {
        privacy = 1;
    }
    if (privacy == 0) {
        return;
    }
    params->privacy = privacy;
    for (loop = 0; loop < WEP_KEY_NUM; loop++) {
        if (wpa_params->wep_key[loop] == NULL) {
            continue;
        }
        params->keyLen = wpa_params->wep_key_len[loop];
        params->key = (uint8_t *)os_zalloc(params->keyLen);
        if (params->key == NULL) {
            return;
        }

        rc = memcpy_s(params->key, params->keyLen, wpa_params->wep_key[loop], params->keyLen);
        if (rc != EOK) {
            os_free(params->key);
            params->key = NULL;
            return;
        }
        params->keyIdx = wpa_params->wep_tx_keyidx;
        break;
    }

    return;
}

static void WifiWpaConnectFree(WifiAssociateParams **params)
{
    if (params == NULL || *params == NULL) {
        return;
    }

    if ((*params)->ie != NULL) {
        os_free((*params)->ie);
        (*params)->ie = NULL;
    }
    if ((*params)->crypto != NULL) {
        os_free((*params)->crypto);
        (*params)->crypto = NULL;
    }
    if ((*params)->ssid != NULL) {
        os_free((*params)->ssid);
        (*params)->ssid = NULL;
    }
    if ((*params)->bssid != NULL) {
        os_free((*params)->bssid);
        (*params)->bssid = NULL;
    }
    if ((*params)->key != NULL) {
        os_free((*params)->key);
        (*params)->key = NULL;
    }

    os_free(*params);
    *params = NULL;
}

static WifiAuthType WifiGetStaAuthType(const struct wpa_driver_associate_params *params)
{
    WifiAuthType type = WIFI_AUTHTYPE_BUTT;
    uint32_t algs = 0;

    if ((uint32_t)(params->auth_alg) & WPA_AUTH_ALG_OPEN) {
        type = WIFI_AUTHTYPE_OPEN_SYSTEM;
        algs++;
    }
    if ((uint32_t)(params->auth_alg) & WPA_AUTH_ALG_SHARED) {
        type = WIFI_AUTHTYPE_SHARED_KEY;
        algs++;
    }
    if ((uint32_t)(params->auth_alg) & WPA_AUTH_ALG_LEAP) {
        type = WIFI_AUTHTYPE_EAP;
        algs++;
    }

    if (algs > 1) {
        return WIFI_AUTHTYPE_AUTOMATIC;
    } else if (algs == 1) {
        return type;
    }

    if ((uint32_t)params->auth_alg & WPA_AUTH_ALG_FT) {
        type = WIFI_AUTHTYPE_FT;
    }
    return type;
}

static int32_t WifiWpaTryConnect(WifiDriverData *drv, struct wpa_driver_associate_params *params)
{
    WifiAssociateParams *assocParams = NULL;
    int32_t ret = -EFAIL;

    if ((drv == NULL) || (params == NULL)) {
        return -EFAIL;
    }

    assocParams = (WifiAssociateParams *)os_zalloc(sizeof(WifiAssociateParams));
    if (assocParams == NULL) {
        return ret;
    }
    if (WifiWpaAssocParamsSet(drv, params, assocParams) != SUCC) {
        wpa_printf(MSG_ERROR, "WifiWpaTryConnect set assoc params faild");
        goto skip_auth_type;
    }
    if (WifiWpaAssocParamCryptoSet(params, assocParams) != SUCC) {
        wpa_printf(MSG_ERROR, "WifiWpaTryConnect set assoc crypto faild");
        goto skip_auth_type;
    }
    assocParams->mfp = params->mgmt_frame_protection;
    assocParams->authType = WifiGetStaAuthType(params);

    WifiWpaSetConnKeys(params, assocParams);
    ret = WifiCmdAssoc(drv->iface, assocParams);
    if (ret != SUCC) {
        wpa_printf(MSG_ERROR, "WifiWpaTryConnect assoc faild");
    }

skip_auth_type:
    WifiWpaConnectFree(&assocParams);
    return ret;
}

static int32_t WifiWpaDisconnet(WifiDriverData *drv, uint16_t reasonCode)
{
    int32_t ret;

    if (drv == NULL) {
        return -EFAIL;
    }
    ret = WifiCmdDisconnet(drv->iface, reasonCode);
    if (ret == SUCC) {
        drv->associated = WIFI_DISCONNECT;
    }
    wpa_printf(MSG_INFO, "WifiWpaDisconnet done ret=%d", ret);
    return ret;
}
static int WifiWpaAssociate(void *priv, struct wpa_driver_associate_params *params)
{
    int ret;
    WifiDriverData *drv = priv;

    if ((drv == NULL) || (params == NULL)) {
        return -EFAIL;
    }
#ifdef CONFIG_OHOS_P2P
    if (params->mode == IEEE80211_MODE_AP) {
        return WifiWpaDriverAp(drv, params);
    }
#endif
    ret = WifiWpaTryConnect(drv, params);
    if (ret != SUCC) {
        if (WifiWpaDisconnet(drv, WLAN_REASON_PREV_AUTH_NOT_VALID)) {
            return -EFAIL;
        }
        ret = WifiWpaTryConnect(drv, params);
    }
    wpa_printf(MSG_INFO, "WifiWpaAssociate done ret=%d", ret);
    return ret;
}

static const uint8_t *WifiWpaGetMacAddr(void *priv)
{
    WifiDriverData *drv = priv;

    if (priv == NULL) {
        return NULL;
    }
    return drv->ownAddr;
}

int32_t WifiWpaWpaSendEapol(void *priv, const uint8_t *dest, uint16_t proto, const uint8_t *data, size_t dataLen)
{
    WifiDriverData *drv = priv;
    int32_t ret;
    uint32_t frameLen;
    uint8_t *frame = NULL;
    uint8_t *payload = NULL;
    struct l2_ethhdr *l2_ethhdr = NULL;
    errno_t rc;

    if ((priv == NULL) || (data == NULL) || (dest == NULL)) {
        return -EFAIL;
    }

    frameLen = dataLen + sizeof(struct l2_ethhdr);
    frame = os_zalloc(frameLen);
    if (frame == NULL) {
        return -EFAIL;
    }

    l2_ethhdr = (struct l2_ethhdr *)frame;
    rc = memcpy_s(l2_ethhdr->h_dest, ETH_ADDR_LEN, dest, ETH_ADDR_LEN);
    if (rc != EOK) {
        os_free(frame);
        frame = NULL;
        return -EFAIL;
    }
    rc = memcpy_s(l2_ethhdr->h_source, ETH_ADDR_LEN, drv->ownAddr, ETH_ADDR_LEN);
    if (rc != EOK) {
        os_free(frame);
        frame = NULL;
        return -EFAIL;
    }
    l2_ethhdr->h_proto = host_to_be16(proto);

    payload = (uint8_t *)(l2_ethhdr + 1);
    rc = memcpy_s(payload, dataLen, data, dataLen);
    if (rc != EOK) {
        os_free(frame);
        frame = NULL;
        return -EFAIL;
    }
    ret = l2_packet_send(drv->eapolSock, dest, host_to_be16(proto), frame, frameLen);
    os_free(frame);
    frame = NULL;
    wpa_printf(MSG_INFO, "WifiWpaWpaSendEapol done ret=%d", ret);
    return ret;
}

static void WifiWpaHwFeatureDataFree(struct hostapd_hw_modes **modes, uint16_t num)
{
    uint16_t loop;

    if (modes == NULL || *modes == NULL) {
        return;
    }
    for (loop = 0; loop < num; ++loop) {
        if ((*modes)[loop].channels != NULL) {
            os_free((*modes)[loop].channels);
            (*modes)[loop].channels = NULL;
        }
        if ((*modes)[loop].rates != NULL) {
            os_free((*modes)[loop].rates);
            (*modes)[loop].rates = NULL;
        }
    }
    os_free(*modes);
    *modes = NULL;
}

static struct hostapd_hw_modes *WifiWpaGetHwFeatureData(void *priv, uint16_t *numModes, uint16_t *flags, uint8_t *dfs)
{
    WifiModes modesData[] = {{IEEE80211G_RATES_NUM, HOSTAPD_MODE_IEEE80211G},
        {IEEE80211B_RATES_NUM, HOSTAPD_MODE_IEEE80211B}, {IEEE80211A_RATES_NUM, HOSTAPD_MODE_IEEE80211A}};
    size_t loop;
    uint32_t index;
    uint32_t iee80211band;
    WifiHwFeatureData hwFeatureData;
    WifiDriverData *drv = (WifiDriverData *)priv;
    (void)dfs;
    if ((priv == NULL) || (numModes == NULL) || (flags == NULL)) {
        return NULL;
    }
    (void)memset_s(&hwFeatureData, sizeof(WifiHwFeatureData), 0, sizeof(WifiHwFeatureData));
    *numModes = DEFAULT_NUM_MODES;
    *flags = 0;

    if (WifiCmdGetHwFeature(drv->iface, &hwFeatureData) != SUCC) {
        return NULL;
    }
    if (hwFeatureData.bands[IEEE80211_BAND_5GHZ].channelNum != 0) {
        *numModes = sizeof(modesData) / sizeof(WifiModes);
    }
    struct hostapd_hw_modes *modes = os_calloc(*numModes, sizeof(struct hostapd_hw_modes));
    if (modes == NULL) {
        return NULL;
    }

    for (loop = 0; loop < *numModes; ++loop) {
        modes[loop].channels = NULL;
        modes[loop].rates = NULL;
    }

    modes[0].ht_capab = hwFeatureData.htCapab;
    iee80211band = IEEE80211_BAND_2GHZ;
    for (index = 0; index < *numModes; index++) {
        if (index >= DEFAULT_NUM_MODES) {
            iee80211band = IEEE80211_BAND_5GHZ;
        }
        modes[index].mode = modesData[index].mode;
        modes[index].num_channels = hwFeatureData.bands[iee80211band].channelNum;
        modes[index].num_rates = modesData[index].numRates;
        modes[index].channels = os_calloc(hwFeatureData.bands[iee80211band].channelNum, sizeof(struct hostapd_channel_data));
        modes[index].rates = os_calloc(modes[index].num_rates, sizeof(uint32_t));
        if ((modes[index].channels == NULL) || (modes[index].rates == NULL)) {
            WifiWpaHwFeatureDataFree(&modes, *numModes);
            return NULL;
        }

        for (loop = 0; loop < (size_t)hwFeatureData.bands[iee80211band].channelNum; loop++) {
            modes[index].channels[loop].chan = hwFeatureData.bands[iee80211band].iee80211Channel[loop].channel;
            modes[index].channels[loop].freq = hwFeatureData.bands[iee80211band].iee80211Channel[loop].freq;
            modes[index].channels[loop].flag = hwFeatureData.bands[iee80211band].iee80211Channel[loop].flags;
            modes[index].channels[loop].allowed_bw = HOSTAPD_CHAN_WIDTH_20 | HOSTAPD_CHAN_WIDTH_10;
        }

        for (loop = 0; loop < (size_t)modes[index].num_rates; loop++) {
            if (index < DEFAULT_NUM_MODES) {
                modes[index].rates[loop] = hwFeatureData.bitrate[loop];
            } else {
                modes[index].rates[loop] = hwFeatureData.bitrate[loop + IEEE80211B_RATES_NUM];
            }
        }
    }

    wpa_printf(MSG_INFO, "WifiWpaGetHwFeatureData done");
    return modes;
}

static int32_t WifiWpaSendMlme(void *priv, const uint8_t *data, size_t dataLen, int32_t noack, uint32_t freq,
    const uint16_t *csaOffs, size_t csaOffsLen)
{
    int32_t ret;
    WifiDriverData *drv = priv;
    WifiMlmeData *mlme = NULL;
    errno_t rc;

    (void)freq;
    (void)csaOffs;
    (void)csaOffsLen;
    (void)noack;
    if ((priv == NULL) || (data == NULL)) {
        return -EFAIL;
    }
    mlme = os_zalloc(sizeof(WifiMlmeData));
    if (mlme == NULL) {
        return -EFAIL;
    }
    mlme->data = NULL;
    mlme->dataLen = dataLen;
    mlme->cookie = &(drv->actionCookie);
    if ((data != NULL) && (dataLen != 0)) {
        mlme->data = (uint8_t *)os_zalloc(dataLen);
        if (mlme->data == NULL) {
            os_free(mlme);
            mlme = NULL;
            return -EFAIL;
        }
        rc = memcpy_s(mlme->data, dataLen, data, dataLen);
        if (rc != EOK) {
            os_free(mlme->data);
            mlme->data = NULL;
            os_free(mlme);
            return -EFAIL;
        }
    }
    ret = WifiCmdSendMlme(drv->iface, mlme);
    os_free(mlme->data);
    mlme->data = NULL;
    os_free(mlme);
    if (ret != SUCC) {
        ret = -EFAIL;
    }
    wpa_printf(MSG_INFO, "WifiWpaSendMlme done ret=%d", ret);
    return ret;
}

static struct wpa_scan_results *WifiWpaGetScanResults2(void *priv)
{
    struct wpa_scan_results *results = NULL;
    WifiDriverData *drv = priv;
    uint32_t loop;
    errno_t rc;

    if (priv == NULL) {
        return NULL;
    }

    results = (struct wpa_scan_results *)os_zalloc(sizeof(struct wpa_scan_results));
    if (results == NULL) {
        return NULL;
    }

    results->num = drv->scanNum;
    if (results->num == 0) {
        return results;
    }
    results->res = (struct wpa_scan_res **)os_zalloc(results->num * sizeof(struct wpa_scan_res *));
    if (results->res == NULL) {
        os_free(results);
        results = NULL;
        return NULL;
    }
    rc = memcpy_s(results->res, results->num * sizeof(struct wpa_scan_res *), drv->scanRes,
        results->num * sizeof(struct wpa_scan_res *));
    if (rc != EOK) {
        os_free(results->res);
        os_free(results);
        results = NULL;
        return NULL;
    }
    drv->scanNum = 0;
    for (loop = 0; loop < SCAN_AP_LIMIT; loop++) {
        drv->scanRes[loop] = NULL;
    }
    wpa_printf(MSG_INFO, "WifiWpaGetScanResults2 done");
    return results;
}

static void *WifiWpaInit2(void *ctx, const char *ifname, void *globalPriv)
{
    (void)globalPriv;
    return WifiWpaInit(ctx, ifname);
}

static int32_t WifiWpaScanProcessSsid(struct wpa_driver_scan_params *params, WifiScan *scan)
{
    errno_t rc;
    size_t loop;
    if (params->num_ssids == 0) {
        return SUCC;
    }

    scan->numSsids = params->num_ssids;
    scan->ssids = (WifiDriverScanSsid *)os_zalloc(sizeof(WifiDriverScanSsid) * params->num_ssids);
    if (scan->ssids == NULL) {
        return -EFAIL;
    }

    for (loop = 0; (loop < params->num_ssids) && (loop < WPAS_MAX_SCAN_SSIDS); loop++) {
        wpa_printf(MSG_INFO, "WIFI: Scan : %s SSID : %zu\n", params->ssids[loop].ssid, params->ssids[loop].ssid_len);

        if (params->ssids[loop].ssid_len > MAX_SSID_LEN) {
            params->ssids[loop].ssid_len = MAX_SSID_LEN;
        }
        if (params->ssids[loop].ssid_len) {
            rc = memcpy_s(scan->ssids[loop].ssid, MAX_SSID_LEN, params->ssids[loop].ssid, params->ssids[loop].ssid_len);
            if (rc != EOK) {
                return -EFAIL;
            }
        }
        scan->ssids[loop].ssidLen = params->ssids[loop].ssid_len;
    }

    return SUCC;
}

static int32_t WifiWpaScanProcessBssid(const struct wpa_driver_scan_params *params, WifiScan *scan)
{
    errno_t rc;
    if (params->bssid != NULL) {
        scan->bssid = (uint8_t *)os_zalloc(ETH_ADDR_LEN);
        if (scan->bssid == NULL) {
            return -EFAIL;
        }
        rc = memcpy_s(scan->bssid, ETH_ADDR_LEN, params->bssid, ETH_ADDR_LEN);
        if (rc != EOK) {
            return -EFAIL;
        }
    }
    return SUCC;
}

static int32_t WifiWpaScanProcessExtraIes(const struct wpa_driver_scan_params *params, WifiScan *scan)
{
    errno_t rc;
    if ((params->extra_ies != NULL) && (params->extra_ies_len != 0)) {
        scan->extraIes = (uint8_t *)os_zalloc(params->extra_ies_len);
        if (scan->extraIes == NULL) {
            return -EFAIL;
        }

        rc = memcpy_s(scan->extraIes, params->extra_ies_len, params->extra_ies, params->extra_ies_len);
        if (rc != EOK) {
            return -EFAIL;
        }
        scan->extraIesLen = params->extra_ies_len;
    }
    return SUCC;
}

static int32_t WifiWpaScanProcessFreq(const struct wpa_driver_scan_params *params, WifiScan *scan)
{
    uint32_t numFreqs;
    int32_t *freqs = NULL;
    errno_t rc;

    if (params->freqs != NULL) {
        numFreqs = 0;
        for (freqs = params->freqs; *freqs != 0; freqs++) {
            numFreqs++;
            if (numFreqs > 14) { // 14 is 2.4G channel num
                return -EFAIL;
            }
        }

        scan->numFreqs = numFreqs;
        scan->freqs = (int32_t *)os_zalloc(numFreqs * (sizeof(int32_t)));
        if (scan->freqs == NULL) {
            return -EFAIL;
        }
        rc = memcpy_s(scan->freqs, numFreqs * (sizeof(int32_t)), params->freqs, numFreqs * (sizeof(int32_t)));
        if (rc != EOK) {
            return -EFAIL;
        }
    }
    return SUCC;
}

static void WifiWpaScanFree(WifiScan **scan)
{
    if (scan == NULL || *scan == NULL) {
        return;
    }

    if ((*scan)->ssids != NULL) {
        os_free((*scan)->ssids);
        (*scan)->ssids = NULL;
    }
    if ((*scan)->bssid != NULL) {
        os_free((*scan)->bssid);
        (*scan)->bssid = NULL;
    }

    if ((*scan)->extraIes != NULL) {
        os_free((*scan)->extraIes);
        (*scan)->extraIes = NULL;
    }

    if ((*scan)->freqs != NULL) {
        os_free((*scan)->freqs);
        (*scan)->freqs = NULL;
    }

    os_free(*scan);
    *scan = NULL;
}

void WifiWpaScanTimeout(void *eloop, void *ctx)
{
    (void)eloop;
    if (ctx == NULL) {
        return;
    }
    wpa_supplicant_event(ctx, EVENT_SCAN_RESULTS, NULL);
}

static int32_t WifiWpaScan2(void *priv, struct wpa_driver_scan_params *params)
{
    WifiScan *scan = NULL;
    WifiDriverData *drv = NULL;
    int32_t timeout;
    int32_t ret;

    if ((priv == NULL) || (params == NULL) || (params->num_ssids > WPAS_MAX_SCAN_SSIDS)) {
        return -EFAIL;
    }
    drv = (WifiDriverData *)priv;
    scan = (WifiScan *)os_zalloc(sizeof(WifiScan));
    if (scan == NULL) {
        return -EFAIL;
    }
    if ((WifiWpaScanProcessSsid(params, scan) != SUCC) || (WifiWpaScanProcessBssid(params, scan) != SUCC) ||
        (WifiWpaScanProcessExtraIes(params, scan) != SUCC) || (WifiWpaScanProcessFreq(params, scan) != SUCC)) {
        WifiWpaScanFree(&scan);
        return -EFAIL;
    }

    scan->fastConnectFlag = WPA_FLAG_OFF;
    scan->prefixSsidScanFlag = WPA_FLAG_OFF;
    ret = WifiCmdScan(drv->iface, scan);
    WifiWpaScanFree(&scan);

    timeout = SCAN_TIME_OUT;
    eloop_cancel_timeout(WifiWpaScanTimeout, drv, drv->ctx);
    eloop_register_timeout(timeout, 0, WifiWpaScanTimeout, drv, drv->ctx);

    return ret;
}

static void WifiSetApFreq(WifiApSetting *apsettings, const struct wpa_driver_ap_params *params)
{
    if (params->freq != NULL) {
        apsettings->freqParams.mode = params->freq->mode;
        apsettings->freqParams.freq = params->freq->freq;
        apsettings->freqParams.channel = params->freq->channel;
        apsettings->freqParams.htEnabled = params->freq->ht_enabled;
        apsettings->freqParams.secChannelOffset = params->freq->sec_channel_offset;
        apsettings->freqParams.centerFreq1 = params->freq->center_freq1;
        apsettings->freqParams.bandwidth = params->freq->bandwidth;
        if (params->freq->bandwidth == WPA_BANDWIDTH_20) {
            apsettings->freqParams.bandwidth = WIFI_CHAN_WIDTH_20;
        } else {
            apsettings->freqParams.bandwidth = WIFI_CHAN_WIDTH_40;
        }
    }
}

static void WifiSetApBand(WifiApSetting *apsettings, struct hostapd_data *hapd)
{
    if ((apsettings!= NULL) && (hapd!= NULL)) {
        switch (hapd->conf->wps_rf_bands) {
            case WPS_RF_24GHZ:
                apsettings->freqParams.band = IEEE80211_BAND_2GHZ;
                break;
            case WPS_RF_50GHZ:
                apsettings->freqParams.band = IEEE80211_BAND_5GHZ;
                break;
            default:
                apsettings->freqParams.band = IEEE80211_BAND_2GHZ;
                break;
        }
    }
}

static int WifiSetApBeaconData(WifiApSetting *apsettings, const struct wpa_driver_ap_params *params)
{
    if ((params->head != NULL) && (params->head_len != 0)) {
        apsettings->beaconData.headLen = params->head_len;
        apsettings->beaconData.head = (uint8_t *)os_zalloc(apsettings->beaconData.headLen);
        if (apsettings->beaconData.head == NULL) {
            return -EFAIL;
        }
        if (memcpy_s(apsettings->beaconData.head, apsettings->beaconData.headLen, params->head, params->head_len) !=
            EOK) {
            return -EFAIL;
        }
    }

    if ((params->tail != NULL) && (params->tail_len != 0)) {
        apsettings->beaconData.tailLen = params->tail_len;
        apsettings->beaconData.tail = (uint8_t *)os_zalloc(apsettings->beaconData.tailLen);
        if (apsettings->beaconData.tail == NULL) {
            return -EFAIL;
        }
        if (memcpy_s(apsettings->beaconData.tail, apsettings->beaconData.tailLen, params->tail, params->tail_len) !=
            EOK) {
            return -EFAIL;
        }
    }
    return SUCC;
}

static void WifiApSettingsFree(WifiApSetting **apsettings)
{
    if (apsettings == NULL || *apsettings == NULL) {
        return;
    }

    if ((*apsettings)->meshSsid != NULL) {
        os_free((*apsettings)->meshSsid);
        (*apsettings)->meshSsid = NULL;
    }

    if ((*apsettings)->ssid != NULL) {
        os_free((*apsettings)->ssid);
        (*apsettings)->ssid = NULL;
    }

    if ((*apsettings)->beaconData.head != NULL) {
        os_free((*apsettings)->beaconData.head);
        (*apsettings)->beaconData.head = NULL;
    }

    if ((*apsettings)->beaconData.tail != NULL) {
        os_free((*apsettings)->beaconData.tail);
        (*apsettings)->beaconData.tail = NULL;
    }

    os_free(*apsettings);
    *apsettings = NULL;
}

static WifiAuthType WifiGetApAuthType(const struct wpa_driver_ap_params *params)
{
    WifiAuthType type;

    if ((params->auth_algs & (WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SHARED)) == (WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SHARED)) {
        type = WIFI_AUTHTYPE_AUTOMATIC;
    } else if ((params->auth_algs & WPA_AUTH_ALG_SHARED) == WPA_AUTH_ALG_SHARED) {
        type = WIFI_AUTHTYPE_SHARED_KEY;
    } else {
        type = WIFI_AUTHTYPE_OPEN_SYSTEM;
    }
    return type;
}

static int32_t WifiWpaSetAp(void *priv, struct wpa_driver_ap_params *params)
{
    int32_t ret;
    WifiApSetting *apsettings = NULL;
    WifiDriverData *drv = (WifiDriverData *)priv;
    if ((priv == NULL) || (params == NULL) || (params->freq == NULL)) {
        return -EFAIL;
    }
    if ((params->freq->bandwidth != WPA_BANDWIDTH_20) && (params->freq->bandwidth != WPA_BANDWIDTH_40)) {
        return -EFAIL;
    }

    apsettings = os_zalloc(sizeof(WifiApSetting));
    if (apsettings == NULL) {
        return -EFAIL;
    }
    apsettings->beaconInterval = params->beacon_int;
    apsettings->dtimPeriod = params->dtim_period;
    apsettings->hiddenSsid = params->hide_ssid;
    apsettings->authType = WifiGetApAuthType(params);

    if ((params->ssid != NULL) && (params->ssid_len != 0)) {
        apsettings->ssidLen = params->ssid_len;
        apsettings->ssid = (uint8_t *)os_zalloc(apsettings->ssidLen);
        if ((apsettings->ssid == NULL) ||
            (memcpy_s(apsettings->ssid, apsettings->ssidLen, params->ssid, params->ssid_len) != EOK)) {
            goto failed;
        }
    }
    WifiSetApFreq(apsettings, params);
    WifiSetApBand(apsettings, drv->hapd);
    if (WifiSetApBeaconData(apsettings, params) != SUCC) {
        goto failed;
    }
    if (drv->beaconSet == TRUE) {
        ret = WifiCmdChangeBeacon(drv->iface, apsettings);
    } else {
        ret = WifiCmdSetAp(drv->iface, apsettings);
    }
    if (ret == SUCC) {
        drv->beaconSet = TRUE;
    }
    WifiApSettingsFree(&apsettings);
    wpa_printf(MSG_INFO, "WifiWpaGetScanResults2 done ret=%d", ret);
    return ret;

failed:
    WifiApSettingsFree(&apsettings);
    return -EFAIL;
}

static void WifiHapdPreInit(const WifiDriverData *drv)
{
    WifiSetNewDev info;

    if (drv == NULL) {
        return;
    }
    info.status = FALSE;
    info.ifType = WIFI_IFTYPE_STATION;
    info.mode = WIFI_PHY_MODE_11N;
    int ret = WifiCmdSetNetdev(drv->iface, &info);

    if (ret != SUCC) {
        wpa_printf(MSG_ERROR, "%s set netdev failed ret = %d.", __func__, ret);
    }
}

static WifiDriverData *WifiDrvInit(void *ctx, const struct wpa_init_params *params)
{
    WifiDriverData *drv = NULL;
    errno_t rc;
    WifiSetNewDev info;
    WifiSetMode setMode;
    int32_t ret;
#ifdef CONFIG_OHOS_P2P
    WifiDev *wifiDev = NULL;
#endif
    if ((ctx == NULL) || (params == NULL)) {
        return NULL;
    }
    drv = os_zalloc(sizeof(WifiDriverData));
    if (drv == NULL) {
        goto failed;
    }

    drv->ctx = ctx;
    rc = memcpy_s(drv->iface, sizeof(drv->iface), params->ifname, sizeof(drv->iface));
    if (rc != EOK) {
        os_free(drv);
        drv = NULL;
        goto failed;
    }
#ifdef CONFIG_OHOS_P2P
    wifiDev = (WifiDev *)os_zalloc(sizeof(WifiDev));
    if (wifiDev == NULL)
    {
        wpa_printf(MSG_ERROR, "%s wifiDev malloc failed.", __FUNCTION__);
        goto failed;
    }
    wifiDev->priv = drv;
    wifiDev->ifNameLen = sizeof(params->ifname);
    rc = memcpy_s(wifiDev->ifName, sizeof(wifiDev->ifName), drv->iface, sizeof(drv->iface));
    if (rc != EOK) {
        wpa_printf(MSG_ERROR, "%s wifiDev could not copy interface name.", __FUNCTION__);
        goto failed;
    }
    wpa_printf(MSG_INFO, "%s init, interface name:%s.", __FUNCTION__, wifiDev->ifName);
    SetWifiDev(wifiDev);
#endif // CONFIG_OHOS_P2P
    WifiHapdPreInit(drv);

    setMode.iftype = WIFI_IFTYPE_AP;
    ret = WifiCmdSetMode(drv->iface, &setMode);
    if (ret != SUCC) {
        wpa_printf(MSG_ERROR, "WifiWpaHapdInit set mode failed, iface = %s, ret = %d.", drv->iface, ret);
        goto failed;
    }
    info.status = TRUE;
    info.ifType = WIFI_IFTYPE_AP;
    info.mode = WIFI_PHY_MODE_11N;
    ret = WifiCmdSetNetdev(drv->iface, &info);
    if (ret != SUCC) {
        wpa_printf(MSG_ERROR, "WifiDrvInit set netdev failed");
        goto failed;
    }
    wpa_printf(MSG_INFO, "WifiDrvInit done");
    return drv;

failed:
    if (drv != NULL) {
        info.status = FALSE;
        info.ifType = WIFI_IFTYPE_STATION;
        info.mode = WIFI_PHY_MODE_11N;
        WifiCmdSetNetdev(drv->iface, &info);
        os_free(drv);
        drv = NULL;
    }
#ifdef CONFIG_OHOS_P2P
    FreeWifiDev(wifiDev);
#endif // CONFIG_OHOS_P2P
    return NULL;
}

static int32_t WifiWpaInitl2(struct wpa_init_params *params, WifiDriverData *drv)
{
    int32_t ret;
    uint8_t addrTmp[ETH_ADDR_LEN] = {0};

    drv->eapolSock = l2_packet_init(drv->iface, NULL, ETH_P_EAPOL, WifiWpaReceiveEapol, drv, 1);
    if (drv->eapolSock == NULL) {
        wpa_printf(MSG_ERROR, "WifiDrvInit l2 packet init failed");
        return -EFAIL;
    }
    if (l2_packet_get_own_addr(drv->eapolSock, addrTmp)) {
        return -EFAIL;
    }
    ret = memcpy_s(params->own_addr, ETH_ADDR_LEN, addrTmp, ETH_ADDR_LEN);
    if (ret != EOK) {
        return -EFAIL;
    }
    ret = memcpy_s(drv->ownAddr, ETH_ADDR_LEN, addrTmp, ETH_ADDR_LEN);
    if (ret != EOK) {
        return -EFAIL;
    }
    return SUCC;
}

static void *WifiWpaHapdInit(struct hostapd_data *hapd, struct wpa_init_params *params)
{
    WifiDriverData *drv = NULL;

    int32_t ret;

    if ((hapd == NULL) || (params == NULL) || (hapd->conf == NULL)) {
        return NULL;
    }

    if (WifiClientInit(params->ifname) != SUCC) {
        wpa_printf(MSG_ERROR, "Wifi client init failed");
        return NULL;
    }
    drv = WifiDrvInit(hapd, params);
    if (drv == NULL) {
        wpa_printf(MSG_ERROR, "WifiWpaHapdInit drv init failed");
        goto failed;
    }
    drv->hapd = hapd;

    ret = WifiWpaInitl2(params, drv);
    if (ret != SUCC) {
        wpa_printf(MSG_ERROR, "WifiWpaInitI2 failed");
        goto failed;
    }

    g_wifiDriverData = drv;
    g_wifiDriverType = WIFI_IFTYPE_AP;
    wpa_printf(MSG_INFO, "WifiWpaHapdInit done");
    return (void *)drv;

failed:
    if (drv != NULL && drv->eapolSock != NULL) {
        l2_packet_deinit(drv->eapolSock);
    }
    WifiWpaDeinit(drv);
    return NULL;
}

static void WifiWpaHapdDeinit(void *priv)
{
    int32_t ret;
    WifiDriverData *drv = NULL;
    WifiSetMode setMode;
    WifiSetNewDev info;

    if (priv == NULL) {
        return;
    }

    (void)memset_s(&setMode, sizeof(WifiSetMode), 0, sizeof(WifiSetMode));
    drv = (WifiDriverData *)priv;
    setMode.iftype = WIFI_IFTYPE_STATION;
    info.status = FALSE;
    info.ifType = WIFI_IFTYPE_AP;
    info.mode = WIFI_PHY_MODE_11N;

    WifiCmdSetNetdev(drv->iface, &info);
    ret = WifiCmdSetMode((char *)drv->iface, &setMode);
    if (ret != SUCC) {
        return;
    }

    if (drv->eapolSock != NULL) {
        l2_packet_deinit(drv->eapolSock);
    }
    os_free(g_wifiDriverData);
    g_wifiDriverData = NULL;
    WifiClientDeinit(drv->iface);

    wpa_printf(MSG_INFO, "WifiWpaHapdDeinit done");
}

static int32_t WifiWpaHapdSendEapol(void *priv, const uint8_t *addr, const uint8_t *data, size_t dataLen, int encrypt,
    const uint8_t *ownAddr, uint32_t flags)
{
    WifiDriverData *drv = priv;
    int32_t ret;
    uint32_t frameLen;
    uint8_t *frameBuf = NULL;
    uint8_t *payload = NULL;
    struct l2_ethhdr *ethhdr = NULL;

    (void)encrypt;
    (void)flags;
    if ((priv == NULL) || (addr == NULL) || (data == NULL) || (ownAddr == NULL)) {
        return -EFAIL;
    }

    frameLen = dataLen + sizeof(struct l2_ethhdr);
    frameBuf = os_zalloc(frameLen);
    if (frameBuf == NULL) {
        return -EFAIL;
    }

    ethhdr = (struct l2_ethhdr *)frameBuf;
    if (memcpy_s(ethhdr->h_dest, ETH_ADDR_LEN, addr, ETH_ADDR_LEN) != EOK) {
        os_free(frameBuf);
        frameBuf = NULL;
        return -EFAIL;
    }
    if (memcpy_s(ethhdr->h_source, ETH_ADDR_LEN, ownAddr, ETH_ADDR_LEN) != EOK) {
        os_free(frameBuf);
        frameBuf = NULL;
        return -EFAIL;
    }
    ethhdr->h_proto = host_to_be16(ETH_P_PAE);
    payload = (uint8_t *)(ethhdr + 1);
    if (memcpy_s(payload, dataLen, data, dataLen) != EOK) {
        os_free(frameBuf);
        frameBuf = NULL;
        return -EFAIL;
    }
    ret = l2_packet_send(drv->eapolSock, addr, ETH_P_EAPOL, frameBuf, frameLen);
    os_free(frameBuf);
    frameBuf = NULL;
    wpa_printf(MSG_INFO, "WifiWpaHapdSendEapol done, ret=%d", ret);
    return ret;
}

static int32_t WifiWpaStaRemove(void *priv, const uint8_t *addr)
{
    WifiDriverData *drv = NULL;
    int32_t ret;

    if ((priv == NULL) || (addr == NULL)) {
        return -EFAIL;
    }
    drv = (WifiDriverData *)priv;
    ret = WifiCmdStaRemove(drv->iface, addr, ETH_ADDR_LEN);
    if (ret != SUCC) {
        return -EFAIL;
    }
    wpa_printf(MSG_INFO, "WifiWpaStaRemove done, ret=%d", ret);
    return ret;
}

static uint8_t *WifiDuplicateStr(const uint8_t *src, size_t len)
{
    uint8_t *res = NULL;

    if (src == NULL) {
        return NULL;
    }
    res = os_malloc(len + 1);
    if (res == NULL) {
        return NULL;
    }
    if (memcpy_s(res, len, src, len) != EOK) {
        os_free(res);
        return NULL;
    }
    res[len] = '\0';

    return res;
}

static void WifiActionDataBufFree(WifiActionData *actionData)
{
    if (actionData == NULL) {
        return;
    }
    if (actionData->data != NULL) {
        os_free(actionData->data);
        actionData->data = NULL;
    }
}

static int32_t WifiWpaSendAction(void *priv, uint32_t freq, uint32_t wait, const uint8_t *dst, const uint8_t *src,
    const uint8_t *bssid, const uint8_t *data, size_t dataLen, int32_t noCck)
{
    WifiActionData actionData = {
        .dst = {0},
        .src = {0},
        .bssid = {0},
        .data = NULL,
        .dataLen = 0,
        .freq = 0,
        .wait = 0,
        .noCck = 0,
    };
    WifiDriverData *drv = NULL;
    int32_t ret;

    if ((priv == NULL) || (data == NULL) || (dst == NULL) || (src == NULL) || (bssid == NULL)) {
        return -EFAIL;
    }
    drv = (WifiDriverData *)priv;

    if (memcpy_s(actionData.dst, ETH_ADDR_LEN, dst, ETH_ADDR_LEN) != EOK) {
        return -EFAIL;
    }
    if (memcpy_s(actionData.src, ETH_ADDR_LEN, src, ETH_ADDR_LEN) != EOK) {
        return -EFAIL;
    }
    if (memcpy_s(actionData.bssid, ETH_ADDR_LEN, bssid, ETH_ADDR_LEN) != EOK) {
        return -EFAIL;
    }

    actionData.dataLen = dataLen;
    actionData.freq = freq;
    actionData.wait = wait;
    actionData.noCck = noCck;
    actionData.data = WifiDuplicateStr(data, dataLen);
    if (actionData.data == NULL) {
        return -EFAIL;
    }
    ret = WifiCmdSendAction(drv->iface, &actionData);
    WifiActionDataBufFree(&actionData);
    wpa_printf(MSG_INFO, "WifiWpaSendAction done, ret=%d", ret);
    return ret;
}

__attribute__ ((visibility ("default"))) void DeinitWifiService()
{
    if (g_wifiDriverType == WIFI_IFTYPE_STATION) {
        WifiWpaDeinit(g_wifiDriverData);
    } else if (g_wifiDriverType == WIFI_IFTYPE_AP) {
        WifiWpaHapdDeinit(g_wifiDriverData);
    } else {
        printf("no need to cleanup \n");
    }
}

#ifdef CONFIG_OHOS_P2P
static int32_t WifiProbeReqReport(void *priv, int32_t report)
{
    WifiDriverData *drv = NULL;
    wpa_printf(MSG_INFO, "%s enter.", __FUNCTION__);
    if (priv == NULL) {
        wpa_printf(MSG_ERROR, "%s input invalid.", __FUNCTION__);
        return -EFAIL;
    }
    drv = (WifiDriverData *)priv;
    return WifiCmdProbeReqReport(drv->iface, &report);
}

static int32_t WifiRemainOnChannel(void *priv, uint32_t freq, uint32_t duration)
{
    int32_t ret;
    WifiDriverData *drv = priv;
    WifiOnChannel *onChannel = NULL;
    if (priv == NULL) {
        wpa_printf(MSG_ERROR, "%s input invalid.", __FUNCTION__);
        return -EFAIL;
    }
    onChannel = (WifiOnChannel *)os_zalloc(sizeof(WifiOnChannel));
    if (onChannel == NULL)
    {
        wpa_printf(MSG_ERROR, "%s failed to alloc channel.", __FUNCTION__);
        return -EFAIL;
    }
    onChannel->freq = freq;
    onChannel->duration = duration;
      
    ret = WifiCmdRemainOnChannel(drv->iface, onChannel);

    os_free(onChannel);
    onChannel = NULL;

    return ret;
}

static int32_t WifiCancelRemainOnChannel(void *priv)
{
    WifiDriverData *drv = priv;
    if (drv == NULL) {
        wpa_printf(MSG_ERROR, "%s input invalid.", __FUNCTION__);
        return -EFAIL;
    }

    return WifiCmdCancelRemainOnChannel(drv->iface);
}

static int32_t WifiAddIf(void *priv, enum wpa_driver_if_type type, const char *ifName, const uint8_t *addr, void *bss_ctx,
                         void **drv_priv, char *force_ifname, uint8_t *if_addr, const char *bridge, int32_t use_existing, int32_t setup_ap)
{
    WifiDriverData *drv = priv;
    WifiIfAdd *ifAdd = NULL;
    int32_t ret;
    WifiDev *wifiDev = NULL;
    if (priv == NULL) {
        wpa_printf(MSG_ERROR, "%s input invalid.", __FUNCTION__);
        return -EFAIL;
    }
    ifAdd = (WifiIfAdd *)os_zalloc(sizeof(WifiIfAdd));
    switch (type) {
    case WPA_IF_STATION:
        ifAdd->type = WIFI_IFTYPE_STATION;
        break;
    case WPA_IF_P2P_GROUP:
    case WPA_IF_P2P_CLIENT:
        ifAdd->type = WIFI_IFTYPE_P2P_CLIENT;
        break;
    case WPA_IF_AP_VLAN:
        ifAdd->type = WIFI_IFTYPE_AP_VLAN;
        break;
    case WPA_IF_AP_BSS:
        ifAdd->type = WIFI_IFTYPE_AP;
        break;
    case WPA_IF_P2P_GO:
        ifAdd->type = WIFI_IFTYPE_P2P_GO;
        break;
    case WPA_IF_P2P_DEVICE:
        ifAdd->type = WIFI_IFTYPE_P2P_DEVICE;
        break;
    case WPA_IF_MESH:
        ifAdd->type = WIFI_IFTYPE_MESH_POINT;
        break;
    default:
        wpa_printf(MSG_ERROR, "%s unsuportted interface type %d.", __FUNCTION__, type);
    }

    ret = WifiRegisterEventCallback(OnWpaWiFiEvents, WIFI_KERNEL_TO_WPA_CLIENT, ifName);
    if (ret != SUCC) {
        wpa_printf(MSG_ERROR, "WifiWpa register event listener faild");
    }
    ret = memcpy_s(ifAdd->ifName, IFNAMSIZ, ifName, IFNAMSIZ);
    if (ret != SUCC) {
        wpa_printf(MSG_ERROR, "%s memcpy_s ifName faild", __FUNCTION__);
        return -EFAIL;
    }

    ret = WifiCmdAddIf(drv->iface, ifAdd);
    if (ret == SUCC) {
        wifiDev = (WifiDev *)os_zalloc(sizeof(WifiDev));
        if (wifiDev == NULL) {
            wpa_printf(MSG_ERROR, "%s failed to malloc wifiDev.", __FUNCTION__);
            return -EFAIL;
        }
        wifiDev->priv = drv;
        wifiDev->ifNameLen = sizeof(ifName);
        errno_t rc = memcpy_s(wifiDev->ifName, sizeof(wifiDev->ifName), ifName, sizeof(drv->iface));
        if (rc != EOK) {
            wpa_printf(MSG_ERROR, "Could not copy wifi device name.");
            FreeWifiDev(wifiDev);
            return ret;
        }
        wpa_printf(MSG_INFO, "%s ifName:%s, type:%d", __FUNCTION__, wifiDev->ifName, ifAdd->type);
        SetWifiDev(wifiDev);
    }
    os_free(ifAdd);
    ifAdd = NULL;
    return ret;
}

static int32_t WifiRemoveIf(void *priv, enum wpa_driver_if_type type, const char *ifName)
{
    WifiDriverData *drv = priv;
    WifiIfRemove ifRemove = {0};
    int32_t ret;
    errno_t rc;
    WifiDev *wifiDev = NULL;
    if (priv == NULL || ifName == NULL) {
        wpa_printf(MSG_ERROR, "%s input invalid.", __FUNCTION__);
        return -EFAIL;
    }
    if (os_strlen(ifName) > IFNAMSIZ) {
        wpa_printf(MSG_ERROR, "%s ifName invalid:%s.", __FUNCTION__, ifName);
        return -EFAIL;
    }
    rc = memcpy_s(ifRemove.ifName, IFNAMSIZ, ifName, IFNAMSIZ);
    if (rc != EOK) {
        wpa_printf(MSG_ERROR, "%s can not copy interface name.", __FUNCTION__);
        return -EFAIL;
    }

    ret = WifiCmdRemoveIf(drv->iface, &ifRemove);
    wifiDev = GetWifiDevByName(ifName);
    if (wifiDev == NULL) {
        wpa_printf(MSG_INFO, "%s: GetWifiDevByName is null, already free.", __FUNCTION__);
        return SUCC;
    }
    FreeWifiDev(wifiDev);
    return SUCC;
}

int32_t WifiSetApWpsP2pIe(void *priv, const struct wpabuf *beacon, const struct wpabuf *probresp, const struct wpabuf *assocresp)
{
    int32_t loops;
    int32_t ret = SUCC;
    WifiAppIe *appIe = NULL;
    struct wpabuf *wpabufTmp = NULL;
    WifiDriverData *drv = (WifiDriverData *)priv;
    WifiCmd cmdAddr[4] = {{0x1, beacon}, {0x2, probresp}, {0x4, assocresp}, {-1, NULL}};
    errno_t rc;
    appIe = (WifiAppIe *)os_zalloc(sizeof(WifiAppIe));
    if (appIe == NULL) {
        wpa_printf(MSG_ERROR, "%s:failed to malloc WifiAppIe.", __FUNCTION__);
        return -EFAIL;
    }
    for (loops = 0; cmdAddr[loops].cmd != -1; loops++) {
        wpabufTmp = (struct wpabuf *)cmdAddr[loops].src;
        if (wpabufTmp != NULL) {
            appIe->appIeType = cmdAddr[loops].cmd;
            appIe->ieLen = wpabuf_len(wpabufTmp);
            if ((wpabufTmp->buf != NULL) && (appIe->ieLen != 0)) {
                appIe->ie = os_zalloc(appIe->ieLen);
                if (appIe->ie == NULL) {
                    wpa_printf(MSG_ERROR, "%s appIe->ie malloc failed.", __FUNCTION__);
                    os_free(appIe);
                    return -EFAIL;
                }
                rc = memcpy_s(appIe->ie, appIe->ieLen, wpabuf_head(wpabufTmp), wpabuf_len(wpabufTmp));
                if (rc != EOK) {
                    wpa_printf(MSG_ERROR, "%s: ", __FUNCTION__);
                    os_free(appIe->ie);
                    os_free(appIe);
                    return -EFAIL;
                }
            }
            wpa_printf(MSG_INFO, "%s type %d, ie_len %d.", __FUNCTION__, appIe->appIeType, appIe->ieLen);

            ret = WifiCmdSetApWpsP2pIe(drv->iface, appIe);
            os_free(appIe->ie);
            appIe->ie = NULL;
            if (ret < 0) {
                break;
            }
        }
    }
    os_free(appIe);
    appIe = NULL;
    return ret;
}

int32_t WifiWpaGetDrvFlags(void *priv, uint64_t *drvFlags)
{
    WifiDriverData *drv = NULL;
    WifiGetDrvFlags *params = NULL;
    int32_t ret;
    if (priv == NULL || drvFlags == NULL)
    {
        return -EFAIL;
    }
    drv = (WifiDriverData *)priv;
    params = (WifiGetDrvFlags *)os_zalloc(sizeof(WifiGetDrvFlags));
    if (params == NULL)
    {
        return -EFAIL;
    }
    params->drvFlags = 0;
    ret = WifiCmdGetDrvFlags(drv->iface, params);
    if (ret != SUCC)
    {
        wpa_printf(MSG_ERROR, "%s WifiCmdGetDrvFlags failed, ret is %d.", __FUNCTION__, ret);
        os_free(params);
        return -EFAIL;
    }
    *drvFlags = params->drvFlags;
    wpa_printf(MSG_INFO, "%s Get drvFlags done.", __FUNCTION__);
    os_free(params);
    return ret;
}
#endif // CONFIG_OHOS_P2P

const struct wpa_driver_ops g_wifiDriverOps = {
    .name = "hdf wifi",
    .desc = "wpa hdf adaptor layer",
    .get_bssid = WifiWpaGetBssid,
    .get_ssid = WifiWpaGetSsid,
    .set_key = WifiWpaSetKey,
    .scan2 = WifiWpaScan2,
    .get_scan_results2 = WifiWpaGetScanResults2,
    .deauthenticate = WifiWpaDeauthenticate,
    .associate = WifiWpaAssociate,
    .send_eapol = WifiWpaWpaSendEapol,
    .init2 = WifiWpaInit2,
    .deinit = WifiWpaDeinit,
    .set_ap = WifiWpaSetAp,
    .send_mlme = WifiWpaSendMlme,
    .get_hw_feature_data = WifiWpaGetHwFeatureData,
    .sta_remove = WifiWpaStaRemove,
    .hapd_init = WifiWpaHapdInit,
    .hapd_deinit = WifiWpaHapdDeinit,
    .hapd_send_eapol = WifiWpaHapdSendEapol,
    .send_action = WifiWpaSendAction,
    .get_mac_addr = WifiWpaGetMacAddr,
#ifdef CONFIG_OHOS_P2P
    .remain_on_channel = WifiRemainOnChannel,
    .cancel_remain_on_channel = WifiCancelRemainOnChannel,
    .probe_req_report = WifiProbeReqReport,
    .if_add = WifiAddIf,
    .if_remove = WifiRemoveIf,
    .set_ap_wps_ie = WifiSetApWpsP2pIe,
#endif // CONFIG_OHOS_P2P
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
