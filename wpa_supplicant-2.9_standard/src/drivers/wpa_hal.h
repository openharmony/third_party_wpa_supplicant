/*
 * Driver interaction with hdf wifi
 * Copyright (c) 2020 Huawei Device Co., Ltd.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef _WPA_HAL_H_
#define _WPA_HAL_H_

#include "wifi_driver_client.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define SUCC 0
#define EFAIL 1
#define EINVAL 22

#define WEP_KEY_NUM 4
#define DEFAULT_NUM_MODES 2
#define WPA_BANDWIDTH_20 20
#define WPA_BANDWIDTH_40 40

#define SCAN_AP_LIMIT 64
#define SCAN_TIME_OUT 5

#define NETDEV_UP 0x0001
#define NETDEV_DOWN 0x0002

#define EAPOL_PKT_BUF_SIZE 800
#define CHECK_DHCP_TIME 30

#define WPA_WEP40_KEY_LEN 5
#define WPA_WEP104_KEY_LEN 13

#define WPA_FLAG_ON 1
#define WPA_FLAG_OFF 0

typedef enum {
    WPA_VERSION_1 = 1 << 0,
    WPA_VERSION_2 = 1 << 1,
} WpaVersions;

typedef enum {
    WIFI_CHAN_WIDTH_20_NOHT,
    WIFI_CHAN_WIDTH_20,
    WIFI_CHAN_WIDTH_40,
    WIFI_CHAN_WIDTH_BUTT
} WifiChannelWidth;

typedef enum {
    WIFI_DISCONNECT,
    WIFI_CONNECT,
} WifiConnectStatus;

typedef enum {
    WIFI_KEYTYPE_GROUP,
    WIFI_KEYTYPE_PAIRWISE,
    WIFI_KEYTYPE_PEERKEY,
    WIFI_KEYTYPE_BUTT
} WifiKeyType;

typedef enum {
    WIFI_KEY_DEFAULT_TYPE_INVALID,
    WIFI_KEY_DEFAULT_TYPE_UNICAST,
    WIFI_KEY_DEFAULT_TYPE_MULTICAST,
    WIFI_KEY_DEFAULT_TYPES
} WifiKeyDefaultType;

typedef enum {
    WIFI_NO_SSID_HIDING,
    WIFI_HIDDEN_SSID_ZERO_LEN,
    WIFI_HIDDEN_SSID_ZERO_CONTENTS
} WifiHiddenSsid;

typedef enum {
    WIFI_MESH_ENABLE_AUTO_PEER,
    WIFI_MESH_ENABLE_ACCEPT_PEER,
    WIFI_MESH_ENABLE_ACCEPT_STA,
    WIFI_MESH_ENABLE_FLAG_BUTT
} WifiMeshEnableFlagType;

typedef enum {
    WIFI_AUTHTYPE_OPEN_SYSTEM = 0,
    WIFI_AUTHTYPE_SHARED_KEY,
    WIFI_AUTHTYPE_FT,
    WIFI_AUTHTYPE_EAP,
    WIFI_AUTHTYPE_SAE,
    WIFI_AUTHTYPE_AUTOMATIC,
    WIFI_AUTHTYPE_BUTT
} WifiAuthType;

typedef enum {
    WIFI_SCAN_SUCCESS,
    WIFI_SCAN_FAILED,
    WIFI_SCAN_REFUSED,
    WIFI_SCAN_TIMEOUT
} WifiScanStatus;

typedef struct {
    int32_t numRates;
    int32_t mode;
} WifiModes;

typedef struct {
    uint8_t *addr;
    uint8_t plinkState;
    uint8_t set;
    uint8_t meshBcnPriority;
    uint8_t meshIsMbr;
    uint8_t meshInitiativePeering;
} WifiMeshUsrParams;

typedef struct {
    uint8_t *addr;
    uint8_t *gtk;
    uint8_t gtkLen;
    uint8_t resv[3];
} WifiSetMeshUsrGtk;

typedef struct {
    uint8_t *buf;
    uint32_t len;
} WifiTxEapol;

typedef struct {
    void *callback;
    void *contex;
} WifiEnableEapol;

typedef struct {
    int32_t start;
    int32_t duration;
    uint8_t count;
    uint8_t resv[3];
} WifiP2pNoa;

typedef struct {
    int32_t legacyPs;
    int8_t oppPs;
    uint8_t ctWindow;
    int8_t resv[2];
} WifiP2pPowerSave;

typedef struct {
    uint8_t type;
    uint8_t macAddr[ETH_ADDR_LEN];
    uint8_t resv;
} WifiGetP2pAddr;

typedef struct {
    enum WifiIfType iftype;
    uint8_t *macAddr;
} WifiIftypeMacAddr;

typedef struct {
    int32_t freq;
} WifiChannelSwitch;

typedef struct {
    uint8_t macAddr[ETH_ADDR_LEN];
    uint16_t reason;
} WifiMeshClosePeer;

typedef struct {
    uint8_t peerAddr[ETH_ADDR_LEN];
    uint8_t meshBcnPriority;
    uint8_t meshIsMbr;
    int8_t rssi;
    int8_t reserved[3];
} WifiMeshNewPeerCandidate;

typedef struct {
    struct hostapd_data *hapd;
    char iface[IFNAMSIZ + 1];
    int8_t resv[3];
    uint64_t actionCookie;
    void *ctx;
    void *eventQueue;

    struct l2_packet_data *eapolSock;
    uint8_t ownAddr[ETH_ADDR_LEN];

    uint32_t associated;
    uint8_t bssid[ETH_ADDR_LEN];
    uint8_t ssid[MAX_SSID_LEN];
    int32_t ssidLen;

    struct wpa_scan_res *scanRes[SCAN_AP_LIMIT];
    uint32_t scanNum;
    uint32_t beaconSet;
    uint8_t mode;
} WifiDriverData;

typedef struct {
    int32_t cmd;
    const struct wpabuf *src;
} WifiCmd;

typedef struct {
    enum WifiIfType ifType;
    WifiDriverData *priv;
    int32_t networkId;
    int32_t ifNameLen;
    char ifName[IFNAMSIZ + 1];
    char reserver[1];
} WifiDev;

WifiDriverData *GetDrvData();
void WifiWpaScanTimeout(void *eloop, void *ctx);
int32_t WifiWpaGetDrvFlags(void *priv, uint64_t *drvFlags);
WifiDev *GetWifiDevByName(const char *ifName);

void WifiWpaNewStaProcess(WifiDriverData *drv, WifiNewStaInfo *staInfo);
void WifiWpaDelStaProcess(WifiDriverData *drv, uint8_t *addr);
void WifiWpaRxMgmtProcess(WifiDriverData *drv, WifiRxMgmt *rxMgmt);
void WifiWpaTxStatusProcess(WifiDriverData *drv, WifiTxStatus *txStatus);
void WifiWpaScanDoneProcess(WifiDriverData *drv, uint32_t *status);
void WifiWpaScanResultProcess(WifiDriverData *drv, WifiScanResult *scanResult);
void WifiWpaConnectResultProcess(WifiDriverData *drv, WifiConnectResult *result);
void WifiWpaDisconnectProcess(WifiDriverData *drv, WifiDisconnect *result);
void WifiWpaDriverEapolRecvProcess(WifiDriverData *drv, void *data);
void WifiWpaRemainOnChannelProcess(WifiDriverData *drv, WifiOnChannel *result);
void WifiWpaCancelRemainOnChannelProcess(WifiDriverData *drv, WifiOnChannel *result);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of wpa_hal.h */
