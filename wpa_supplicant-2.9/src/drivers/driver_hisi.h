/*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
* Description: driver_hisi header
* Author: hisilicon
* Create: 2019-03-04
*/

#ifndef DRIVER_HISI_H
#define DRIVER_HISI_H

#include "driver.h"

typedef char int8;
typedef signed short int16;
typedef signed int int32;
typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

typedef signed long long int64;
typedef unsigned long long uint64;
typedef unsigned int size_t;
typedef signed int ssize_t;
typedef unsigned long ulong;
typedef signed long slong;

#define HISI_OK                         0
#define HISI_FAIL                       (-1)

#define HISI_SUCC 0
#define HISI_EFAIL  1
#define HISI_EINVAL 22

#ifndef ETH_ADDR_LEN
#define ETH_ADDR_LEN 6
#endif

#ifndef MAX_SSID_LEN
#define MAX_SSID_LEN 32
#endif

#ifndef HISI_MAX_NR_CIPHER_SUITES
#define HISI_MAX_NR_CIPHER_SUITES 5
#endif

#ifndef HISI_WPAS_MAX_SCAN_SSIDS
#define HISI_WPAS_MAX_SCAN_SSIDS     2
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#ifndef HISI_MAX_NR_AKM_SUITES
#define HISI_MAX_NR_AKM_SUITES 2
#endif

#ifndef	HISI_PTR_NULL
#define	HISI_PTR_NULL NULL
#endif

#ifndef	SCAN_AP_LIMIT
#define	SCAN_AP_LIMIT 64
#endif

#ifndef   NETDEV_UP
#define   NETDEV_UP   0x0001
#endif
#ifndef   NETDEV_DOWN
#define   NETDEV_DOWN 0x0002
#endif

#ifndef   NOTIFY_DONE
#define   NOTIFY_DONE 0x0000
#endif

#define WPA_MIN_KEY_LEN                 8
#define WPA_MAX_KEY_LEN                 64
#define WPA_HT_CAPA_LEN                 20
#define WPA_MAX_SSID_LEN                32
#define WPA_MAX_ESSID_LEN               WPA_MAX_SSID_LEN
#define WPA_AP_MIN_BEACON               33
#define WPA_AP_MAX_BEACON               1000
#define WPA_24G_FREQ_TXT_LEN            4
#define WPA_WEP40_KEY_LEN               5
#define WPA_WEP104_KEY_LEN              13
#define WPA_AP_MAX_DTIM                 30
#define WPA_AP_MIN_DTIM                 1
#define WPA_MAX_REKEY_TIME              86400
#define WPA_MIN_REKEY_TIME              30
#define WPA_DOUBLE_IFACE_WIFI_DEV_NUM   2
#define WPA_BASE_WIFI_DEV_NUM           1
#define WPA_MAX_WIFI_DEV_NUM            2
#define WPA_NETWORK_ID_TXT_LEN          sizeof(int)
#define WPA_CTRL_CMD_LEN                256
#define WPA_CMD_BUF_SIZE                64
#define WPA_MIN(x, y)                   (((x) < (y)) ? (x) : (y))
#define WPA_STR_LEN(x)                  (strlen(x) + 1)
#define WPA_EXTERNED_SSID_LEN           (WPA_MAX_SSID_LEN * 5)
#define WPA_CMD_BSSID_LEN               32
#define WPA_CMD_MIN_SIZE                16
#define WPA_MAX_NUM_STA                 8
#define WPA_SSID_SCAN_PREFEX_ENABLE     1
#define WPA_SSID_SCAN_PREFEX_DISABEL    0
#define WPA_P2P_INTENT_LEN              13
#define WPA_INT_TO_CHAR_LEN             11
#define WPA_P2P_PEER_CMD_LEN            27
#define WPA_P2P_MIN_INTENT              0
#define WPA_P2P_MAX_INTENT              15
#define WPA_DELAY_2S                    200
#define WPA_DELAY_3S                    300
#define WPA_DELAY_5S                    500
#define WPA_DELAY_10S                   1000
#define WPA_DELAY_60S                   6000
#define WPA_BIT0                        (1 << 0)
#define WPA_BIT1                        (1 << 1)
#define WPA_BIT2                        (1 << 2)
#define WPA_BIT3                        (1 << 3)
#define WPA_BIT4                        (1 << 4)
#define WPA_BIT5                        (1 << 5)
#define WPA_BIT6                        (1 << 6)
#define WPA_BIT7                        (1 << 7)
#define WPA_BIT8                        (1 << 8)
#define WPA_BIT9                        (1 << 9)
#define WPA_BIT10                       (1 << 10)
#define WPA_BIT11                       (1 << 11)
#define WPA_BIT12                       (1 << 12)
#define WPA_BIT13                       (1 << 13)
#define WPA_BIT14                       (1 << 14)
#define WPA_BIT15                       (1 << 15)
#define WPA_BIT16                       (1 << 16)
#define WPA_BIT17                       (1 << 17)
#define WPA_BIT18                       (1 << 18)
#define WPA_BIT19                       (1 << 19)
#define WPA_BIT20                       (1 << 20)
#define WPA_BIT21                       (1 << 21)
#define WPA_BIT22                       (1 << 22)
#define WPA_BIT23                       (1 << 23)
#define WPA_BIT24                       (1 << 24)
#define WPA_BIT26                       (1 << 26)
#define WPA_BIT27                       (1 << 27)
#define WPA_BIT28                       (1 << 28)
#define WPA_BIT29                       (1 << 29)
#define WPA_BIT30                       (1 << 30)

#define WPA_P2P_SCAN_MAX_CMD            32
#define WPA_P2P_IFNAME_MAX_LEN          10
#define WPA_P2P_DEFAULT_PERSISTENT      1
#define WPA_P2P_DEFAULT_GO_INTENT       6

#define MESH_AP                         1
#define MESH_STA                        0

#ifndef MAX_SSID_LEN
#define MAX_SSID_LEN                    32
#endif
#define MAX_DRIVER_NAME_LEN             16
#define WPA_MAX_SSID_KEY_INPUT_LEN      128
#define WPA_TXT_ADDR_LEN                17
#define WPA_INVITE_ADDR_LEN             23
#define WPA_24G_FREQ_TXT_LEN            4
#define WPA_INVITE_PERSISTENT_ID        13
#define WPA_STA_PMK_LEN                 32
#define WPA_STA_ITERA                   4096
#define WPA_MAX_TRY_FREQ_SCAN_CNT       3

#define WPA_FLAG_ON	 1
#define WPA_FLAG_OFF	0

typedef enum {
	HISI_FALSE = 0,
	HISI_TRUE = 1,

	HISI_BUTT
} hisi_bool_enum;
typedef uint8 hisi_bool_enum_uint8;

#define HISI_KEYTYPE_DEFAULT_INVALID (-1)
typedef uint8 hisi_iftype_enum_uint8;

typedef enum {
	HISI_KEYTYPE_GROUP,
	HISI_KEYTYPE_PAIRWISE,
	HISI_KEYTYPE_PEERKEY,

	NUM_HISI_KEYTYPES
} hisi_key_type_enum;
typedef uint8 hisi_key_type_enum_uint8;

typedef enum {
	HISI_KEY_DEFAULT_TYPE_INVALID,
	HISI_KEY_DEFAULT_TYPE_UNICAST,
	HISI_KEY_DEFAULT_TYPE_MULTICAST,

	NUM_HISI_KEY_DEFAULT_TYPES
} hisi_key_default_types_enum;
typedef uint8 hisi_key_default_types_enum_uint8;

typedef enum {
	HISI_NO_SSID_HIDING,
	HISI_HIDDEN_SSID_ZERO_LEN,
	HISI_HIDDEN_SSID_ZERO_CONTENTS
} hisi_hidden_ssid_enum;
typedef uint8 hisi_hidden_ssid_enum_uint8;

typedef enum {
	HISI_IOCTL_SET_AP = 0,
	HISI_IOCTL_NEW_KEY,
	HISI_IOCTL_DEL_KEY,
	HISI_IOCTL_SET_KEY,
	HISI_IOCTL_SEND_MLME,
	HISI_IOCTL_SEND_EAPOL,
	HISI_IOCTL_RECEIVE_EAPOL,
	HISI_IOCTL_ENALBE_EAPOL,
	HISI_IOCTL_DISABLE_EAPOL,
	HIIS_IOCTL_GET_ADDR,
	HISI_IOCTL_SET_MODE = 10,
	HIIS_IOCTL_GET_HW_FEATURE,
	HISI_IOCTL_SCAN,
	HISI_IOCTL_DISCONNET,
	HISI_IOCTL_ASSOC,
	HISI_IOCTL_SET_NETDEV,
	HISI_IOCTL_CHANGE_BEACON,
	HISI_IOCTL_SET_REKEY_INFO,
 	HISI_IOCTL_STA_REMOVE,
	HISI_IOCTL_SEND_ACTION,
	HISI_IOCTL_SET_MESH_USER,
	HISI_IOCTL_SET_MESH_GTK,
	HISI_IOCTL_EN_AUTO_PEER,
	HISI_IOCTL_EN_ACCEPT_PEER,
	HISI_IOCTL_EN_ACCEPT_STA,
	HISI_IOCTL_ADD_IF,
	HISI_IOCTL_PROBE_REQUEST_REPORT,
	HISI_IOCTL_REMAIN_ON_CHANNEL,
	HISI_IOCTL_CANCEL_REMAIN_ON_CHANNEL,
	HISI_IOCTL_SET_P2P_NOA,
	HISI_IOCTL_SET_P2P_POWERSAVE,
	HISI_IOCTL_SET_AP_WPS_P2P_IE,
	HISI_IOCTL_REMOVE_IF,
	HISI_IOCTL_GET_P2P_MAC_ADDR,
	HISI_IOCTL_GET_DRIVER_FLAGS,
	HISI_IOCTL_SET_USR_APP_IE,
	HWAL_EVENT_BUTT
} hisi_event_enum;
typedef uint8 hisi_event_enum_uint8;

typedef enum {
	HISI_ELOOP_EVENT_NEW_STA = 0,
	HISI_ELOOP_EVENT_DEL_STA,
	HISI_ELOOP_EVENT_RX_MGMT,
	HISI_ELOOP_EVENT_TX_STATUS,
	HISI_ELOOP_EVENT_SCAN_DONE,
	HISI_ELOOP_EVENT_SCAN_RESULT,
	HISI_ELOOP_EVENT_CONNECT_RESULT,
	HISI_ELOOP_EVENT_DISCONNECT,
	HISI_ELOOP_EVENT_MESH_CLOSE,
	HISI_ELOOP_EVENT_NEW_PEER_CANDIDATE,
	HISI_ELOOP_EVENT_REMAIN_ON_CHANNEL,
	HISI_ELOOP_EVENT_CANCEL_REMAIN_ON_CHANNEL,
	HISI_ELOOP_EVENT_CHANNEL_SWITCH,
	HISI_ELOOP_EVENT_EAPOL_RECV,
	HISI_ELOOP_EVENT_BUTT
} hisi_eloop_event_enum;
typedef uint8 hisi_eloop_event_enum_uint8;

typedef enum {
	HISI_MFP_NO,
	HISI_MFP_OPTIONAL,
	HISI_MFP_REQUIRED,
} hisi_mfp_enum;

typedef uint8 hisi_mfp_enum_uint8;

typedef enum {
	HISI_AUTHTYPE_OPEN_SYSTEM = 0,
	HISI_AUTHTYPE_SHARED_KEY,
	HISI_AUTHTYPE_FT,
	HISI_AUTHTYPE_NETWORK_EAP,
	HISI_AUTHTYPE_SAE,
	/* keep last */
	HISI_AUTHTYPE_NUM,
	HISI_AUTHTYPE_MAX = HISI_AUTHTYPE_NUM - 1,
	HISI_AUTHTYPE_AUTOMATIC,
	HISI_AUTHTYPE_BUTT
} hisi_auth_type_enum;
typedef uint8 hisi_auth_type_enum_uint8;

typedef enum {
    HI_WIFI_IFTYPE_UNSPECIFIED,
    HI_WIFI_IFTYPE_ADHOC,
    HI_WIFI_IFTYPE_STATION,
    HI_WIFI_IFTYPE_AP,
    HI_WIFI_IFTYPE_AP_VLAN,
    HI_WIFI_IFTYPE_WDS,
    HI_WIFI_IFTYPE_MONITOR,
    HI_WIFI_IFTYPE_MESH_POINT,
    HI_WIFI_IFTYPE_P2P_CLIENT,
    HI_WIFI_IFTYPE_P2P_GO,
    HI_WIFI_IFTYPE_P2P_DEVICE,

    HI_WIFI_IFTYPES_BUTT
} hi_wifi_iftype;

typedef enum {
	HISI_SCAN_SUCCESS,
	HISI_SCAN_FAILED,
	HISI_SCAN_REFUSED,
	HISI_SCAN_TIMEOUT
} hisi_scan_status_enum;

typedef enum {
    WAL_PHY_MODE_11N = 0,
    WAL_PHY_MODE_11G = 1,
    WAL_PHY_MODE_11B = 2,
    WAL_PHY_MODE_BUTT
 } hisi_phy_mode_enum;

typedef struct {
	hisi_scan_status_enum scan_status;
} hisi_driver_scan_status_stru;

typedef struct {
	unsigned int cmd;
	void *buf;
} hisi_ioctl_command_stru;

typedef int32 (*hisi_send_event_cb)(const char*, signed int, const unsigned char *, unsigned int);

typedef struct {
	int32  reassoc;
	size_t ielen;
	uint8  *ie;
	uint8  macaddr[ETH_ADDR_LEN];
	uint8  resv[2];
} hisi_new_sta_info_stru;

typedef struct {
	uint8  *buf;
	uint32 len;
	int32  sig_mbm;
	int32  freq;
} hisi_rx_mgmt_stru;

typedef struct {
	uint8                *buf;
	uint32               len;
	hisi_bool_enum_uint8 ack;
	uint8                resv[3];
} hisi_tx_status_stru;

typedef struct {
	uint32 freq;
	size_t data_len;
	uint8  *data;
	uint64 *send_action_cookie;
} hisi_mlme_data_stru;

typedef struct {
	size_t head_len;
	size_t tail_len;
	uint8 *head;
	uint8 *tail;
} hisi_beacon_data_stru;

typedef struct {
	uint8 *dst;
	uint8 *src;
	uint8 *bssid;
	uint8 *data;
	size_t data_len;
} hisi_action_data_stru;


typedef struct {
	int32 mode;
	int32 freq;
	int32 channel;

	/* for HT */
	int32 ht_enabled;

	/* 0 = HT40 disabled, -1 = HT40 enabled,
	 * secondary channel below primary, 1 = HT40
	 * enabled, secondary channel above primary */
	int32 sec_channel_offset;

	/* for VHT */
	int32 vht_enabled;

	/* valid for both HT and VHT, center_freq2 is non-zero
	 * only for bandwidth 80 and an 80+80 channel */
	int32 center_freq1;
	int32 center_freq2;
	int32 bandwidth;
} hisi_freq_params_stru;

typedef struct {
	int32                             type;
	uint32                            key_idx;
	uint32                            key_len;
	uint32                            seq_len;
	uint32                            cipher;
	uint8                             *addr;
	uint8                             *key;
	uint8                             *seq;
	hisi_bool_enum_uint8              def;
	hisi_bool_enum_uint8              defmgmt;
 	hisi_key_default_types_enum_uint8 default_types;
	uint8                             resv;
} hisi_key_ext_stru;

typedef struct {
	hisi_freq_params_stru       freq_params;
	hisi_beacon_data_stru       beacon_data;
	size_t                      ssid_len;
	int32                       beacon_interval;
	int32                       dtim_period;
	uint8                       *ssid;
	hisi_hidden_ssid_enum_uint8 hidden_ssid;
	hisi_auth_type_enum_uint8   auth_type;
	size_t                      mesh_ssid_len;
	uint8                       *mesh_ssid;
} hisi_ap_settings_stru;

typedef struct {
	uint8                  status;
	hisi_iftype_enum_uint8 iftype;
	hisi_phy_mode_enum     phy_mode;
} hisi_set_netdev_stru;

typedef struct {
	uint8                  bssid[ETH_ADDR_LEN];
	hisi_iftype_enum_uint8 iftype;
	uint8                  resv;
} hisi_set_mode_stru;

typedef struct {
	uint8  *puc_buf;
	uint32 len;
} hisi_tx_eapol_stru;

typedef struct {
	uint8  *buf;
	uint32 len;
} hisi_rx_eapol_stru;

typedef struct {
	void *callback;
	void *contex;
} hisi_enable_eapol_stru;

typedef struct {
	uint16 channel;
	uint8  resv[2];
	uint32 freq;
	uint32 flags;
} hisi_ieee80211_channel_stru;

typedef struct {
	int32                       channel_num;
	uint16                      bitrate[12];
	uint16                      ht_capab;
	uint8                       resv[2];
	hisi_ieee80211_channel_stru iee80211_channel[14];
} hisi_hw_feature_data_stru;

typedef struct {
	uint8  ssid[MAX_SSID_LEN];
	size_t ssid_len;
} hisi_driver_scan_ssid_stru;

typedef struct {
	hisi_driver_scan_ssid_stru *ssids;
	int32                      *freqs;
	uint8                      *extra_ies;
	uint8                      *bssid;
	uint8                      num_ssids;
	uint8                      num_freqs;
	uint8                      prefix_ssid_scan_flag;
	uint8                      fast_connect_flag;
	int32                      extra_ies_len ;
} hisi_scan_stru;

typedef struct {
	uint32 freq;
	uint32 duration;
} hisi_on_channel_stru;

typedef struct {
	uint8 type;
} hisi_if_add_stru;

typedef struct {
	int32 start;
	int32 duration;
	uint8 count;
	uint8 resv[3];
} hisi_p2p_noa_stru;

typedef struct {
	int32 legacy_ps;
	int8  opp_ps;
	uint8 ctwindow;
	int8  resv[2];
} hisi_p2p_power_save_stru;

typedef struct {
	uint8 ifname[IFNAMSIZ];
} hisi_if_remove_stru;

typedef struct {
	uint8 type;
	uint8 mac_addr[ETH_ADDR_LEN];
	uint8 resv;
} hisi_get_p2p_addr_stru;

typedef struct {
	hi_wifi_iftype iftype;
	uint8          *mac_addr;
} hisi_iftype_mac_addr_stru;
typedef struct {
	uint64 drv_flags;
} hisi_get_drv_flags_stru;

typedef struct {
	int32 freq;
} hisi_ch_switch_stru;

typedef struct {
	uint32 wpa_versions;
	uint32 cipher_group;
	int32  n_ciphers_pairwise;
	uint32 ciphers_pairwise[HISI_MAX_NR_CIPHER_SUITES];
	int32  n_akm_suites;
	uint32 akm_suites[HISI_MAX_NR_AKM_SUITES];
} hisi_crypto_settings_stru;

typedef struct {
	uint8                     *bssid;
	uint8                     *ssid;
	uint8                     *ie;
	uint8                     *key;
	uint8                     auth_type;
	uint8                     privacy;
	uint8                     key_len;
	uint8                     key_idx;
	uint8                     mfp;
	uint8                     rsv[3];
	uint32                    freq;
	uint32                    ssid_len;
	uint32                    ie_len;
	hisi_crypto_settings_stru *crypto;
} hisi_associate_params_stru;

typedef struct {
	uint8  *req_ie;
	size_t req_ie_len;
	uint8  *resp_ie;
	size_t resp_ie_len;
	uint8  bssid[ETH_ADDR_LEN];
	uint8  rsv[2];
	uint16 status;
	uint16 freq;
} hisi_connect_result_stru;

typedef struct {
	int32  flags;
	uint8  bssid[ETH_ADDR_LEN];
	int16  caps;
	int32  freq;
	int16  beacon_int;
	int32  qual;
	uint32 beacon_ie_len;
	int32  level;
	uint32 age;
	uint32 ie_len;
	uint8  *variable;

} hisi_scan_result_stru;

typedef struct {
	uint8  *ie;
	uint16 reason;
	uint8  rsv[2];
	uint32 ie_len;
} hisi_disconnect_stru;

typedef struct {
	uint8  macaddr[ETH_ADDR_LEN];
	uint16 reason;
} hisi_mesh_close_peer_stru;

typedef struct {
	uint8 peer_addr[ETH_ADDR_LEN];
	uint8 mesh_bcn_priority;
	uint8 mesh_is_mbr;
	int8  rssi;
	int8  reserved[3];
} hisi_mesh_new_peer_candidate_stru;

struct modes {
	int32 modes_num_rates;
	int32 mode;
};

typedef struct _hisi_driver_data_stru {
	struct hostapd_data *hapd;
	const int8 iface[IFNAMSIZ + 1];
	int8 resv[3];
	uint64 send_action_cookie;
	void *ctx;
	void *event_queue;
	hisi_iftype_enum_uint8 nlmode;
	struct l2_packet_data *eapol_sock;  /* EAPOL message sending and receiving channel */
	uint8 own_addr[ETH_ALEN];
	uint8 resv1[2];
	uint32 associated;
	uint8 bssid[ETH_ALEN];
	uint8 ssid[MAX_SSID_LEN];
	uint8 resv2[2];
	uint32 ssid_len;
	struct wpa_scan_res *res[SCAN_AP_LIMIT];
	uint32 scan_ap_num;
	uint32 beacon_set;
} hisi_driver_data_stru;


/*
struct hisi_wifi_dev {
	hi_wifi_iftype iftype;
	void *priv;
	int network_id;
	int ifname_len;
	char ifname[MAX_DRIVER_NAME_LEN + 1];
	char reserve[1];
};
*/
/*extern int wal_init_drv_wlan_netdev(hi_wifi_iftype type, hi_wifi_protocol_mode en_mode, char *ifname, int *len);
extern int wal_deinit_drv_wlan_netdev(const char *ifname);
void hisi_hapd_deinit(void *priv);
void hisi_wpa_deinit(void *priv);
int32 hisi_set_mesh_mgtk(const char *ifname, const uint8 *addr, const uint8 *mgtk, size_t mgtk_len);
int32 hisi_mesh_enable_flag(const char *ifname, enum hisi_mesh_enable_flag_type flag_type, uint8 enable_flag);
int32 hisi_get_drv_flags(void *priv, uint64 *drv_flags);
int32 hisi_get_p2p_mac_addr(void *priv, enum wpa_driver_if_type type, uint8 *mac_addr);*/

#endif /* DRIVER_HISI_H */
