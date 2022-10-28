/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef DRIVER_NL80211_HISI_H
#define DRIVER_NL80211_HISI_H

#include "includes.h"
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include "nl80211_copy.h"

#include "common.h"
#include "eloop.h"
#include "utils/list.h"
#include "common/ieee802_11_defs.h"
#include "netlink.h"
#include "linux_ioctl.h"
#include "radiotap.h"
#include "radiotap_iter.h"
#include "rfkill.h"
#include "driver.h"

#ifdef CONFIG_LIBNL20
/* libnl 2.0 compatibility code */
#define nl_handle nl_sock
#define nl80211_handle_alloc nl_socket_alloc_cb
#define nl80211_handle_destroy nl_socket_free
#endif /* CONFIG_LIBNL20 */

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP   0x10000         /* driver signals L1 up */
#endif
#ifndef IFF_DORMANT
#define IFF_DORMANT    0x20000         /* driver signals dormant */
#endif

#ifndef IF_OPER_DORMANT
#define IF_OPER_DORMANT 5
#endif
#ifndef IF_OPER_UP
#define IF_OPER_UP 6
#endif

#define MAX_QOS_UP_RANGE  8
#define MAX_DSCP_EXCEPT   21  /* maximum of DSCP Exception fields for QoS Map set */
#define MAX_PRIV_CMD_SIZE		4096
#define WLAN_WPS_IE_MAX_SIZE    608
#define MAX_WPSP2PIE_CMD_SIZE   (WLAN_WPS_IE_MAX_SIZE + 8 + 32)  /* IE body + IE header + cmd length */
//#error duankaiyong 512
typedef unsigned char               uint8;
typedef char                        int8;
typedef short                       int16;
typedef unsigned short              uint16;
typedef unsigned int                uint32;
typedef int                         int32;
typedef unsigned long long          uint64;

typedef struct wifi_priv_cmd {
#ifdef CONFIG_DRIVER_NL80211_HISI_TRUNK
  char *buf;
  int total_len;
  int used_len;
#else
  int total_len;
  int used_len;
  char buf[MAX_PRIV_CMD_SIZE];
#endif
} wifi_priv_cmd;

typedef struct
{
    uint32  ul_ie_len;
    uint8   en_app_ie_type;
    uint8   auc_rsv[3];
    uint8   auc_ie[WLAN_WPS_IE_MAX_SIZE];
}oal_app_ie_stru;

enum SET_MLME_TYPE
{
    OAL_IEEE80211_MLME_AUTH         = 0,
    OAL_IEEE80211_MLME_ASSOC_RSP    = 1,
    OAL_IEEE80211_MLME_REASSOC_RSP  = 2,
    OAL_IEEE80211_MLME_NUM
};
typedef u8 en_set_mlme_type_uint8;

typedef struct
{
    en_set_mlme_type_uint8     en_mlme_type;
    u8                  uc_seq;
    u16                 us_status;
    u8                  uc_macaddr[6];
    u16                 us_ie_len;
    u8                  auc_ie[WLAN_WPS_IE_MAX_SIZE];
}set_mlme_stru;

/* P2P OPS parameter*/
typedef struct
{
    uint8       en_ops_ctrl;
    uint8       uc_ct_window;
    uint8       auc_rsv[2];
}oal_p2p_ops_param_stru;

/* P2P NOA parameter */
typedef struct
{
    uint32      ul_start_time;
    uint32      ul_duration;
    uint32      ul_interval;
    uint8       uc_count;
    uint8       auc_rsv[3];
}oal_p2p_noa_param_stru;

/* QoS Map SET ELEMENT */
typedef struct
{
    uint8  valid;
    uint8  num_dscp_except;
    uint8  up_low[MAX_QOS_UP_RANGE];
    uint8  up_high[MAX_QOS_UP_RANGE];
    uint8  dscp_exception_up[MAX_DSCP_EXCEPT];
    uint8  dscp_exception[MAX_DSCP_EXCEPT];
}oal_qos_map_param_stru;


/* supplicant customized struct. */
typedef struct cust_data_stru
{
    u32  read;
    u32  disable_capab_2ght40;
}cust_data_stru;

#endif  /* DRIVER_NL80211_HISI_H */
