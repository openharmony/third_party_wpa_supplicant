/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "wpa_magiclink.h"
#include <net/if.h>
#include "includes.h"
#include "common.h"
#include "common/ieee802_11_common.h"
#include "common/ieee802_11_defs.h"
#include "wps/wps_i.h"
#include "eap_peer/eap.h"

#include "wpa_supplicant_i.h"
#include "p2p_supplicant.h"
#include "bss.h"
#include "ctrl_iface.h"
#include "config.h"
#include "notify.h"
#include "securec.h"
#ifdef BRCM_VE
#include "wpa.h"
#include "wpa_i.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#endif /* BRCM_VE */

#define MANUFACTURER_LEN  32
#define MODEL_NAME_LEN    32
#define MODEL_NUMBER_LEN  16
#define DEVICE_NAME_LEN   64

#define HW_PENDING_EAPOL_EXPIRE_TIME_DEF     500 /* ms */
/*
 * used in wps_vendor_specific_ies(wpa_supplicant/scan.c)
 * wps vendor specific ies,
 */
struct wps_vendor_ies {
    char manufacturer[MANUFACTURER_LEN];
    char model_name[MODEL_NAME_LEN];
    char model_number[MODEL_NUMBER_LEN];
    char device_name[DEVICE_NAME_LEN];
};

#if defined(CONFIG_MAGICLINK)
/*lint -restore*/
#ifdef CONFIG_MAGICLINK_PC
static struct wpa_scan_res *hw_magiclink_gen_scan_res(const u8 *bssid, int freqency, int noGc)
{
#else
static struct wpa_scan_res *hw_magiclink_gen_scan_res(const u8 *bssid, int freqency)
{
#endif
    struct wpa_scan_res* res = NULL;
    unsigned char ie_data[] = {
        48, 20, 1,  0,  0, 15, 172, 4, 1, 0, 0,
        15, 172, 4, 1, 0, 0, 15, 172, 2, 12, 0 }; // RSN IE

    res = os_zalloc(sizeof(*res) + sizeof(ie_data) + sizeof(ie_data));
    if (!res) {
        wpa_printf(MSG_ERROR, "P2P: Failed to allocate memory for magiclink");
        return NULL;
    }

    res->flags = 11;
#ifdef CONFIG_MAGICLINK_PC
    if (noGc == 1) {
        res->legacyGO = 1;
    } else {
        res->legacyGO = 0;
    }
#endif
    os_memcpy(res->bssid, bssid, ETH_ALEN);

    res->freq = freqency;
    res->beacon_int = 100;
    res->caps = 1297;
    res->qual = 0;
    res->noise = 0;
    res->level = 0;
    res->tsf = 0;
    res->age = 0;
    res->ie_len = sizeof(ie_data);
    res->beacon_ie_len = sizeof(ie_data);
    os_memcpy(res + 1, ie_data, sizeof(ie_data));
    os_memcpy((char*)(res + 1) + res->ie_len, ie_data, sizeof(ie_data));

    return res;
}

static int hw_magiclink_get_ht40_mode(int channel)
{
    for (int op = 0; global_op_class[op].op_class; op++) {
        const struct oper_class_map *o = &global_op_class[op];
        u8 ch;

        if (o->mode != HOSTAPD_MODE_IEEE80211A)
            continue;

        for (ch = o->min_chan; ch <= o->max_chan; ch += o->inc) {
            if ((o->bw != BW40PLUS && o->bw != BW40MINUS) ||
                ch != channel)
                continue;
            return (o->bw == BW40MINUS) ? -1 : 1;
        }
    }
    return 0;
}

static int hw_magiclink_scan_param(struct wpa_supplicant *wpa_s)
{
    if (wpa_s == NULL) {
        wpa_printf(MSG_ERROR, "Parameter error,wpa_s == NULL");
        return -1;
    }

    wpa_s->scan_req = MANUAL_SCAN_REQ;

    int pri_chan = 0;
    enum hostapd_hw_mode hw_mode = ieee80211_freq_to_chan(wpa_s->magic_link_freq,
                                                         (u8 *)&pri_chan);
    if (hw_mode == NUM_HOSTAPD_MODES) {
        wpa_printf(MSG_ERROR, "frequency(%d MHz) error", wpa_s->magic_link_freq);
        return -1;
    }
    os_free(wpa_s->manual_scan_freqs);
    // 3:Number of channels:primary channel,secondary channel,0
    wpa_s->manual_scan_freqs = os_zalloc(3 * sizeof(int));
    if (wpa_s->manual_scan_freqs == NULL) {
        wpa_printf(MSG_ERROR, "alloc wpa_s->manual_scan_freqs failed");
        return -1;
    }
    wpa_s->manual_scan_freqs[0] = wpa_s->magic_link_freq;
    if (wpa_s->normal_scans && hw_mode == HOSTAPD_MODE_IEEE80211A) {
        int behavior = hw_magiclink_get_ht40_mode(pri_chan);
        // 5G channel to freq
        int sec_freq = 5000 + (pri_chan + behavior * 4) * 5;

        switch (behavior) {
        case -1:
            wpa_s->manual_scan_freqs[0] = sec_freq;
            wpa_s->manual_scan_freqs[1] = wpa_s->magic_link_freq;
            break;
        case 1:
            wpa_s->manual_scan_freqs[1] = sec_freq;
            break;
        default:
            break;
        }
    }
    wpa_printf(MSG_DEBUG, "%s: freq[0]=%d, freq[1]=%d", __func__, wpa_s->manual_scan_freqs[0],
                wpa_s->manual_scan_freqs[1]);
    return 0;
}

void hw_magiclink_scan(struct wpa_supplicant *wpa_s)
{
    if (!wpa_s) {
        wpa_msg(wpa_s, MSG_DEBUG,
                "magiclink: Start scan for network selection fail");
        return;
    }
    wpa_s->normal_scans = 0;
    hw_magiclink_scan_param(wpa_s);
    wpa_supplicant_req_scan(wpa_s, 0, 0);
    return;
}

void magiclink_prepare_scan(struct wpa_supplicant *wpa_s, int *timeout_usec)
{
    if (!wpa_s) {
        wpa_printf(MSG_ERROR, "Parameter error");
        return;
    }
    if (timeout_usec != NULL) {
        *timeout_usec = 50000;
    }
    if (wpa_s->normal_scans > 4) {
        return;
    }
    hw_magiclink_scan_param(wpa_s);
}

static int hw_magiclink_add_new_scan_res(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid, int freq, int noGc)
{
#define DEFAULT_SCAN_RES_SIZE 32
    struct os_reltime fetch_time;
    struct wpa_bss *bss = NULL;
    struct wpa_scan_res *res = NULL;
    struct wpa_bss **n = NULL;
    unsigned int siz = DEFAULT_SCAN_RES_SIZE;

#ifdef CONFIG_MAGICLINK_PC
    res = hw_magiclink_gen_scan_res(ssid->bssid, freq, noGc);
#else
    res = hw_magiclink_gen_scan_res(ssid->bssid, freq);
#endif

    if (!res) {
        wpa_printf(MSG_ERROR, "P2P: Failed to generate scan result");
        return -1;
    }

    os_get_reltime(&fetch_time);
    bss = hw_magiclink_bss_add(wpa_s, ssid->ssid, ssid->ssid_len, res, &fetch_time);
    if (!bss) {
        os_free(res);
        return -1;
    }

    n = os_realloc_array(wpa_s->last_scan_res, siz, sizeof(struct wpa_bss *));
    if (!n) {
        os_free(res);
        return -1;
    }
    wpa_s->last_scan_res = n;
    wpa_s->last_scan_res_size = siz;
    wpa_s->last_scan_res[0] = bss;
    wpa_s->last_scan_res_used = 1;
    os_free(res);
    return 0;
}

static int hw_magiclink_connect_parse_param(struct wpa_supplicant *wpa_s, const char *cmd,
    char **ppsk, char **pbssid, char **pfreq, int *noGc)
{
    char *pos = NULL;

    if (!wpa_s || !cmd || !ppsk || !pbssid || !pfreq || !noGc) {
        wpa_printf(MSG_ERROR, "%s param is null", __func__);
        return -1;
    }
    // ssid
    pos = os_strstr(cmd, "\n");
    if (!pos) {
        return -1;
    }
    *pos = '\0';

    // bssid
    *pbssid = pos + 1;
    pos = os_strstr(pos + 1, "\n");
    if (!pos) {
        return -1;
    }
    *pos = '\0';

    // password
    *ppsk = pos + 1;
    pos = os_strstr(pos + 1, "\n");
    if (!pos) {
        return -1;
    }
    *pos = '\0';
    // frequency
    *pfreq = pos + 1;

    return 0;
}

static struct wpa_ssid *hw_magiclink_add_network(struct wpa_supplicant *wpa_s, char *pssid,
    const char *pbssid, char *ppsk)
{
    struct wpa_ssid *ssid = wpa_config_add_network(wpa_s->conf);
    if (!ssid) {
        return NULL;
    }

    wpa_config_set_network_defaults(ssid);
    hw_magiclink_ctrl_iface_update_network(wpa_s, ssid, "ssid", pssid);
    hw_magiclink_ctrl_iface_update_network(wpa_s, ssid, "priority", "0");

    if (strcmp(ppsk, "\"\"") == 0) {
        wpa_printf(MSG_DEBUG, "key_mgmt is NONE");
        hw_magiclink_ctrl_iface_update_network(wpa_s, ssid, "key_mgmt", "NONE");
    } else {
        hw_magiclink_ctrl_iface_update_network(wpa_s, ssid, "key_mgmt", "WPA-PSK");
        hw_magiclink_ctrl_iface_update_network(wpa_s, ssid, "psk", ppsk);
    }
    if (hwaddr_aton(pbssid, ssid->bssid)) {
        wpa_printf(MSG_ERROR, "fail to parser bssid");
        return NULL;
    }
    ssid->bssid_set = 1;
    return ssid;
}

static int hw_magiclink_connect_known_ap(struct wpa_supplicant *wpa_s, char *cmd)
{
    /* cmd: "SSID BSSID PASSWORD FREQUENCY"
         "P"DIRECT-xx-xxxx" xx:xx:xx:xx:xx:xx "xxxxxxxx" 2412|2437|2462"
         "P\"DIRECT-XA-send\" 5a:7f:66:ae:a1:66 \"d9hHbPv0\" 2412" */
    char *pfreq = NULL;
    char *ppsk = NULL;
    char *pbssid = NULL;
    char *pssid = cmd;
    int freq;
    int noGc = 0xFF;

    if (hw_magiclink_connect_parse_param(wpa_s, cmd, &ppsk, &pbssid, &pfreq, &noGc)) {
        wpa_printf(MSG_DEBUG, "hw_magiclink_connect_parse_param failed");
        return -1;
    }
    struct wpa_ssid *ssid = hw_magiclink_add_network(wpa_s, pssid, pbssid, ppsk);
    if (!ssid) {
        wpa_printf(MSG_ERROR, "hw_magiclink_add_network failed");
        return -1;
    }
    freq = atoi(pfreq);
    if (hw_magiclink_add_new_scan_res(wpa_s, ssid, freq, noGc)) {
        wpa_printf(MSG_ERROR, "hw_magiclink_add_new_scan_res failed");
        return -1;
    }

    struct os_reltime now;
    os_get_reltime(&now);
    wpa_s->last_scan = now;
    wpa_s->magic_link_freq = freq;
    hw_magiclink_scan(wpa_s);
    wpa_s->disconnected = 0;
    wpa_s->reassociate = 1;
    ssid->p2p_group = 1;
    wpa_s->show_group_started = 1;
    return 0;
}

int hw_magiclink_p2p_ctrl_connect(struct wpa_supplicant *wpa_s, char *cmd)
{
    enum wpa_driver_if_type iftype;
    char p[256];
    wpa_printf(MSG_ERROR, "hw_magiclink_p2p_ctrl_connect");
    if (!wpa_s || !cmd) {
        wpa_printf(MSG_ERROR, "%s:wpa_s or cmd is null", __func__);
        return -1;
    }

    os_memset(p, 0, sizeof(p));
    wpa_s->create_p2p_iface = hw_magiclink_create_iface(wpa_s);
    iftype = WPA_IF_P2P_GROUP;
    /*
     * reltek chip don not support create p2p interface, use p2p0
     */
#ifdef CONFIG_SUPPORT_PLATEFORM_REALTEK
    struct wpa_supplicant *magiclink_wpa_s = wpa_s;
#else
    if (hw_magiclink_add_group_interface(wpa_s, iftype) < 0) {
        wpa_printf(MSG_ERROR, "P2P: Failed to allocate a new "
            "interface for the group");
        return -1;
    }

    struct wpa_supplicant *magiclink_wpa_s = hw_magiclink_init_group_interface(wpa_s, 0);
    if (!magiclink_wpa_s) {
        wpa_printf(MSG_ERROR, "P2P: Failed to get magiclink interface");
        return -1;
    }
#endif

    wpa_msg(wpa_s, MSG_INFO, "P2P-INTERFACE-CREATED GC %s",  magiclink_wpa_s->ifname);
    os_snprintf(p, sizeof(p), "P2P-INTERFACE-CREATED GC %s",  magiclink_wpa_s->ifname);
#ifdef MTK_SET_MAGIC_LINK_FLAG
    magiclink_wpa_s->is_magic_link = 1;
#endif
    wpa_s->global->p2p_group_formation = NULL;
    return hw_magiclink_connect_known_ap(magiclink_wpa_s, cmd);
}

int hw_wpas_p2p_group_add(struct wpa_supplicant *wpa_s,
    int network_id, int persistent, int freq, int max_band)
{
    int vht = wpa_s->conf->p2p_go_vht;
    int ht40 = wpa_s->conf->p2p_go_ht40 || vht;
    struct wpa_ssid* ssid =
        wpa_config_get_network(wpa_s->conf, network_id);
    if (ssid == NULL) {
        return wpas_p2p_group_add(
            wpa_s, persistent, freq, 0, ht40, vht, max_band, 0);
    } else if (ssid->disabled == 2) {
        return wpas_p2p_group_add_persistent(
            wpa_s, ssid, 0, freq, 0, 0, ht40, vht, max_band, 0, NULL, 0, 0);
    }
    return -1;
}
#endif

