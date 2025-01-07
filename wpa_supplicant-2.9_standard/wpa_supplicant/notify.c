/*
 * wpa_supplicant - Event notifications
 * Copyright (c) 2009-2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/wpa_ctrl.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "wps_supplicant.h"
#include "binder/binder.h"
#include "dbus/dbus_common.h"
#include "dbus/dbus_new.h"
#include "rsn_supp/wpa.h"
#include "rsn_supp/pmksa_cache.h"
#include "fst/fst.h"
#include "crypto/tls.h"
#include "bss.h"
#include "driver_i.h"
#include "scan.h"
#include "p2p_supplicant.h"
#include "sme.h"
#include "notify.h"
#if defined(CONFIG_LIBWPA_VENDOR) || defined(OHOS_EUPDATER)
#include "wpa_client.h"
#endif
#ifdef CONFIG_OPEN_HARMONY_MIRACAST_MAC
#include "common/ieee802_11_defs.h"
#endif
#ifdef CONFIG_EAP_AUTH
#include "crypto/milenage.h"
#include "eloop.h"
#include "eap_defs.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "eap_peer/eap_i.h"
#include "eap_common/eap_sim_common.h"
#include "securec.h"

#ifdef CONFIG_P2P_CHR
#include "wpa_hw_p2p_chr.h"
#endif

#define HEX_OPC_LEN 16
#define HEX_AMF_LEN 2
#define HEX_KI_LEN 16
#define HEX_SQN_LEN 6
struct NetRspEapSimGsmAuthParams eapsim_params;
struct NetRspEapAkaUmtsAuthParams eapaka_params;
#endif
#ifdef CONFIG_VENDOR_EXT
#include "vendor_ext.h"
#endif

#define STA_NOTIFY_PARAM_LEN 128

#if defined(CONFIG_OPEN_HARMONY_PATCH) && defined(CONFIG_HILINK_OKC_STA)
#define HILINK_PARAM_SIZE 64
#endif
#ifdef CONFIG_OPEN_HARMONY_PATCH
#define MLO_STATE_SIZE 64
#endif

int wpas_notify_supplicant_initialized(struct wpa_global *global)
{
#ifdef CONFIG_CTRL_IFACE_DBUS_NEW
	if (global->params.dbus_ctrl_interface) {
		global->dbus = wpas_dbus_init(global);
		if (global->dbus == NULL)
			return -1;
	}
#endif /* CONFIG_CTRL_IFACE_DBUS_NEW */

#ifdef CONFIG_BINDER
	global->binder = wpas_binder_init(global);
	if (!global->binder)
		return -1;
#endif /* CONFIG_BINDER */

	return 0;
}


void wpas_notify_supplicant_deinitialized(struct wpa_global *global)
{
#ifdef CONFIG_CTRL_IFACE_DBUS_NEW
	if (global->dbus)
		wpas_dbus_deinit(global->dbus);
#endif /* CONFIG_CTRL_IFACE_DBUS_NEW */

#ifdef CONFIG_BINDER
	if (global->binder)
		wpas_binder_deinit(global->binder);
#endif /* CONFIG_BINDER */
}


int wpas_notify_iface_added(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return 0;

	if (wpas_dbus_register_interface(wpa_s))
		return -1;

	return 0;
}


void wpas_notify_iface_removed(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	/* unregister interface in new DBus ctrl iface */
	wpas_dbus_unregister_interface(wpa_s);
}


void wpas_notify_state_changed(struct wpa_supplicant *wpa_s,
			       enum wpa_states new_state,
			       enum wpa_states old_state)
{
	if (wpa_s->p2p_mgmt)
		return;

	/* notify the new DBus API */
	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_STATE);

#ifdef CONFIG_FST
	if (wpa_s->fst && !is_zero_ether_addr(wpa_s->bssid)) {
		if (new_state == WPA_COMPLETED)
			fst_notify_peer_connected(wpa_s->fst, wpa_s->bssid);
		else if (old_state >= WPA_ASSOCIATED &&
			 new_state < WPA_ASSOCIATED)
			fst_notify_peer_disconnected(wpa_s->fst, wpa_s->bssid);
	}
#endif /* CONFIG_FST */

	if (new_state == WPA_COMPLETED)
		wpas_p2p_notif_connected(wpa_s);
	else if (old_state >= WPA_ASSOCIATED && new_state < WPA_ASSOCIATED)
		wpas_p2p_notif_disconnected(wpa_s);

	sme_state_changed(wpa_s);

#ifdef ANDROID
	wpa_msg_ctrl(wpa_s, MSG_INFO, WPA_EVENT_STATE_CHANGE
		     "id=%d state=%d BSSID=" MACSTR " SSID=%s",
		     wpa_s->current_ssid ? wpa_s->current_ssid->id : -1,
		     new_state,
		     MAC2STR(wpa_s->bssid),
		     wpa_s->current_ssid && wpa_s->current_ssid->ssid ?
		     wpa_ssid_txt(wpa_s->current_ssid->ssid,
				  wpa_s->current_ssid->ssid_len) : "");
#endif /* ANDROID */
	wpa_printf(MSG_DEBUG, "prepare call onEventStateChanged");
#if defined(CONFIG_LIBWPA_VENDOR) || defined(OHOS_EUPDATER)
	struct WpaStateChangedParam wpaStateChangedParma;
	os_memset(&wpaStateChangedParma, 0, sizeof(struct WpaStateChangedParam));
	os_memcpy(wpaStateChangedParma.bssid, wpa_s->bssid, ETH_ALEN);
	wpaStateChangedParma.status = new_state;
	wpaStateChangedParma.networkId = wpa_s->current_ssid ? wpa_s->current_ssid->id : -1;
	if (wpa_s->current_ssid && wpa_s->current_ssid->ssid) {
		os_memcpy(wpaStateChangedParma.ssid, wpa_s->current_ssid->ssid, wpa_s->current_ssid->ssid_len);
		wpa_printf(MSG_EXCESSIVE, "id = %d state = %d BSSID = " MACSTR_SEC " SSID = %s", wpaStateChangedParma.networkId,
			wpaStateChangedParma.status, MAC2STR_SEC(wpa_s->bssid), wpaStateChangedParma.ssid);
	} else {
		wpa_printf(MSG_EXCESSIVE, "wpaStateChangedParma.ssid = NULL");
	}
	WpaEventReport(wpa_s->ifname, WPA_EVENT_STATE_CHANGED, (void *) &wpaStateChangedParma);
#endif

#ifdef CONFIG_VENDOR_EXT
	if (new_state == WPA_ASSOCIATING) {
		char old_ap_vendor_info[MAX_AP_VENDOR_INFO_LEN] = {0};
		strcpy_s(old_ap_vendor_info, sizeof(old_ap_vendor_info), wpa_s->ap_vendor_info);

		/* update ap_vendor_info */
		for (int i = 0; i < wpa_s->last_scan_res_used; i++) {
			struct wpa_bss *bss = wpa_s->last_scan_res[i];
			if (os_memcmp(wpa_s->pending_bssid, bss->bssid, ETH_ALEN) == 0) {
				wpa_printf(MSG_INFO, "wpa_bss_get_vendor_specific_ies match bssid");
				wpa_bss_get_vendor_specific_ies(wpa_s, bss);
			}
		}

		/* notify ap_vendor_info if it is updated */
		if (strcmp(wpa_s->ap_vendor_info, old_ap_vendor_info) != 0) {
			wpa_printf(MSG_INFO, "ap_vendor_info updated, notify it");
			notify_ap_vendor_info(wpa_s->ap_vendor_info);
		}
	}
#endif /* CONFIG_VENDOR_EXT */
}


void wpas_notify_disconnect_reason(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_DISCONNECT_REASON);
}


void wpas_notify_auth_status_code(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_AUTH_STATUS_CODE);
}


void wpas_notify_assoc_status_code(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_ASSOC_STATUS_CODE);
}


void wpas_notify_roam_time(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_ROAM_TIME);
}


void wpas_notify_roam_complete(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_ROAM_COMPLETE);
}


void wpas_notify_session_length(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_SESSION_LENGTH);
}


void wpas_notify_bss_tm_status(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_BSS_TM_STATUS);
}


void wpas_notify_network_changed(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_CURRENT_NETWORK);
}


void wpas_notify_ap_scan_changed(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_AP_SCAN);
}


void wpas_notify_bssid_changed(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_CURRENT_BSS);
#ifdef CONFIG_OPEN_HARMONY_PATCH
	const u8 *bssid;
	const char *reason = NULL;
	if (is_zero_ether_addr(wpa_s->bssid) &&
	    !is_zero_ether_addr(wpa_s->pending_bssid)) {
		bssid = wpa_s->pending_bssid;
		reason = "ASSOC_START";
	} else if (!is_zero_ether_addr(wpa_s->bssid) &&
		is_zero_ether_addr(wpa_s->pending_bssid)) {
		bssid = wpa_s->bssid;
		reason = "ASSOC_COMPLETE";
	} else if (is_zero_ether_addr(wpa_s->bssid) &&
		is_zero_ether_addr(wpa_s->pending_bssid)) {
		bssid = wpa_s->pending_bssid;
		reason = "DISASSOC";
	} else {
		wpa_printf(MSG_ERROR, "Unknown bssid change reason");
		return;
	}
	wpa_msg_ctrl(wpa_s, MSG_INFO, WPA_EVENT_BSSID_CHANGED " REASON=%s BSSID=" MACSTR, reason, MAC2STR(bssid));
#if defined(CONFIG_LIBWPA_VENDOR) || defined(OHOS_EUPDATER)
	struct WpaBssidChangedParam wpaBssidChangedParma;
	os_memcpy(wpaBssidChangedParma.bssid, wpa_s->bssid, ETH_ALEN);
	os_memcpy(wpaBssidChangedParma.reason, reason, strlen(reason));
	WpaEventReport(wpa_s->ifname, WPA_EVENT_BSSID_CHANGE, (void *) &wpaBssidChangedParma);
#endif
#endif // CONFIG_OPEN_HARMONY_PATCH
}

#ifdef CONFIG_MLD_PATCH
void wpas_notify_bssid_changed_ext(struct wpa_supplicant *wpa_s, char *reason)
{
	if (wpa_s->p2p_mgmt)
		return;
	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_CURRENT_BSS);
#ifdef CONFIG_OPEN_HARMONY_PATCH
	const u8 *bssid;
	bssid = wpa_s->bssid;
	wpa_msg_ctrl(wpa_s, MSG_INFO, WPA_EVENT_BSSID_CHANGED " REASON=%s BSSID=" MACSTR, reason, MAC2STR(bssid));
	#if defined(CONFIG_LIBWPA_VENDOR) || defined(OHOS_EUPDATER)
	struct WpaBssidChangedParam wpaBssidChangedParma;
	os_memcpy(wpaBssidChangedParma.bssid, wpa_s->bssid, ETH_ALEN);
	os_memcpy(wpaBssidChangedParma.reason, reason, strlen(reason));
	WpaEventReport(wpa_s->ifname, WPA_EVENT_BSSID_CHANGE, (void *) &wpaBssidChangedParma);
	#endif
#endif // CONFIG_OPEN_HARMONY_PATCH
}
#endif

void wpas_notify_mac_address_changed(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_MAC_ADDRESS);
}

void wpas_notify_mlo_work_state_changed(struct wpa_supplicant *wpa_s, struct mlo_work_state_event *mlo_event)
{
	if (wpa_s->p2p_mgmt)
		return;

#ifdef CONFIG_OPEN_HARMONY_PATCH
	wpa_msg_ctrl(wpa_s, MSG_INFO, "notify_mlo_work_state feature=%d state=%d reason_code=%d",
				 mlo_event->feature, mlo_event->state, mlo_event->reason_code);

	wpa_printf(MSG_INFO, "notify_mlo_work_state feature=%d state=%d reason_code=%d",
		mlo_event->feature, mlo_event->state, mlo_event->reason_code);

	char param[MLO_STATE_SIZE] = {0};
	sprintf(param, "05:%d:%d:%d", mlo_event->feature, mlo_event->state, mlo_event->reason_code);
#if defined(CONFIG_LIBWPA_VENDOR) || defined(OHOS_EUPDATER)
	WpaEventReport(wpa_s->ifname, WPA_EVENT_STA_NOTIFY, (void *)param);
#endif
#endif // CONFIG_OPEN_HARMONY_PATCH
}

void wpas_notify_auth_changed(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_CURRENT_AUTH_MODE);
}


void wpas_notify_network_enabled_changed(struct wpa_supplicant *wpa_s,
					 struct wpa_ssid *ssid)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_network_enabled_changed(wpa_s, ssid);
}


void wpas_notify_network_selected(struct wpa_supplicant *wpa_s,
				  struct wpa_ssid *ssid)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_network_selected(wpa_s, ssid->id);
}

#ifdef CONFIG_EAP_AUTH
int send_network_eapsim_gsmauth_response_internal(struct NetRspEapSimGsmAuthParams vecParams,
	struct wpa_supplicant *wpaSupp, struct wpa_ssid *ssid)
{
	size_t i, j, ret = 0;
	char Params[PAR_MAX] = {0};
	enum wpa_ctrl_req_type reqType = WPA_CTRL_REQ_SIM;
	char* sim_params[] = {":", vecParams.kc, ":", vecParams.sres};

	wpa_printf(MSG_INFO, "notify sim ssid= %p", ssid);
	if (strncpy_s(Params, PAR_MAX, "GSM-AUTH", strlen("GSM-AUTH")) != 0) {
		return ret;
	}
	for (j = 0; j < ACT_NUM; j++) {
		for (i = 0; i < (sizeof(sim_params) / sizeof(sim_params[0])); i++) {
			if (strncat_s(Params, PAR_MAX - strlen(Params), sim_params[i], PAR_MAX - strlen(Params) - 1) == 0) {
				wpa_printf(MSG_INFO, "write %s success", sim_params[i]);
			}
		}
	}

	wpa_printf(MSG_INFO, "notify sim wpaSupp=%p RspParam=%s", wpaSupp, Params);
	if (wpa_supp_ctl_response_hdl(ssid, reqType, Params)) {
		wpa_printf(MSG_INFO, "notify sim wpa_supp_ctl_response_hdl succ");
		ret = 1;
	}

	eapol_sm_notify_ctrl_response(wpaSupp->eapol);
	return ret;
}

static void wpas_send_network_eapsim_gsmauth_response_internal(void *eloopCtx, void *timeoutCtx)
{
	struct wpa_supplicant *wpaS = eloopCtx;
	struct wpa_ssid *ssid = timeoutCtx;
	struct NetRspEapSimGsmAuthParams params;

	os_memcpy(params.kc, eapsim_params.kc, os_strlen(eapsim_params.kc));
	os_memcpy(params.sres, eapsim_params.sres, os_strlen(eapsim_params.sres));
	wpa_printf(MSG_DEBUG, "get eap sim params successful "
		"kc=%s sres=%s, ssid->id=%d", params.kc, params.sres, ssid->id);
	if (send_network_eapsim_gsmauth_response_internal(params, wpaS, ssid)) {
		wpa_printf(MSG_INFO, "send_network_eapsim_gsmauth_response_internal succ");
	}
}

static int copy_rsp_param(char* Params, struct NetRspEapAkaUmtsAuthParams vecParams)
{
       int ret = 0;
       size_t i;
       char* aka_params[] = {":", vecParams.ik, ":", vecParams.ck, ":", vecParams.res};
       for (i = 0; i < (sizeof(aka_params) / sizeof(aka_params[0])); i++) {
               if (strncat_s(Params, PAR_MAX - strlen(Params), aka_params[i], PAR_MAX - strlen(Params) - 1) != 0) {
                       return ret;
               }
       }
       if (i == (sizeof(aka_params) / sizeof(aka_params[0]) - 1)) {
               ret = 1;
       }
       return ret;
}

int send_network_eapaka_umtsauth_response_internal(struct NetRspEapAkaUmtsAuthParams vecParams,
	struct wpa_supplicant *wpaSupp, struct wpa_ssid *ssid)
{
	size_t ret = 0;
	char Params[PAR_MAX] = {0};
	enum wpa_ctrl_req_type reqType = WPA_CTRL_REQ_SIM;
	if (strncpy_s(Params, PAR_MAX, "UMTS-AUTH", strlen("UMTS-AUTH")) != 0) {
		return ret;
	}

	wpa_printf(MSG_INFO, "notify aka ssid= %p", ssid);
	if (copy_rsp_param(Params, vecParams)) {
		wpa_printf(MSG_INFO, "get aka ctrlRspParam success");
	}

	wpa_printf(MSG_INFO, "notify aka wpaSupp=%p Param=%s", wpaSupp, Params);
	if (wpa_supp_ctl_response_hdl(ssid, reqType, Params)) {
		wpa_printf(MSG_INFO, "notify aka wpa_supp_ctl_response_hdl succ");
		ret = 1;
	}
	eapol_sm_notify_ctrl_response(wpaSupp->eapol);
	return ret;
}

static void wpas_send_network_eapaka_umtsauth_response_internal(void *eloopCtx, void *timeoutCtx)
{
	struct wpa_supplicant *wpaS = eloopCtx;
	struct wpa_ssid *ssid = timeoutCtx;
	struct NetRspEapAkaUmtsAuthParams params;
	const unsigned char *localEapakaRand;
	size_t res_len;
	u8 local_autn[EAP_AKA_AUTN_LEN];
	u8 local_ik[EAP_AKA_IK_LEN];
	u8 local_ck[EAP_AKA_CK_LEN];
	u8 local_res[EAP_AKA_RES_MAX_LEN];

	u8 local_opc[HEX_OPC_LEN];
	u8 local_amf[HEX_AMF_LEN];
	u8 local_ki[HEX_KI_LEN];
	u8 local_sqn[HEX_SQN_LEN];

	wpa_printf(MSG_INFO, "WpasSendNetworkEapAkaUMTSAuthResponseInternal ssid->id= %d", ssid->id);
	res_len = EAP_AKA_RES_MAX_LEN;
	localEapakaRand = eapaka_rand;
	hexstr2bin(eapaka_params.opc, local_opc, sizeof(local_opc));
	hexstr2bin(eapaka_params.amf, local_amf, sizeof(local_amf));
	hexstr2bin(eapaka_params.ki, local_ki, sizeof(local_ki));
	hexstr2bin(eapaka_params.sqn, local_sqn, sizeof(local_sqn));

	milenage_generate(local_opc, local_amf, local_ki, local_sqn, localEapakaRand,
		local_autn, local_ik, local_ck, local_res, &res_len);
	bin2hexstr(local_ik, sizeof(local_ik), params.ik, sizeof(params.ik));
	bin2hexstr(local_ck, sizeof(local_ck), params.ck, sizeof(params.ck));
	bin2hexstr(local_res, sizeof(local_res), params.res, sizeof(params.res));

	if (os_memcmp(eapaka_autn, local_autn, EAP_AKA_AUTN_LEN) == 0) {
		if (send_network_eapaka_umtsauth_response_internal(params, wpaS, ssid)) {
			wpa_printf(MSG_INFO, "send_network_eapaka_umtsauth_response_internal succ");
		}
	} else {
		os_memset(params.ik, 0, sizeof(params.ik));
		os_memset(params.ck, 0, sizeof(params.ck));
		os_memset(params.res, 0, sizeof(params.res));
		send_network_eapaka_umtsauth_response_internal(params, wpaS, ssid);
	}
}
#endif

static int wpas_hdi_notify_network_request(struct wpa_supplicant *wpa_s,
					   struct wpa_ssid *ssid,
					   int type, const char *param)
{
	if (!wpa_s || !ssid) {
		return 0;
	}
	wpa_printf(MSG_DEBUG, "Notifying network request to hdi control: %d %s", ssid->id, param);

#if defined(CONFIG_LIBWPA_VENDOR) || defined(OHOS_EUPDATER)
	if (type == WPA_CTRL_REQ_SIM) {
		char data[STA_NOTIFY_PARAM_LEN] = { 0 };
		sprintf(data, "02:%s", param);
		WpaEventReport(wpa_s->ifname, WPA_EVENT_STA_NOTIFY, (void *)data);
		return 1;
	}
#endif
	return 0;
}

void wpas_notify_network_request(struct wpa_supplicant *wpa_s,
				 struct wpa_ssid *ssid,
				 enum wpa_ctrl_req_type rtype,
				 const char *default_txt)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_network_request(wpa_s, ssid, rtype, default_txt);
	if (wpas_hdi_notify_network_request(wpa_s, ssid, rtype, default_txt) == 0) {
		return;
	}
#ifdef CONFIG_EAP_AUTH
	if (eapol_sm_get_eap(wpa_s->eapol)->selectedMethod == EAP_TYPE_SIM) {
		eloop_register_timeout(1, 0, wpas_send_network_eapsim_gsmauth_response_internal, wpa_s, ssid);
	} else if (eapol_sm_get_eap(wpa_s->eapol)->selectedMethod == EAP_TYPE_AKA) {
		wpa_printf(MSG_INFO, "eloop_register_timeout hdl rsp for AKA");
		eloop_register_timeout(1, 0, wpas_send_network_eapaka_umtsauth_response_internal, wpa_s, ssid);
	} else if (eapol_sm_get_eap(wpa_s->eapol)->selectedMethod == EAP_TYPE_AKA_PRIME) {
		wpa_printf(MSG_INFO, "eloop_register_timeout hdl rsp for AKA'");
		eloop_register_timeout(1, 0, wpas_send_network_eapaka_umtsauth_response_internal, wpa_s, ssid);
	} else {
		wpa_printf(MSG_INFO, "wpas_notify_network_request do nothing");
	}
#endif
}


void wpas_notify_scanning(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	/* notify the new DBus API */
	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_SCANNING);
}


void wpas_notify_scan_done(struct wpa_supplicant *wpa_s, int success)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_scan_done(wpa_s, success);
}


void wpas_notify_scan_results(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_wps_notify_scan_results(wpa_s);
}


void wpas_notify_wps_credential(struct wpa_supplicant *wpa_s,
				const struct wps_credential *cred)
{
	if (wpa_s->p2p_mgmt)
		return;

#ifdef CONFIG_WPS
	/* notify the new DBus API */
	wpas_dbus_signal_wps_cred(wpa_s, cred);
#endif /* CONFIG_WPS */
}


void wpas_notify_wps_event_m2d(struct wpa_supplicant *wpa_s,
			       struct wps_event_m2d *m2d)
{
	if (wpa_s->p2p_mgmt)
		return;

#ifdef CONFIG_WPS
	wpas_dbus_signal_wps_event_m2d(wpa_s, m2d);
#endif /* CONFIG_WPS */
}


void wpas_notify_wps_event_fail(struct wpa_supplicant *wpa_s,
				struct wps_event_fail *fail)
{
	if (wpa_s->p2p_mgmt)
		return;

#ifdef CONFIG_WPS
	wpas_dbus_signal_wps_event_fail(wpa_s, fail);
#endif /* CONFIG_WPS */
}


void wpas_notify_wps_event_success(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

#ifdef CONFIG_WPS
	wpas_dbus_signal_wps_event_success(wpa_s);
#endif /* CONFIG_WPS */
}

void wpas_notify_wps_event_pbc_overlap(struct wpa_supplicant *wpa_s)
{
	if (wpa_s->p2p_mgmt)
		return;

#ifdef CONFIG_WPS
	wpas_dbus_signal_wps_event_pbc_overlap(wpa_s);
#endif /* CONFIG_WPS */
}


void wpas_notify_network_added(struct wpa_supplicant *wpa_s,
			       struct wpa_ssid *ssid)
{
	if (wpa_s->p2p_mgmt)
		return;

	/*
	 * Networks objects created during any P2P activities should not be
	 * exposed out. They might/will confuse certain non-P2P aware
	 * applications since these network objects won't behave like
	 * regular ones.
	 */
	if (!ssid->p2p_group && wpa_s->global->p2p_group_formation != wpa_s) {
		wpas_dbus_register_network(wpa_s, ssid);
		wpa_msg_ctrl(wpa_s, MSG_INFO, WPA_EVENT_NETWORK_ADDED "%d",
			     ssid->id);
	}
}


void wpas_notify_persistent_group_added(struct wpa_supplicant *wpa_s,
					struct wpa_ssid *ssid)
{
#ifdef CONFIG_P2P
	wpas_dbus_register_persistent_group(wpa_s, ssid);
#endif /* CONFIG_P2P */
}


void wpas_notify_persistent_group_removed(struct wpa_supplicant *wpa_s,
					  struct wpa_ssid *ssid)
{
#ifdef CONFIG_P2P
	wpas_dbus_unregister_persistent_group(wpa_s, ssid->id);
#endif /* CONFIG_P2P */
}


void wpas_notify_network_removed(struct wpa_supplicant *wpa_s,
				 struct wpa_ssid *ssid)
{
	if (wpa_s->next_ssid == ssid)
		wpa_s->next_ssid = NULL;
	if (wpa_s->last_ssid == ssid)
		wpa_s->last_ssid = NULL;
	if (wpa_s->current_ssid == ssid)
		wpa_s->current_ssid = NULL;
	if (wpa_s->ml_connect_probe_ssid == ssid) {
		wpa_s->ml_connect_probe_ssid = NULL;
		wpa_s->ml_connect_probe_bss = NULL;
	}
	if (wpa_s->connect_without_scan == ssid)
		wpa_s->connect_without_scan = NULL;
#if defined(CONFIG_SME) && defined(CONFIG_SAE)
	if (wpa_s->sme.ext_auth_wpa_ssid == ssid)
		wpa_s->sme.ext_auth_wpa_ssid = NULL;
#endif /* CONFIG_SME && CONFIG_SAE */
	if (wpa_s->wpa) {
		if ((wpa_key_mgmt_sae(ssid->key_mgmt) &&
		     (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_SAE_OFFLOAD_STA)) ||
		    ((ssid->key_mgmt & WPA_KEY_MGMT_OWE) &&
		     (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_OWE_OFFLOAD_STA))) {
			/* For cases when PMK is generated at the driver */
			struct wpa_pmkid_params params;

			os_memset(&params, 0, sizeof(params));
			params.ssid = ssid->ssid;
			params.ssid_len = ssid->ssid_len;
			wpa_drv_remove_pmkid(wpa_s, &params);
		}
		wpa_sm_pmksa_cache_flush(wpa_s->wpa, ssid);
	}
	if (!ssid->p2p_group && wpa_s->global->p2p_group_formation != wpa_s &&
	    !wpa_s->p2p_mgmt) {
		wpas_dbus_unregister_network(wpa_s, ssid->id);
		wpa_msg_ctrl(wpa_s, MSG_INFO, WPA_EVENT_NETWORK_REMOVED "%d",
			     ssid->id);
	}
	if (network_is_persistent_group(ssid))
		wpas_notify_persistent_group_removed(wpa_s, ssid);

	wpas_p2p_network_removed(wpa_s, ssid);
}


void wpas_notify_bss_added(struct wpa_supplicant *wpa_s,
			   u8 bssid[], unsigned int id)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_register_bss(wpa_s, bssid, id);
	wpa_msg_ctrl(wpa_s, MSG_INFO, WPA_EVENT_BSS_ADDED "%u " MACSTR,
		     id, MAC2STR(bssid));
	wpa_printf(MSG_DEBUG, WPA_EVENT_BSS_ADDED "%u " MACSTR_SEC, id, MAC2STR_SEC(bssid));
}


void wpas_notify_bss_removed(struct wpa_supplicant *wpa_s,
			     u8 bssid[], unsigned int id)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_unregister_bss(wpa_s, bssid, id);
	wpa_msg_ctrl(wpa_s, MSG_INFO, WPA_EVENT_BSS_REMOVED "%u " MACSTR,
		     id, MAC2STR(bssid));
}


void wpas_notify_bss_freq_changed(struct wpa_supplicant *wpa_s,
				  unsigned int id)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_bss_signal_prop_changed(wpa_s, WPAS_DBUS_BSS_PROP_FREQ, id);
}


void wpas_notify_bss_signal_changed(struct wpa_supplicant *wpa_s,
				    unsigned int id)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_bss_signal_prop_changed(wpa_s, WPAS_DBUS_BSS_PROP_SIGNAL,
					  id);
}


void wpas_notify_bss_privacy_changed(struct wpa_supplicant *wpa_s,
				     unsigned int id)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_bss_signal_prop_changed(wpa_s, WPAS_DBUS_BSS_PROP_PRIVACY,
					  id);
}


void wpas_notify_bss_mode_changed(struct wpa_supplicant *wpa_s,
				  unsigned int id)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_bss_signal_prop_changed(wpa_s, WPAS_DBUS_BSS_PROP_MODE, id);
}


void wpas_notify_bss_wpaie_changed(struct wpa_supplicant *wpa_s,
				   unsigned int id)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_bss_signal_prop_changed(wpa_s, WPAS_DBUS_BSS_PROP_WPA, id);
}


void wpas_notify_bss_rsnie_changed(struct wpa_supplicant *wpa_s,
				   unsigned int id)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_bss_signal_prop_changed(wpa_s, WPAS_DBUS_BSS_PROP_RSN, id);
}


void wpas_notify_bss_wps_changed(struct wpa_supplicant *wpa_s,
				 unsigned int id)
{
	if (wpa_s->p2p_mgmt)
		return;

#ifdef CONFIG_WPS
	wpas_dbus_bss_signal_prop_changed(wpa_s, WPAS_DBUS_BSS_PROP_WPS, id);
#endif /* CONFIG_WPS */
}


void wpas_notify_bss_ies_changed(struct wpa_supplicant *wpa_s,
				   unsigned int id)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_bss_signal_prop_changed(wpa_s, WPAS_DBUS_BSS_PROP_IES, id);
}


void wpas_notify_bss_rates_changed(struct wpa_supplicant *wpa_s,
				   unsigned int id)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_bss_signal_prop_changed(wpa_s, WPAS_DBUS_BSS_PROP_RATES, id);
}


void wpas_notify_bss_seen(struct wpa_supplicant *wpa_s, unsigned int id)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_bss_signal_prop_changed(wpa_s, WPAS_DBUS_BSS_PROP_AGE, id);
}


void wpas_notify_bss_anqp_changed(struct wpa_supplicant *wpa_s, unsigned int id)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_bss_signal_prop_changed(wpa_s, WPAS_DBUS_BSS_PROP_ANQP, id);
}


void wpas_notify_blob_added(struct wpa_supplicant *wpa_s, const char *name)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_blob_added(wpa_s, name);
}


void wpas_notify_blob_removed(struct wpa_supplicant *wpa_s, const char *name)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_blob_removed(wpa_s, name);
}


void wpas_notify_debug_level_changed(struct wpa_global *global)
{
	wpas_dbus_signal_debug_level_changed(global);
}


void wpas_notify_debug_timestamp_changed(struct wpa_global *global)
{
	wpas_dbus_signal_debug_timestamp_changed(global);
}


void wpas_notify_debug_show_keys_changed(struct wpa_global *global)
{
	wpas_dbus_signal_debug_show_keys_changed(global);
}


void wpas_notify_suspend(struct wpa_global *global)
{
	struct wpa_supplicant *wpa_s;

	os_get_time(&global->suspend_time);
	wpa_printf(MSG_DEBUG, "System suspend notification");
	for (wpa_s = global->ifaces; wpa_s; wpa_s = wpa_s->next)
		wpa_drv_suspend(wpa_s);
}


void wpas_notify_resume(struct wpa_global *global)
{
	struct os_time now;
	int slept;
	struct wpa_supplicant *wpa_s;

	if (global->suspend_time.sec == 0)
		slept = -1;
	else {
		os_get_time(&now);
		slept = now.sec - global->suspend_time.sec;
	}
	wpa_printf(MSG_DEBUG, "System resume notification (slept %d seconds)",
		   slept);

	for (wpa_s = global->ifaces; wpa_s; wpa_s = wpa_s->next) {
		wpa_drv_resume(wpa_s);
		if (wpa_s->wpa_state == WPA_DISCONNECTED)
			wpa_supplicant_req_scan(wpa_s, 0, 100000);
	}
}


#ifdef CONFIG_P2P

void wpas_notify_p2p_find_stopped(struct wpa_supplicant *wpa_s)
{
	/* Notify P2P find has stopped */
	wpas_dbus_signal_p2p_find_stopped(wpa_s);
}


void wpas_notify_p2p_device_found(struct wpa_supplicant *wpa_s,
				  const u8 *dev_addr, int new_device)
{
	if (new_device) {
		/* Create the new peer object */
		wpas_dbus_register_peer(wpa_s, dev_addr);
	}

	/* Notify a new peer has been detected*/
	wpas_dbus_signal_peer_device_found(wpa_s, dev_addr);
}


void wpas_notify_p2p_device_lost(struct wpa_supplicant *wpa_s,
				 const u8 *dev_addr)
{
	wpas_dbus_unregister_peer(wpa_s, dev_addr);

	/* Create signal on interface object*/
	wpas_dbus_signal_peer_device_lost(wpa_s, dev_addr);
}


void wpas_notify_p2p_group_removed(struct wpa_supplicant *wpa_s,
				   const struct wpa_ssid *ssid,
				   const char *role)
{
	wpas_dbus_signal_p2p_group_removed(wpa_s, role);

	wpas_dbus_unregister_p2p_group(wpa_s, ssid);
}


void wpas_notify_p2p_go_neg_req(struct wpa_supplicant *wpa_s,
				const u8 *src, u16 dev_passwd_id, u8 go_intent)
{
	wpas_dbus_signal_p2p_go_neg_req(wpa_s, src, dev_passwd_id, go_intent);
}


void wpas_notify_p2p_go_neg_completed(struct wpa_supplicant *wpa_s,
				      struct p2p_go_neg_results *res)
{
#ifdef CONFIG_OPEN_HARMONY_MIRACAST_MAC
	if (wpa_s && (wpa_s->p2p_business == MIRACAST_BUSINESS) && res && res->status)
		wpa_s->p2p_business = 0;
#endif
	wpas_dbus_signal_p2p_go_neg_resp(wpa_s, res);
}


void wpas_notify_p2p_invitation_result(struct wpa_supplicant *wpa_s,
				       int status, const u8 *bssid)
{
#ifdef CONFIG_OPEN_HARMONY_MIRACAST_MAC
	if (wpa_s && (wpa_s->p2p_business == MIRACAST_BUSINESS) && status &&
		status != P2P_SC_FAIL_UNKNOWN_GROUP &&
		status != P2P_SC_FAIL_INFO_CURRENTLY_UNAVAILABLE)
		wpa_s->p2p_business = 0;
#endif
	wpas_dbus_signal_p2p_invitation_result(wpa_s, status, bssid);
}


void wpas_notify_p2p_sd_request(struct wpa_supplicant *wpa_s,
				int freq, const u8 *sa, u8 dialog_token,
				u16 update_indic, const u8 *tlvs,
				size_t tlvs_len)
{
	wpas_dbus_signal_p2p_sd_request(wpa_s, freq, sa, dialog_token,
					update_indic, tlvs, tlvs_len);
}


void wpas_notify_p2p_sd_response(struct wpa_supplicant *wpa_s,
				 const u8 *sa, u16 update_indic,
				 const u8 *tlvs, size_t tlvs_len)
{
	wpas_dbus_signal_p2p_sd_response(wpa_s, sa, update_indic,
					 tlvs, tlvs_len);
}


/**
 * wpas_notify_p2p_provision_discovery - Notification of provision discovery
 * @dev_addr: Who sent the request or responded to our request.
 * @request: Will be 1 if request, 0 for response.
 * @status: Valid only in case of response (0 in case of success)
 * @config_methods: WPS config methods
 * @generated_pin: PIN to be displayed in case of WPS_CONFIG_DISPLAY method
 *
 * This can be used to notify:
 * - Requests or responses
 * - Various config methods
 * - Failure condition in case of response
 */
void wpas_notify_p2p_provision_discovery(struct wpa_supplicant *wpa_s,
					 const u8 *dev_addr, int request,
					 enum p2p_prov_disc_status status,
					 u16 config_methods,
					 unsigned int generated_pin)
{
	wpas_dbus_signal_p2p_provision_discovery(wpa_s, dev_addr, request,
						 status, config_methods,
						 generated_pin);
#ifdef CONFIG_P2P_CHR
	if (status != P2P_PROV_DISC_SUCCESS) {
		wpa_supplicant_upload_state_before_group_formation_success(PROVISION_DISCOVERY, status);
	}
#endif
}


void wpas_notify_p2p_group_started(struct wpa_supplicant *wpa_s,
				   struct wpa_ssid *ssid, int persistent,
				   int client, const u8 *ip)
{
	/* Notify a group has been started */
	wpas_dbus_register_p2p_group(wpa_s, ssid);

	wpas_dbus_signal_p2p_group_started(wpa_s, client, persistent, ip);
}


void wpas_notify_p2p_group_formation_failure(struct wpa_supplicant *wpa_s,
					     const char *reason)
{
	/* Notify a group formation failed */
	wpas_dbus_signal_p2p_group_formation_failure(wpa_s, reason);
}


void wpas_notify_p2p_wps_failed(struct wpa_supplicant *wpa_s,
				struct wps_event_fail *fail)
{
	wpas_dbus_signal_p2p_wps_failed(wpa_s, fail);
}


void wpas_notify_p2p_invitation_received(struct wpa_supplicant *wpa_s,
					 const u8 *sa, const u8 *go_dev_addr,
					 const u8 *bssid, int id, int op_freq)
{
	/* Notify a P2P Invitation Request */
	wpas_dbus_signal_p2p_invitation_received(wpa_s, sa, go_dev_addr, bssid,
						 id, op_freq);
}

#endif /* CONFIG_P2P */


static void wpas_notify_ap_sta_authorized(struct wpa_supplicant *wpa_s,
					  const u8 *sta,
					  const u8 *p2p_dev_addr, const u8 *ip)
{
#ifdef CONFIG_P2P
	wpas_p2p_notify_ap_sta_authorized(wpa_s, p2p_dev_addr);

	/*
	 * Create 'peer-joined' signal on group object -- will also
	 * check P2P itself.
	 */
	if (p2p_dev_addr)
		wpas_dbus_signal_p2p_peer_joined(wpa_s, p2p_dev_addr);
#endif /* CONFIG_P2P */

	/* Register the station */
	wpas_dbus_register_sta(wpa_s, sta);

	/* Notify listeners a new station has been authorized */
	wpas_dbus_signal_sta_authorized(wpa_s, sta);
#ifdef CONFIG_VENDOR_EXT
	/* Vendor notify connected */
	wpa_vendor_ext_notify_connected(wpa_s, sta);
#endif
}


static void wpas_notify_ap_sta_deauthorized(struct wpa_supplicant *wpa_s,
					    const u8 *sta,
					    const u8 *p2p_dev_addr)
{
#ifdef CONFIG_P2P
	/*
	 * Create 'peer-disconnected' signal on group object if this
	 * is a P2P group.
	 */
	if (p2p_dev_addr)
		wpas_dbus_signal_p2p_peer_disconnected(wpa_s, p2p_dev_addr);
#endif /* CONFIG_P2P */

	/* Notify listeners a station has been deauthorized */
	wpas_dbus_signal_sta_deauthorized(wpa_s, sta);
#ifdef CONFIG_VENDOR_EXT
	/* Vendor notify deauthorized */
	wpa_vendor_ext_notify_deauthorized(wpa_s, sta, p2p_dev_addr);
#endif
	/* Unregister the station */
	wpas_dbus_unregister_sta(wpa_s, sta);
}


void wpas_notify_sta_authorized(struct wpa_supplicant *wpa_s,
				const u8 *mac_addr, int authorized,
				const u8 *p2p_dev_addr, const u8 *ip)
{
	if (authorized)
		wpas_notify_ap_sta_authorized(wpa_s, mac_addr, p2p_dev_addr,
					      ip);
	else
		wpas_notify_ap_sta_deauthorized(wpa_s, mac_addr, p2p_dev_addr);
}


void wpas_notify_certification(struct wpa_supplicant *wpa_s,
			       struct tls_cert_data *cert,
			       const char *cert_hash)
{
	int i;

	wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_EAP_PEER_CERT
		"depth=%d subject='%s'%s%s%s%s",
		cert->depth, cert->subject, cert_hash ? " hash=" : "",
		cert_hash ? cert_hash : "",
		cert->tod == 2 ? " tod=2" : "",
		cert->tod == 1 ? " tod=1" : "");

	if (cert->cert) {
		char *cert_hex;
		size_t len = wpabuf_len(cert->cert) * 2 + 1;
		cert_hex = os_malloc(len);
		if (cert_hex) {
			wpa_snprintf_hex(cert_hex, len, wpabuf_head(cert->cert),
					 wpabuf_len(cert->cert));
			wpa_msg_ctrl(wpa_s, MSG_INFO,
				     WPA_EVENT_EAP_PEER_CERT
				     "depth=%d subject='%s' cert=%s",
				     cert->depth, cert->subject, cert_hex);
			os_free(cert_hex);
		}
	}

	for (i = 0; i < cert->num_altsubject; i++)
		wpa_msg(wpa_s, MSG_INFO, WPA_EVENT_EAP_PEER_ALT
			"depth=%d %s", cert->depth, cert->altsubject[i]);

	/* notify the new DBus API */
	wpas_dbus_signal_certification(wpa_s, cert->depth, cert->subject,
				       cert->altsubject, cert->num_altsubject,
				       cert_hash, cert->cert);
}


void wpas_notify_preq(struct wpa_supplicant *wpa_s,
		      const u8 *addr, const u8 *dst, const u8 *bssid,
		      const u8 *ie, size_t ie_len, u32 ssi_signal)
{
#ifdef CONFIG_AP
	wpas_dbus_signal_preq(wpa_s, addr, dst, bssid, ie, ie_len, ssi_signal);
#endif /* CONFIG_AP */
}


void wpas_notify_eap_status(struct wpa_supplicant *wpa_s, const char *status,
			    const char *parameter)
{
	wpas_dbus_signal_eap_status(wpa_s, status, parameter);
	wpa_msg_ctrl(wpa_s, MSG_INFO, WPA_EVENT_EAP_STATUS
		     "status='%s' parameter='%s'",
		     status, parameter);
}


void wpas_notify_eap_error(struct wpa_supplicant *wpa_s, int error_code)
{
	wpa_msg(wpa_s, MSG_ERROR, WPA_EVENT_EAP_ERROR_CODE "%d", error_code);
}


void wpas_notify_psk_mismatch(struct wpa_supplicant *wpa_s)
{
	wpas_dbus_signal_psk_mismatch(wpa_s);
}


void wpas_notify_network_bssid_set_changed(struct wpa_supplicant *wpa_s,
					   struct wpa_ssid *ssid)
{
	if (wpa_s->current_ssid != ssid)
		return;

	wpa_dbg(wpa_s, MSG_DEBUG,
		"Network bssid config changed for the current network - within-ESS roaming %s",
		ssid->bssid_set ? "disabled" : "enabled");

	wpa_drv_roaming(wpa_s, !ssid->bssid_set,
			ssid->bssid_set ? ssid->bssid : NULL);
}


void wpas_notify_network_type_changed(struct wpa_supplicant *wpa_s,
				      struct wpa_ssid *ssid)
{
#ifdef CONFIG_P2P
	if (ssid->disabled == 2) {
		/* Changed from normal network profile to persistent group */
		ssid->disabled = 0;
		wpas_dbus_unregister_network(wpa_s, ssid->id);
		ssid->disabled = 2;
		ssid->p2p_persistent_group = 1;
		wpas_dbus_register_persistent_group(wpa_s, ssid);
	} else {
		/* Changed from persistent group to normal network profile */
		wpas_dbus_unregister_persistent_group(wpa_s, ssid->id);
		ssid->p2p_persistent_group = 0;
		wpas_dbus_register_network(wpa_s, ssid);
	}
#endif /* CONFIG_P2P */
}


#ifdef CONFIG_MESH

void wpas_notify_mesh_group_started(struct wpa_supplicant *wpa_s,
				    struct wpa_ssid *ssid)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_mesh_group_started(wpa_s, ssid);
}


void wpas_notify_mesh_group_removed(struct wpa_supplicant *wpa_s,
				    const u8 *meshid, u8 meshid_len,
				    u16 reason_code)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpas_dbus_signal_mesh_group_removed(wpa_s, meshid, meshid_len,
					    reason_code);
}


void wpas_notify_mesh_peer_connected(struct wpa_supplicant *wpa_s,
				     const u8 *peer_addr)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpa_msg(wpa_s, MSG_INFO, MESH_PEER_CONNECTED MACSTR,
		MAC2STR(peer_addr));
	wpas_dbus_signal_mesh_peer_connected(wpa_s, peer_addr);
}


void wpas_notify_mesh_peer_disconnected(struct wpa_supplicant *wpa_s,
					const u8 *peer_addr, u16 reason_code)
{
	if (wpa_s->p2p_mgmt)
		return;

	wpa_msg(wpa_s, MSG_INFO, MESH_PEER_DISCONNECTED MACSTR,
		MAC2STR(peer_addr));
	wpas_dbus_signal_mesh_peer_disconnected(wpa_s, peer_addr, reason_code);
}

#endif /* CONFIG_MESH */

#if defined(CONFIG_OPEN_HARMONY_PATCH) && defined(CONFIG_HILINK_OKC_STA)
void wpas_notify_hilink_start_wps(struct wpa_supplicant *wpa_s, const char *arg)
{
	if (!wpa_s)
		return;

	char param[HILINK_PARAM_SIZE] = {0};
	sprintf(param, "01:%s", arg);
#ifdef CONFIG_LIBWPA_VENDOR
	WpaEventReport(wpa_s->ifname, WPA_EVENT_STA_NOTIFY, (void *)param);
#endif
}
#endif

#ifdef CONFIG_INTERWORKING

void wpas_notify_interworking_ap_added(struct wpa_supplicant *wpa_s,
				       struct wpa_bss *bss,
				       struct wpa_cred *cred, int excluded,
				       const char *type, int bh, int bss_load,
				       int conn_capab)
{
	wpa_msg(wpa_s, MSG_INFO, "%s" MACSTR " type=%s%s%s%s id=%d priority=%d sp_priority=%d",
		excluded ? INTERWORKING_EXCLUDED : INTERWORKING_AP,
		MAC2STR(bss->bssid), type,
		bh ? " below_min_backhaul=1" : "",
		bss_load ? " over_max_bss_load=1" : "",
		conn_capab ? " conn_capab_missing=1" : "",
		cred->id, cred->priority, cred->sp_priority);

	wpas_dbus_signal_interworking_ap_added(wpa_s, bss, cred, type, excluded,
					       bh, bss_load, conn_capab);
}


void wpas_notify_interworking_select_done(struct wpa_supplicant *wpa_s)
{
	wpas_dbus_signal_interworking_select_done(wpa_s);
}

void wpas_notify_anqp_query_done(struct wpa_supplicant *wpa_s,
				 const u8 *dst, const char *result)
{
	wpa_msg(wpa_s, MSG_INFO, ANQP_QUERY_DONE "addr=" MACSTR " result=%s",
		MAC2STR(dst), result);

	wpas_dbus_signal_anqp_query_done(wpa_s, dst, result);
}

#endif /* CONFIG_INTERWORKING */

int wpas_set_external_sim(struct wpa_supplicant* wpa_s, char *params)
{
	if (wpa_s == NULL || params == NULL) {
		return -1;
	}
 
	bool useExternalSim = false;
	WPA_ASSERT(wpa_s);
	wpa_printf(MSG_DEBUG, "EAP-SIM: wpas_set_external_sim params=%s", params);
	if (strncmp(params, SET_EXT_SIM_1, SET_EXT_SIM_1_SIZE) == 0) {
		useExternalSim = true;
	} else if (strncmp(params, SET_EXT_SIM_0, SET_EXT_SIM_0_SIZE) == 0) {
		useExternalSim = false;
	} else {
		return -1;
	}
	wpa_s->conf->external_sim = useExternalSim ? 1 : 0;
	return 0;
}
 
int wpas_eap_sim_auth_rsp(struct wpa_supplicant *wpa_s, char *params)
{
	if (wpa_s == NULL || params == NULL) {
		return -1;
	}
 
	wpa_printf(MSG_DEBUG, "EAP-SIM: enter wpas_eap_sim_auth_rsp");
	struct wpa_ssid *ssid = wpa_s->current_ssid;
	char *auth_rsp_params = (char *)malloc(RSP_PARAM_SIZE);
	os_memset(auth_rsp_params, 0, RSP_PARAM_SIZE);
	os_memcpy(auth_rsp_params, params, strlen(params));
 
	wpa_printf(MSG_DEBUG, "EAP-SIM: auth rsp auth_rsp_params=%s", auth_rsp_params);
	const char *field = "SIM";
	if (wpa_supplicant_ctrl_iface_ctrl_rsp_handle(wpa_s, ssid, field, auth_rsp_params) != 0) {
		os_free(auth_rsp_params);
		return -1;
	}
	eapol_sm_notify_ctrl_response(wpa_s->eapol);
	os_free(auth_rsp_params);
	return 0;
}


void wpas_notify_pmk_cache_added(struct wpa_supplicant *wpa_s,
				 struct rsn_pmksa_cache_entry *entry)
{
	/* TODO: Notify external entities of the added PMKSA cache entry */
}


void wpas_notify_signal_change(struct wpa_supplicant *wpa_s)
{
	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_SIGNAL_CHANGE);
}


#ifdef CONFIG_HS20
void wpas_notify_hs20_t_c_acceptance(struct wpa_supplicant *wpa_s,
				     const char *url)
{
	wpa_msg(wpa_s, MSG_INFO, HS20_T_C_ACCEPTANCE "%s", url);
	wpas_dbus_signal_hs20_t_c_acceptance(wpa_s, url);
}
#endif /* CONFIG_HS20 */
