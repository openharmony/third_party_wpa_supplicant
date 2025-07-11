/*
 * wpa_supplicant - Event notifications
 * Copyright (c) 2009-2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef NOTIFY_H
#define NOTIFY_H

#include "p2p/p2p.h"
#ifdef CONFIG_EAP_AUTH
#include "crypto/milenage.h"
#endif

struct wps_credential;
struct wps_event_m2d;
struct wps_event_fail;
struct tls_cert_data;
struct wpa_cred;
struct rsn_pmksa_cache_entry;

#define RSP_PARAM_SIZE 120

#ifdef EXT_AUTHENTICATION_SUPPORT
#define EXT_AUTH_REG_PREFIX "EXT_AUTH_REG "
#define EXT_AUTH_REG_PREFIX_SIZE 13
#define EXT_AUTH_UNREG_PREFIX "EXT_AUTH_UNREG "
#define EXT_AUTH_UNREG_PREFIX_SIZE 15
#define EXT_AUTH_DATA_PREFIX "EXT_AUTH_DATA "
#define EXT_AUTH_DATA_PREFIX_SIZE 14
#endif /* EXT_AUTHENTICATION_SUPPORT */

#define GSM_AUTH_PREFIX "GSM-AUTH"
#define GSM_AUTH_PREFIX_SIZE 8
#define UMTS_AUTH_PREFIX "UMTS-AUTH"
#define UMTS_AUTH_PREFIX_SIZE 9
#define UMTS_AUTS_PREFIX "UMTS-AUTS"
#define UMTS_AUTS_PREFIX_SIZE 9
#define SET_EXT_SIM "set external_sim"
#define SET_EXT_SIM_SIZE 16
#define SET_EXT_SIM_1 "set external_sim 1"
#define SET_EXT_SIM_1_SIZE 18
#define SET_EXT_SIM_0 "set external_sim 0"
#define SET_EXT_SIM_0_SIZE 18
#ifdef CONFIG_EAP_AUTH
#define EAP_AKA_RES_MAX_LEN 16
#define PAR_MAX 256
#define EAP_AKA_RES_MAX_LEN 16
#define MAX_KC_LEN 17
#define MAX_SRES_LEN 9
#define MAX_IK_LEN 33
#define MAX_CK_LEN 33
#define MAX_RES_LEN 17
#define MAX_KI_LEN 33
#define MAX_OPC_LEN 33
#define MAX_AMF_LEN 5
#define MAX_SQN_LEN 13
#define ACT_NUM 3

struct NetRspEapSimGsmAuthParams {
	char kc[MAX_KC_LEN];
	char sres[MAX_SRES_LEN];
};

struct NetRspEapAkaUmtsAuthParams {
	char ik[MAX_IK_LEN];
	char ck[MAX_CK_LEN];
	char res[MAX_RES_LEN];
	char ki[MAX_KI_LEN];
	char opc[MAX_OPC_LEN];
	char amf[MAX_AMF_LEN];
	char sqn[MAX_SQN_LEN];
};

extern struct NetRspEapSimGsmAuthParams eapsim_params;
extern struct NetRspEapAkaUmtsAuthParams eapaka_params;
#endif

int wpas_notify_supplicant_initialized(struct wpa_global *global);
void wpas_notify_supplicant_deinitialized(struct wpa_global *global);
int wpas_notify_iface_added(struct wpa_supplicant *wpa_s);
void wpas_notify_iface_removed(struct wpa_supplicant *wpa_s);
void wpas_notify_state_changed(struct wpa_supplicant *wpa_s,
			       enum wpa_states new_state,
			       enum wpa_states old_state);
void wpas_notify_disconnect_reason(struct wpa_supplicant *wpa_s);
void wpas_notify_auth_status_code(struct wpa_supplicant *wpa_s);
void wpas_notify_assoc_status_code(struct wpa_supplicant *wpa_s);
void wpas_notify_roam_time(struct wpa_supplicant *wpa_s);
void wpas_notify_roam_complete(struct wpa_supplicant *wpa_s);
void wpas_notify_session_length(struct wpa_supplicant *wpa_s);
void wpas_notify_bss_tm_status(struct wpa_supplicant *wpa_s);
void wpas_notify_network_changed(struct wpa_supplicant *wpa_s);
void wpas_notify_ap_scan_changed(struct wpa_supplicant *wpa_s);
void wpas_notify_bssid_changed(struct wpa_supplicant *wpa_s);
#ifdef CONFIG_MLD_PATCH
void wpas_notify_bssid_changed_ext(struct wpa_supplicant *wpa_s, char *reason);
#endif
void wpas_notify_mlo_work_state_changed(struct wpa_supplicant *wpa_s,
			 		 struct mlo_work_state_event *mlo_event);
void wpas_notify_mac_address_changed(struct wpa_supplicant *wpa_s);
void wpas_notify_auth_changed(struct wpa_supplicant *wpa_s);
void wpas_notify_network_enabled_changed(struct wpa_supplicant *wpa_s,
					 struct wpa_ssid *ssid);
void wpas_notify_network_selected(struct wpa_supplicant *wpa_s,
				  struct wpa_ssid *ssid);
void wpas_notify_network_request(struct wpa_supplicant *wpa_s,
				 struct wpa_ssid *ssid,
				 enum wpa_ctrl_req_type rtype,
				 const char *default_txt);
void wpas_notify_scanning(struct wpa_supplicant *wpa_s);
void wpas_notify_scan_done(struct wpa_supplicant *wpa_s, int success);
void wpas_notify_scan_results(struct wpa_supplicant *wpa_s);
void wpas_notify_wps_credential(struct wpa_supplicant *wpa_s,
				const struct wps_credential *cred);
void wpas_notify_wps_event_m2d(struct wpa_supplicant *wpa_s,
			       struct wps_event_m2d *m2d);
void wpas_notify_wps_event_fail(struct wpa_supplicant *wpa_s,
				struct wps_event_fail *fail);
void wpas_notify_wps_event_success(struct wpa_supplicant *wpa_s);
void wpas_notify_wps_event_pbc_overlap(struct wpa_supplicant *wpa_s);
void wpas_notify_network_added(struct wpa_supplicant *wpa_s,
			       struct wpa_ssid *ssid);
void wpas_notify_network_removed(struct wpa_supplicant *wpa_s,
				 struct wpa_ssid *ssid);
void wpas_notify_bss_added(struct wpa_supplicant *wpa_s, u8 bssid[],
			   unsigned int id);
void wpas_notify_bss_removed(struct wpa_supplicant *wpa_s, u8 bssid[],
			     unsigned int id);
void wpas_notify_bss_freq_changed(struct wpa_supplicant *wpa_s,
				  unsigned int id);
void wpas_notify_bss_signal_changed(struct wpa_supplicant *wpa_s,
				    unsigned int id);
void wpas_notify_bss_privacy_changed(struct wpa_supplicant *wpa_s,
				     unsigned int id);
void wpas_notify_bss_mode_changed(struct wpa_supplicant *wpa_s,
				  unsigned int id);
void wpas_notify_bss_wpaie_changed(struct wpa_supplicant *wpa_s,
				   unsigned int id);
void wpas_notify_bss_rsnie_changed(struct wpa_supplicant *wpa_s,
				   unsigned int id);
void wpas_notify_bss_wps_changed(struct wpa_supplicant *wpa_s,
				 unsigned int id);
void wpas_notify_bss_ies_changed(struct wpa_supplicant *wpa_s,
				 unsigned int id);
void wpas_notify_bss_rates_changed(struct wpa_supplicant *wpa_s,
				   unsigned int id);
void wpas_notify_bss_seen(struct wpa_supplicant *wpa_s, unsigned int id);
void wpas_notify_bss_anqp_changed(struct wpa_supplicant *wpa_s,
				  unsigned int id);
void wpas_notify_blob_added(struct wpa_supplicant *wpa_s, const char *name);
void wpas_notify_blob_removed(struct wpa_supplicant *wpa_s, const char *name);

void wpas_notify_debug_level_changed(struct wpa_global *global);
void wpas_notify_debug_timestamp_changed(struct wpa_global *global);
void wpas_notify_debug_show_keys_changed(struct wpa_global *global);
void wpas_notify_suspend(struct wpa_global *global);
void wpas_notify_resume(struct wpa_global *global);

void wpas_notify_sta_authorized(struct wpa_supplicant *wpa_s,
				const u8 *mac_addr, int authorized,
				const u8 *p2p_dev_addr, const u8 *ip);
void wpas_notify_p2p_find_stopped(struct wpa_supplicant *wpa_s);
void wpas_notify_p2p_device_found(struct wpa_supplicant *wpa_s,
				  const u8 *dev_addr, int new_device);
void wpas_notify_p2p_device_lost(struct wpa_supplicant *wpa_s,
				 const u8 *dev_addr);
void wpas_notify_p2p_group_removed(struct wpa_supplicant *wpa_s,
				   const struct wpa_ssid *ssid,
				   const char *role);
void wpas_notify_p2p_go_neg_req(struct wpa_supplicant *wpa_s,
				const u8 *src, u16 dev_passwd_id, u8 go_intent);
void wpas_notify_p2p_go_neg_completed(struct wpa_supplicant *wpa_s,
				      struct p2p_go_neg_results *res);
void wpas_notify_p2p_invitation_result(struct wpa_supplicant *wpa_s,
				       int status, const u8 *bssid);
void wpas_notify_p2p_sd_request(struct wpa_supplicant *wpa_s,
				int freq, const u8 *sa, u8 dialog_token,
				u16 update_indic, const u8 *tlvs,
				size_t tlvs_len);
void wpas_notify_p2p_sd_response(struct wpa_supplicant *wpa_s,
				 const u8 *sa, u16 update_indic,
				 const u8 *tlvs, size_t tlvs_len);
void wpas_notify_p2p_provision_discovery(struct wpa_supplicant *wpa_s,
					 const u8 *dev_addr, int request,
					 enum p2p_prov_disc_status status,
					 u16 config_methods,
					 unsigned int generated_pin);
void wpas_notify_p2p_group_started(struct wpa_supplicant *wpa_s,
				   struct wpa_ssid *ssid, int persistent,
				   int client, const u8 *ip);
void wpas_notify_p2p_group_formation_failure(struct wpa_supplicant *wpa_s,
					     const char *reason);
void wpas_notify_persistent_group_added(struct wpa_supplicant *wpa_s,
					struct wpa_ssid *ssid);
void wpas_notify_persistent_group_removed(struct wpa_supplicant *wpa_s,
					  struct wpa_ssid *ssid);

void wpas_notify_p2p_wps_failed(struct wpa_supplicant *wpa_s,
				struct wps_event_fail *fail);

void wpas_notify_certification(struct wpa_supplicant *wpa_s,
			       struct tls_cert_data *cert,
			       const char *cert_hash);
void wpas_notify_preq(struct wpa_supplicant *wpa_s,
		      const u8 *addr, const u8 *dst, const u8 *bssid,
		      const u8 *ie, size_t ie_len, u32 ssi_signal);
void wpas_notify_eap_status(struct wpa_supplicant *wpa_s, const char *status,
			    const char *parameter);
void wpas_notify_eap_error(struct wpa_supplicant *wpa_s, int error_code);
void wpas_notify_psk_mismatch(struct wpa_supplicant *wpa_s);
void wpas_notify_network_bssid_set_changed(struct wpa_supplicant *wpa_s,
					   struct wpa_ssid *ssid);
void wpas_notify_network_type_changed(struct wpa_supplicant *wpa_s,
				      struct wpa_ssid *ssid);
void wpas_notify_p2p_invitation_received(struct wpa_supplicant *wpa_s,
					 const u8 *sa, const u8 *go_dev_addr,
					 const u8 *bssid, int id, int op_freq);
void wpas_notify_mesh_group_started(struct wpa_supplicant *wpa_s,
				    struct wpa_ssid *ssid);
void wpas_notify_mesh_group_removed(struct wpa_supplicant *wpa_s,
				    const u8 *meshid, u8 meshid_len,
				    u16 reason_code);
void wpas_notify_mesh_peer_connected(struct wpa_supplicant *wpa_s,
				     const u8 *peer_addr);
void wpas_notify_mesh_peer_disconnected(struct wpa_supplicant *wpa_s,
					const u8 *peer_addr, u16 reason_code);
void wpas_notify_interworking_ap_added(struct wpa_supplicant *wpa_s,
				       struct wpa_bss *bss,
				       struct wpa_cred *cred, int excluded,
				       const char *type, int bh, int bss_load,
				       int conn_capab);
#if defined(CONFIG_OPEN_HARMONY_PATCH) && defined(CONFIG_HILINK_OKC_STA)
void wpas_notify_hilink_start_wps(struct wpa_supplicant *wpa_s, const char *arg);
#endif
void wpas_notify_interworking_select_done(struct wpa_supplicant *wpa_s);

int wpas_set_external_sim(struct wpa_supplicant *wpa_s, char *params);
int wpas_eap_sim_auth_rsp(struct wpa_supplicant *wpa_s, char *params);
void wpas_notify_anqp_query_done(struct wpa_supplicant *wpa_s,
				 const u8 *dst, const char *result);
void wpas_notify_pmk_cache_added(struct wpa_supplicant *wpa_s,
				 struct rsn_pmksa_cache_entry *entry);
void wpas_notify_signal_change(struct wpa_supplicant *wpa_s);
void wpas_notify_hs20_t_c_acceptance(struct wpa_supplicant *wpa_s,
				     const char *url);

#endif /* NOTIFY_H */
