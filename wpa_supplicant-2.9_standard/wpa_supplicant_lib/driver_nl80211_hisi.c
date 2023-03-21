/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "includes.h"
#include "driver_nl80211_hisi.h"
#include "driver_nl80211.h"
#include "wpa_supplicant_i.h"
#include "config.h"
#include "android_drv.h"
#include "securec.h"

#if defined(HISI_CONNECTIVITY_PATCH) && defined(HISI_MIRACAST_SINK_OPT)
#include "hisi_miracast_sink.h"
#endif

#define WPA_PS_ENABLED 0
#define WPA_PS_DISABLED 1

int send_and_recv_msgs(struct wpa_driver_nl80211_data *drv, struct nl_msg *msg,
						int (*valid_handler)(struct nl_msg *, void *),
						void *valid_data,
						int (*ack_handler_custom)(struct nl_msg *, void *),
						void *ack_data);

static int drv_errors = 0;

static void wpa_driver_send_hang_msg(struct wpa_driver_nl80211_data *drv)
{
	drv_errors++;
	if (drv_errors > DRV_NUMBER_SEQUENTIAL_ERRORS) {
		drv_errors = 0;
		wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "HANGED");
	}
}

static int wpa_driver_set_power_save(void *priv, int state)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret = -1;
	enum nl80211_ps_state ps_state;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	genlmsg_put(msg, 0, 0, drv->global->nl80211_id, 0, 0,
				NL80211_CMD_SET_POWER_SAVE, 0);

	if (state == WPA_PS_ENABLED)
		ps_state = NL80211_PS_ENABLED;
	else
		ps_state = NL80211_PS_DISABLED;

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);
	NLA_PUT_U32(msg, NL80211_ATTR_PS_STATE, ps_state);

	ret = send_and_recv_msgs(drv, msg, NULL, NULL, NULL, NULL);
	msg = NULL;
	if (ret < 0)
		wpa_printf(MSG_ERROR, "nl80211: Set power mode fail: %d", ret);
nla_put_failure:
	nlmsg_free(msg);
	return ret;
}

static int get_power_mode_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	int *state = (int *) arg;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
				genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_PS_STATE])
		return NL_SKIP;

	if (state) {
		*state = (int) nla_get_u32(tb[NL80211_ATTR_PS_STATE]);
		wpa_printf(MSG_DEBUG, "nl80211: Get power mode = %d", *state);
		*state = (*state == NL80211_PS_ENABLED) ? WPA_PS_ENABLED : WPA_PS_DISABLED;
	}

	return NL_SKIP;
}

static int wpa_driver_get_power_save(void *priv, int *state)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;
	int ret = -1;

	msg = nlmsg_alloc();
	if (!msg)
		return -1;

	genlmsg_put(msg, 0, 0, drv->global->nl80211_id, 0, 0,
			NL80211_CMD_GET_POWER_SAVE, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, drv->ifindex);

	ret = send_and_recv_msgs(drv, msg, get_power_mode_handler, state, NULL,
							NULL);
	msg = NULL;
	if (ret < 0)
		wpa_printf(MSG_ERROR, "nl80211: Get power mode fail: %d", ret);
nla_put_failure:
	nlmsg_free(msg);
	return ret;
}

int g_is_jp = 0;
int wpa_driver_nl80211_driver_cmd(void *priv, char *cmd, char *buf, size_t buf_len)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct ifreq ifr;
	int ret = 0;
	int ret_s;
#ifdef CONFIG_DRIVER_NL80211_HISI_TRUNK
	char temp_cmd[MAX_PRIV_CMD_SIZE] = {0};
#endif

	wpa_printf(MSG_ERROR, "wpa_driver_nl80211_driver_cmd:cmd = %s", cmd);
	if (os_strcasecmp(cmd, "STOP") == 0) {
		linux_set_iface_flags(drv->global->ioctl_sock, bss->ifname, 0);
		wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "STOPPED");
	} else if (os_strcasecmp(cmd, "START") == 0) {
		linux_set_iface_flags(drv->global->ioctl_sock, bss->ifname, 1);
		wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "STARTED");
	} else if (os_strcasecmp(cmd, "MACADDR") == 0) {
		u8 macaddr[ETH_ALEN] = {};

		ret = linux_get_ifhwaddr(drv->global->ioctl_sock, bss->ifname, macaddr);
		if (!ret) {
			ret_s = snprintf_s(buf, buf_len, buf_len - 1,
			                   "Macaddr = " MACSTR "\n", MAC2STR(macaddr));
			if (ret_s == -1) {
				wpa_printf(MSG_ERROR, "%s:%d, snprintf failed, ret=%d", __func__, __LINE__, ret_s);
			}
		}
	} else if (os_strcasecmp(cmd, "RELOAD") == 0) {
		wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "HANGED");
	} else if (os_strncasecmp(cmd, "POWERMODE ", 10) == 0) {
		int state;

		state = atoi(cmd + 10);
		ret = wpa_driver_set_power_save(priv, state);
		if (ret < 0) {
			wpa_driver_send_hang_msg(drv);
		} else {
			drv_errors = 0;
		}
	} else if (os_strncasecmp(cmd, "GETPOWER", 8) == 0) {
		int state = -1;

		ret = wpa_driver_get_power_save(priv, &state);
		if (!ret && (state != -1)) {
			ret_s = snprintf_s(buf, buf_len, buf_len - 1, "POWERMODE = %d\n", state);
			if (ret_s == -1) {
				wpa_printf(MSG_ERROR, "%s:%d, snprintf failed, ret=%d", __func__, __LINE__, ret_s);
			}
			drv_errors = 0;
		} else {
			wpa_driver_send_hang_msg(drv);
		}
	} else {
		/* Use private command */
		wifi_priv_cmd priv_cmd = {0};
		uint32 ret_len = 0;
		size_t buf_len_tmp;

		if (buf_len > MAX_PRIV_CMD_SIZE || strlen(cmd) >= MAX_PRIV_CMD_SIZE) {
			wpa_printf(MSG_ERROR, "%s: too long priavte command, strlen(cmd)=%zu buf_len=%zu", __func__, strlen(cmd), buf_len);
			return -1;
		}
		buf_len_tmp = buf_len;
		if (MAX_PRIV_CMD_SIZE == buf_len) {
			buf_len = strlen(cmd); /* default driver xxx cmd */
		}

		/* Hisi private data structure cmd should use buf_len, rather than strlen(cmd) */
#ifdef CONFIG_DRIVER_NL80211_HISI_TRUNK
		priv_cmd.buf = temp_cmd;
		ret_s = memcpy_s(temp_cmd, buf_len_tmp, cmd, buf_len);
#else
		ret_s = memcpy_s(buf, buf_len_tmp, cmd, buf_len);
#endif /* CONFIG_DRIVER_NL80211_HISI_TRUNK */
		if (ret_s != EOK) {
			wpa_printf(MSG_ERROR, "%s:%d, memcpy failed, ret=%d", __func__, __LINE__, ret_s);
		}

		ret_s = memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr));
		if (ret_s != EOK) {
			wpa_printf(MSG_ERROR, "%s:%d, memset failed, ret=%d", __func__, __LINE__, ret_s);
		}

		ret_s = memcpy_s(priv_cmd.buf, MAX_PRIV_CMD_SIZE, cmd, buf_len);
		if (ret_s != EOK) {
			wpa_printf(MSG_ERROR, "%s:%d, memcpy failed, ret=%d", __func__, __LINE__, ret_s);
		}

#ifdef CONFIG_DRIVER_NL80211_HISI_TRUNK
		priv_cmd.total_len = sizeof(temp_cmd);
#else
		priv_cmd.total_len = buf_len; /* MAX_PRIV_CMD_SIZE */
#endif /* CONFIG_DRIVER_NL80211_HISI_TRUNK */
		priv_cmd.used_len = buf_len;  /* strlen(cmd) */

		ifr.ifr_data = (void *) &priv_cmd;
		os_strlcpy(ifr.ifr_name, bss->ifname, IFNAMSIZ);

		wpa_printf(MSG_EXCESSIVE, "%s: 1:ifr_name=%s, len=%zu, buf_len=%zu", __func__, ifr.ifr_name, strlen(buf), buf_len);

		ret = ioctl(drv->global->ioctl_sock, SIOCDEVPRIVATE + 1, &ifr);
		if (ret < 0) {
			wpa_printf(MSG_ERROR, "%s: failed to issue private commands\n", __func__);
			wpa_driver_send_hang_msg(drv);
		} else {
			drv_errors = 0;
			ret_len = os_strlen(priv_cmd.buf);
			ret_len = (ret_len < MAX_PRIV_CMD_SIZE) ? ret_len : (MAX_PRIV_CMD_SIZE - 1);
			/* SET Command return 0 which means OK, GET Command return string length */
			if (os_strncasecmp(buf, priv_cmd.buf, ret_len) != 0) {
				ret = ret_len;
			}
			ret_s = memset_s(buf, buf_len, 0, buf_len);
			if (ret_s != EOK) {
				wpa_printf(MSG_ERROR, "%s:%d, memset failed, ret=%d", __func__, __LINE__, ret_s);
			}

			ret_s = memcpy_s(buf, buf_len, priv_cmd.buf, ret_len); /* copy kernel space return string to user space */
			if (ret_s != EOK) {
				wpa_printf(MSG_ERROR, "%s:%d, memcpy failed, ret=%d", __func__, __LINE__, ret_s);
			}
			buf[ret_len] = '\0';

			if (os_strncasecmp(cmd, "COUNTRY", 7) == 0) {
				union wpa_event_data event = {0};
				g_is_jp = (os_strncasecmp(cmd + 8, "JP", 2) == 0) ? 1 : 0;

				event.channel_list_changed.initiator = REGDOM_SET_BY_USER;
				event.channel_list_changed.type = REGDOM_TYPE_UNKNOWN;
				wpa_supplicant_event(drv->ctx, EVENT_CHANNEL_LIST_CHANGED, &event);

				wpa_printf(MSG_DEBUG, "%s:set country code end. len=%zu, ret_len=%d ret=%d", __func__, strlen(buf), ret_len, ret);
				return ret;
			}
#ifdef HISI_MIRACAST_SINK_OPT
			hisi_miracast_sink_log("%s:%.15s len=%zu, ret_len=%d ret=%d", __func__, buf, strlen(buf), ret_len, ret);
#else
#ifdef HW_WPA_REDUCE_LOG
			wpa_printf(MSG_EXCESSIVE, "%s:%.15s len=%zu, ret_len=%d ret=%d", __func__, buf, strlen(buf), ret_len, ret);
#else
			wpa_printf(MSG_DEBUG, "%s:%.15s len=%zu, ret_len=%d ret=%d", __func__, buf, strlen(buf), ret_len, ret);
#endif
#endif
		}
	}
	return ret;
}

int wpa_driver_set_p2p_noa(void *priv, u8 count, int start, int duration)
{
	char buf[MAX_DRV_CMD_SIZE] = {0};
	char *pbuf;
	oal_p2p_noa_param_stru *pst_p2p_noa = NULL;
	char *_cmd = "P2P_SET_NOA";
	int ret_s;

	wpa_printf(MSG_ERROR, "%s: Entry", __func__);
	pbuf = buf;
	ret_s = sprintf_s(pbuf, MAX_DRV_CMD_SIZE, "%s", _cmd);
	if (ret_s == -1) {
		wpa_printf(MSG_ERROR, "%s:%d, sprintf failed, ret=%d", __func__, __LINE__, ret_s);
	}
	pbuf += ret_s;
	*pbuf++ = '\0';
	pst_p2p_noa = (oal_p2p_noa_param_stru *) pbuf;
	pst_p2p_noa->uc_count = count;
	pst_p2p_noa->ul_duration = duration;
	pst_p2p_noa->ul_start_time = start;

	return wpa_driver_nl80211_driver_cmd(priv, buf, buf, strlen(_cmd) + 1 + sizeof(oal_p2p_noa_param_stru));
}

int wpa_driver_get_p2p_noa(void *priv, u8 *buf, size_t len)
{
	/* Return 0 till we handle p2p_presence request completely in the device side */
	return 0;
}

int wpa_driver_set_p2p_ps(void *priv, int legacy_ps, int opp_ps, int ctwindow)
{
	char buf[MAX_DRV_CMD_SIZE] = {0};
	char *pbuf;
	oal_p2p_ops_param_stru *pst_p2p_ops = NULL;
	char *_cmd = "P2P_SET_PS";
	int ret_s;

	wpa_printf(MSG_ERROR, "%s: Entry", __func__);
	pbuf = buf;
	ret_s = sprintf_s(pbuf, MAX_DRV_CMD_SIZE, "%s", _cmd);
	if (ret_s == -1) {
		wpa_printf(MSG_ERROR, "%s:%d, sprintf failed, ret=%d", __func__, __LINE__, ret_s);
	}
	pbuf += ret_s;
	*pbuf++ = '\0';
	pst_p2p_ops = (oal_p2p_ops_param_stru *) pbuf;
	pst_p2p_ops->en_ops_ctrl = opp_ps;
	pst_p2p_ops->uc_ct_window = ctwindow;

	return wpa_driver_nl80211_driver_cmd(priv, buf, buf, strlen(_cmd) + 1 + sizeof(oal_p2p_ops_param_stru));
}

int wpa_driver_set_ap_wps_p2p_ie(void *priv,
								const struct wpabuf *beacon,
								const struct wpabuf *proberesp,
								const struct wpabuf *assocresp)
{
	char buf[MAX_WPSP2PIE_CMD_SIZE] = {0};
	struct wpabuf *ap_wps_p2p_ie = NULL;
	char *_cmd = "SET_AP_WPS_P2P_IE";
	char *pbuf;
	int ret = 0;
	int i;
	int ret_s;
	oal_app_ie_stru *pst_app_ie = NULL;
	struct cmd_desc {
		int cmd;
		const struct wpabuf *src;
	} cmd_arr[] = {
		{0x0, beacon},
		{0x2, proberesp},
		{0x4, assocresp},
		{-1, NULL}
	};

	wpa_printf(MSG_ERROR, "%s: Entry", __func__);
	for (i = 0; cmd_arr[i].cmd != -1; i++) {
		ret_s = memset_s(buf, sizeof(buf), 0, sizeof(buf));
		if (ret_s != EOK) {
			wpa_printf(MSG_ERROR, "%s:%d, memset failed, ret=%d", __func__, __LINE__, ret_s);
		}
		pbuf = buf;
		ret_s = sprintf_s(pbuf, MAX_WPSP2PIE_CMD_SIZE, "%s", _cmd);
		if (ret_s == -1) {
			wpa_printf(MSG_ERROR, "%s:%d, memset failed, ret=%d", __func__, __LINE__, ret_s);
		}
		pbuf += ret_s;
		*pbuf++ = '\0';
		ap_wps_p2p_ie = cmd_arr[i].src ? wpabuf_dup(cmd_arr[i].src) : NULL;
		if (ap_wps_p2p_ie) {
			if (wpabuf_len(ap_wps_p2p_ie) > WLAN_WPS_IE_MAX_SIZE) {
				wpa_printf(MSG_ERROR, "%s: app ie too large to wifi driver buffer.app_ie_len %d, auc_ie len %ul",
				           __func__, (int) wpabuf_len(ap_wps_p2p_ie), WLAN_WPS_IE_MAX_SIZE);
				wpabuf_free(ap_wps_p2p_ie);
				return -1;
			}

			pst_app_ie = (oal_app_ie_stru *) pbuf;
			pst_app_ie->en_app_ie_type = cmd_arr[i].cmd;
			pst_app_ie->ul_ie_len = wpabuf_len(ap_wps_p2p_ie);

			ret_s = memcpy_s(pst_app_ie->auc_ie, sizeof(pst_app_ie->auc_ie), wpabuf_head(ap_wps_p2p_ie), wpabuf_len(ap_wps_p2p_ie));
			if (ret_s != EOK) {
				wpa_printf(MSG_ERROR, "%s:%d, memcpy failed, ret=%d", __func__, __LINE__, ret_s);
			}
#if defined(HISI_CONNECTIVITY_PATCH) && defined(HISI_MIRACAST_SINK_OPT)
			hisi_miracast_sink_log("cmd:%s, type %d, ie_len %d\r\n",
									_cmd,
									pst_app_ie->en_app_ie_type,
									pst_app_ie->ul_ie_len);
#else
#ifdef HW_WPA_REDUCE_LOG
			wpa_printf(MSG_EXCESSIVE, "cmd:%s, type %d, ie_len %d\r\n",
						_cmd,
						pst_app_ie->en_app_ie_type,
						pst_app_ie->ul_ie_len);
#else
			wpa_printf(MSG_DEBUG, "cmd:%s, type %d, ie_len %d\r\n",
						_cmd,
						pst_app_ie->en_app_ie_type,
						pst_app_ie->ul_ie_len);
#endif /* HW_WPA_REDUCE_LOG */
#endif
			wpa_printf(MSG_EXCESSIVE, "ie %p\r\n",
						pst_app_ie->auc_ie);

			wpa_hexdump(MSG_EXCESSIVE, "P2P: set p2p wps ie", (const char *) pbuf, pst_app_ie->ul_ie_len + 8);

			if (strlen(_cmd) + sizeof(oal_app_ie_stru) + 1 < sizeof(buf)) {
				ret = wpa_driver_nl80211_driver_cmd(priv, buf, buf,
													strlen(_cmd) + sizeof(oal_app_ie_stru) + 1);
			} else {
				wpa_printf(MSG_ERROR, "%s:error.app total length to large!, cmd_len = %zu, buffer = %d", __func__, strlen(_cmd) + sizeof(oal_app_ie_stru) + 1, (int) sizeof(buf));
				ret = -1;
			}
			wpabuf_free(ap_wps_p2p_ie);
			if (ret < 0)
				break;
		}
	}
	return ret;
}

int wpa_driver_set_power_on(void *priv, int on)
{
	char buf[MAX_PRIV_CMD_SIZE] = {0};
	char *pbuf;
	char *_cmd = "SET_POWER_ON";
	int ret_s;

	wpa_printf(MSG_DEBUG, "%s: Entry,power flag:%d", __func__, on);
	pbuf = buf;
	ret_s = sprintf_s(pbuf, MAX_PRIV_CMD_SIZE, "%s %d", _cmd, on);
	if (ret_s == -1) {
		wpa_printf(MSG_ERROR, "%s:%d, sprintf failed, ret=%d", __func__, __LINE__, ret_s);
	}
	wpa_printf(MSG_DEBUG, "%s:buf is %s", __func__, buf);

	return wpa_driver_nl80211_driver_cmd(priv, buf, buf, strlen(buf));
}

int wpa_driver_set_powermgmt_on(void *priv, int powermgmt_on)
{
	char buf[MAX_PRIV_CMD_SIZE] = {0};
	char *pbuf;
	char *_cmd = "SET_POWER_MGMT_ON";
	int ret_s;

	wpa_printf(MSG_DEBUG, "%s: Entry,power mgmt flag:%d", __func__, powermgmt_on);
	pbuf = buf;
	ret_s = sprintf_s(pbuf, MAX_PRIV_CMD_SIZE, "%s %d", _cmd, powermgmt_on);
	if (ret_s == -1) {
		wpa_printf(MSG_ERROR, "%s:%d, sprintf failed, ret=%d", __func__, __LINE__, ret_s);
	}
	wpa_printf(MSG_DEBUG, "%s:buf is %s", __func__, buf);

	return wpa_driver_nl80211_driver_cmd(priv, buf, buf, strlen(buf));
}

int wpa_driver_set_qos_map(void *priv, const u8 *qos_map_set,
							u8 qos_map_set_len)
{
	char buf[MAX_DRV_CMD_SIZE] = {0};
	char *pbuf;
	int i, up_start;
	int ret = 0;
	int ret_s;
	oal_qos_map_param_stru *pst_qos_map = NULL;
	char *_cmd = "SET_QOS_MAP";

	if (qos_map_set_len < 16 || qos_map_set_len > 58 || qos_map_set_len & 1) {
		wpa_printf(MSG_ERROR, "Invalid QoS Map");
		return -1;
	}

	wpa_printf(MSG_ERROR, "%s: Entry,set_qos_map", __func__);
	pbuf = buf;
	ret_s = sprintf_s(pbuf, MAX_DRV_CMD_SIZE, "%s", _cmd);
	if (ret_s == -1) {
		wpa_printf(MSG_ERROR, "%s:%d, sprintf failed, ret=%d", __func__, __LINE__, ret_s);
	}
	pbuf += ret_s;
	*pbuf++ = '\0';

	pst_qos_map = (oal_qos_map_param_stru *) pbuf;
	pst_qos_map->valid = 1;
	pst_qos_map->num_dscp_except = (qos_map_set_len - 16) / 2;
	if (pst_qos_map->num_dscp_except) {
		for (i = 0; i < pst_qos_map->num_dscp_except; i++) {
			pst_qos_map->dscp_exception[i] = qos_map_set[i * 2];
			pst_qos_map->dscp_exception_up[i] = qos_map_set[i * 2 + 1];
		}
	}
	up_start = qos_map_set_len - 16;
	for (i = 0; i < MAX_QOS_UP_RANGE; i++) {
		pst_qos_map->up_low[i] = qos_map_set[up_start + (i * 2)];
		pst_qos_map->up_high[i] = qos_map_set[up_start + (i * 2) + 1];
	}

	ret = wpa_driver_nl80211_driver_cmd(priv, buf, buf, strlen(_cmd) + 1 + sizeof(oal_qos_map_param_stru));
	return ret;
}

int wpa_driver_set_tx_power(void *priv, int power)
{
	char buf[MAX_PRIV_CMD_SIZE] = {0};
	int len = 0;

	wpa_printf(MSG_ERROR, "%s: Entry,power limit:%d", __func__, power);
	if (power <= 0 || power > 100) {
		wpa_printf(MSG_ERROR, "%s: Entry,invalid power, valid power should in range(0,100]!", __func__);
		return -1;
	}
	len = snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "TX_POWER %d", power);
	if (len == -1) {
		wpa_printf(MSG_ERROR, "%s:%d, snprintf failed, ret=%d", __func__, __LINE__, len);
	}
	buf[len] = '\0';
	wpa_printf(MSG_DEBUG, "%s:buf is %s", __func__, buf);

	return wpa_driver_nl80211_driver_cmd(priv, buf, buf, len);
}

#ifdef CONFIG_OWE
int wpa_driver_nl80211_sta_assoc(void *priv, const u8 *own_addr, const u8 *addr,
								int reassoc, u16 status, const u8 *pst_assoc_rsp_ie, size_t len)
{
	char buf[MAX_WPSP2PIE_CMD_SIZE] = {0};
	char *pbuf;
	char *_cmd = "SET_MLME_IE";
	int ret = 0;
	int ret_s;
	set_mlme_stru *pst_mlme_ie = NULL;

	if (NULL == pst_assoc_rsp_ie) {
		wpa_printf(MSG_WARNING, "%s[%d]: buf is null.\n", __FUNCTION__, __LINE__);
		return -1;
	}

	if (len > WLAN_WPS_IE_MAX_SIZE) {
		/* ����·�ie ���ȴ����¼��ڴ��С����ʾ���� */
		wpa_printf(MSG_ERROR, "%s[%d]: assoc rsp ie too large to wifi driver buffer. ie_len %zu, MAX len %d",
				__FUNCTION__, __LINE__, len, WLAN_WPS_IE_MAX_SIZE);
		return -1;
	}

	pbuf = buf;
	ret_s = sprintf_s(pbuf, MAX_WPSP2PIE_CMD_SIZE, "%s", _cmd);
	if (ret_s == -1) {
		wpa_printf(MSG_ERROR, "%s:%d, sprintf failed, ret=%d", __func__, __LINE__, ret_s);
	}
	pbuf += ret_s;
	*pbuf++ = '\0';

	pst_mlme_ie = (set_mlme_stru *) pbuf;
	if (reassoc) {
		pst_mlme_ie->en_mlme_type = OAL_IEEE80211_MLME_REASSOC_RSP;
	} else {
		pst_mlme_ie->en_mlme_type = OAL_IEEE80211_MLME_ASSOC_RSP;
	}
	pst_mlme_ie->us_status = status;
	ret_s = memcpy_s(pst_mlme_ie->uc_macaddr, sizeof(pst_mlme_ie->uc_macaddr), addr, ETH_ALEN);
	if (ret_s != EOK) {
		wpa_printf(MSG_ERROR, "%s:%d, memcpy failed, ret=%d", __func__, __LINE__, ret_s);
	}

	pst_mlme_ie->us_ie_len = len;
	ret_s = memcpy_s(pst_mlme_ie->auc_ie, sizeof(pst_mlme_ie->auc_ie), pst_assoc_rsp_ie, len);
	if (ret_s != EOK) {
		wpa_printf(MSG_ERROR, "%s:%d, memcpy failed, ret=%d", __func__, __LINE__, ret_s);
	}

	wpa_printf(MSG_ERROR, "%s[%d]: sta_assoc begin send assoc rsp ie len[%zu] to driver", __FUNCTION__, __LINE__, len);

	wpa_printf(MSG_ERROR, "cmd:%s, type %d, status %d, ie_len %d",
				_cmd,
				pst_mlme_ie->en_mlme_type,
				pst_mlme_ie->us_status,
				pst_mlme_ie->us_ie_len);

	wpa_hexdump(MSG_ERROR, "MLME: set sta_assoc ie", (const char *) pbuf, pst_mlme_ie->us_ie_len + 8);

	if (os_strlen(_cmd) + sizeof(set_mlme_stru) + 1 < sizeof(buf)) {
		ret = wpa_driver_nl80211_driver_cmd(priv, buf, buf,
					os_strlen(_cmd) + sizeof(set_mlme_stru) + 1);
	} else {
		wpa_printf(MSG_ERROR, "%s:error. app total length to large! cmd_len = %zu, buffer = %d",
			__func__, os_strlen(_cmd) + sizeof(set_mlme_stru) + 1, (int)sizeof(buf));
		ret = -1;
	}

	return ret;
}
#endif

#ifdef CONFIG_HW_GET_P2P_SIGNAL_POLL
int wpa_drv_get_p2p_link_noise(void *priv, struct wpa_signal_info *si)
{
	if (priv == NULL || si == NULL) {
		return -1;
	}
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	os_memset(si, 0, sizeof(struct wpa_signal_info));
	return nl80211_get_link_noise(drv, si);
}
#endif /* CONFIG_HW_GET_P2P_SIGNAL_POLL */

static int wpa_sockets_open(void)
{
	int skfd;

	skfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (skfd < 0) {
		wpa_printf(MSG_ERROR,
		           "nl80211: socket open failed.");
		return -1;
	}
	return skfd;
}
static void wpa_sockets_close(int32 skfd)
{
	close(skfd);
}
static int wpa_send_cmd_to_driver(int skfd, s8 *ifname, wifi_priv_cmd *ioctl_data)
{
	struct ifreq ifr;
	int ret;
	int ret_s;

	ret_s = memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr));
	if (ret_s != EOK) {
		wpa_printf(MSG_ERROR, "%s:%d, memset failed, ret=%d", __func__, __LINE__, ret_s);
	}

	ret_s = strncpy_s(ifr.ifr_name, IFNAMSIZ, "wlan0", strlen("wlan0"));
	if (ret_s != EOK) {
		wpa_printf(MSG_ERROR, "%s:%d, strncpy failed, ret=%d", __func__, __LINE__, ret_s);
	}
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	ifr.ifr_data = (void *) ioctl_data;

	ret = ioctl(skfd, SIOCDEVPRIVATE + 1, &ifr);

	if (ret < 0) {
		wpa_printf(MSG_ERROR,
		           "%s: failed to issue ioctl cmd.\n", __func__);
	}

	return ret;
}

static cust_data_stru global_cust_data = {0, 0};

static void get_cust_config_params(void)
{
	int skfd;
	wifi_priv_cmd ioctl_data = {0};
	int ret;
	int len;
#ifdef CONFIG_DRIVER_NL80211_HISI_TRUNK
	char buff[MAX_PRIV_CMD_SIZE] = {0};
#endif /* CONFIG_DRIVER_NL80211_HISI_TRUNK */

	if (-1 == (skfd = wpa_sockets_open())) {
		wpa_printf(MSG_ERROR,
		           "%s: failed create socket.\n", __func__);
		return;
	}

#ifdef CONFIG_DRIVER_NL80211_HISI_TRUNK
	ioctl_data.buf = buff;
	len = snprintf_s(buff, MAX_PRIV_CMD_SIZE, MAX_PRIV_CMD_SIZE - 1, "WPAS_GET_CUST");
#else
	len = snprintf_s(ioctl_data.buf, MAX_PRIV_CMD_SIZE, MAX_PRIV_CMD_SIZE - 1, "WPAS_GET_CUST");
#endif
	if (len == -1) {
		wpa_printf(MSG_ERROR, "%s:%d, snprintf failed, ret=%d", __func__, __LINE__, len);
	}
	ioctl_data.total_len = MAX_PRIV_CMD_SIZE;
	ioctl_data.used_len = len;
#ifdef HW_WPA_REDUCE_LOG
	wpa_printf(MSG_ERROR, "%s:ioctl_data cmd is %s", __func__, ioctl_data.buf);
#else
	wpa_printf(MSG_ERROR, "%s:ioctl_data cmd is %s", __func__, ioctl_data.buf);
#endif

	ret = wpa_send_cmd_to_driver(skfd, (s8 *) "wlan0", &ioctl_data);

	if (ret < 0) {
		wpa_printf(MSG_ERROR,
		           "%s: send cmd to driver failed.\n", __func__);
		wpa_sockets_close(skfd);
		return;
	}

	drv_errors = 0;

	global_cust_data.read = 1;
	global_cust_data.disable_capab_2ght40 = (u32) (*ioctl_data.buf);
	wpa_printf(MSG_ERROR,
		"%s: update wps global cust data: [disable_capab_2ght40:%d]\n", __func__, global_cust_data.disable_capab_2ght40);

	wpa_sockets_close(skfd);
}

u32 get_cust_disable_capab_2ght40(void)
{
	if (!global_cust_data.read) {
		get_cust_config_params();
	}

	return global_cust_data.disable_capab_2ght40;
}