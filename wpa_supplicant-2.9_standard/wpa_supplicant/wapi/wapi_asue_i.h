/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef WAPI_ASUE_I_H_
#define WAPI_ASUE_I_H_

#include "wpa_supplicant_i.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define MAX_WAPI_SSID_LEN 64
#define BK_LEN 16

typedef enum {
	/* No WAPI */
	AUTH_TYPE_NONE_WAPI = 0,
	/* Certificate */
	AUTH_TYPE_WAPI_CERT,
	/* Pre-PSK */
	AUTH_TYPE_WAPI_PSK,
} AUTH_TYPE;

typedef enum {
	/* ascii */
	KEY_TYPE_ASCII = 0,
	/* HEX */
	KEY_TYPE_HEX,
} KEY_TYPE;

enum wapi_event_type {
	WAPI_EVENT_ASSOC = 0,
	WAPI_EVENT_DISASSOC,
};

struct wapi_config {
	u8 *ssid;
	size_t ssid_len;

	u8 *psk;
	size_t psk_len;
	u8 psk_bk[BK_LEN];
	int psk_set;

	int wapi_policy;

	unsigned int pairwise_cipher;
	unsigned int group_cipher;

	int key_mgmt;

	int proto;
	int auth_alg;
	char *cert_name;
	int disabled;
};

void wapi_config_free(struct wapi_config *config);

struct wapi_config *wapi_config_init(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid);

int wapi_asue_init();

int wapi_asue_deinit();

int wapi_asue_update_iface(void *iface);

void wapi_asue_event(enum wapi_event_type action, const u8 *pBSSID, const u8 *pLocalMAC,
				unsigned char *assoc_ie, unsigned char assoc_ie_len);

void wapi_asue_rx_wai(void *ctx, const u8 *src_addr, const u8 *buf, size_t len);

#if defined(__cplusplus)
}
#endif

#endif /* WAPI_ASUE_I_H_ */
