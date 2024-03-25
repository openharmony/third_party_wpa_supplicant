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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/time.h>
#include "utils/common.h"
#include "wapi_asue_i.h"
#include "common/defs.h"

void wapi_config_free(struct wapi_config *config)
{
}

struct wapi_config *wapi_config_init(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid)
{
	return NULL;
}

int wapi_asue_init()
{
	return 0;
}

int wapi_asue_deinit()
{
	return 0;
}

int wapi_asue_update_iface(void *iface)
{
	return 0;
}

void wapi_asue_event(enum wapi_event_type action, const u8 *pBSSID, const u8 *pLocalMAC,
	unsigned char *assoc_ie, unsigned char assoc_ie_len)
{
}

void wapi_asue_rx_wai(void *ctx, const u8 *src_addr, const u8 *buf, size_t len)
{
}
