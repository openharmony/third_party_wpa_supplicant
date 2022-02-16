/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef _WPA_MAGICLINK_H
#define _WPA_MAGICLINK_H

#include "includes.h"
#include "common.h"
#include "utils/list.h"
#include "wpa_supplicant_i.h"
#include "bss.h"
#include "drivers/driver.h"
#include "driver_i.h"
#include "scan.h"
#include "eap_peer/eap_i.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_MAGICLINK
/*
 * hw_magiclink_p2p_ctrl_connect is for magic link connect
 * connect AP with cmd indicated.
 */
int hw_magiclink_p2p_ctrl_connect(struct wpa_supplicant *wpa_s, char *cmd);
void magiclink_prepare_scan(struct wpa_supplicant *wpas, int *timeout_usec);
int hw_wpas_p2p_group_add(struct wpa_supplicant *wpa_s, int network_id, int persistent, int freq, int max_oper_chwidth);
#endif /* CONFIG_MAGICLINK */

#ifdef __cplusplus
}
#endif
#endif /* _WPA_MAGICLINK_H */
