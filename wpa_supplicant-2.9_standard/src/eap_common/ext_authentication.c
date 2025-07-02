/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#ifdef EXT_AUTHENTICATION_SUPPORT
#include "ext_authentication.h"

#include "common.h"
#include "includes.h"
#include "securec.h"
#include "trace.h"
#include "wpa_debug.h"

#define EXT_AUTH_CODE_SIZE 5
#define EAP_TYPE_SIZE 255

static u8 g_authMap[EXT_AUTH_CODE_SIZE][EAP_TYPE_SIZE] = {0};

const char *g_ifnameToString[] = {
    "unkown",
    "wlan0",
    "eth0"
};

bool reg_ext_auth(int code, int type, int ifname)
{
    wpa_printf(MSG_INFO, "ext_certification reg_ext_auth : code : %d , type : %d, ifname : %d", code, type, ifname);
    bool illegal = code < 1 || code >= EXT_AUTH_CODE_SIZE || type < 0 || type >= EAP_TYPE_SIZE || ifname < 0 ||
        ifname >= IFNAME_SIZE;
    if (illegal) {
        wpa_printf(MSG_ERROR, "ext_authentication reg_ext_auth : code : %d , type : %d, ifname : %d", code, type,
            ifname);
        return false;
    }
    g_authMap[code][type] = ifname;
    return true;
}

bool un_reg_ext_auth(int code, int type)
{
    wpa_printf(MSG_INFO, "ext_certification un_reg_ext_auth : code : %d , type : %d", code, type);
    if (code < 1 || code >= EXT_AUTH_CODE_SIZE || type < 0 || type >= EAP_TYPE_SIZE) {
        wpa_printf(MSG_ERROR, "ext_certification un_reg_ext_auth : code : %d , type : %d", code, type);
        return false;
    }
    g_authMap[code][type] = IFNAME_UNKNOWN;
    return true;
}

int get_ext_auth(int code, int type)
{
    wpa_printf(MSG_DEBUG, "ext_certification get_ext_auth : code : %d , type : %d, res : %d", code, type,
        (int)g_authMap[code][type]);
    if (code < 1 || code >= EXT_AUTH_CODE_SIZE || type < 0 || type >= EAP_TYPE_SIZE) {
        wpa_printf(MSG_ERROR, "ext_authentication get_ext_auth : code : %d , type : %d", code, type);
        return IFNAME_UNKNOWN;
    }
    return g_authMap[code][type];
}

static int g_idx = 0;

int get_authentication_idx()
{
    return g_idx;
}

void add_authentication_idx()
{
    int idxMod = 100;
    g_idx = (g_idx + 1) % idxMod;
}

static uint8_t* g_eapData = NULL;
static int g_eapDataLen = 0;

uint8_t* get_eap_data()
{
    return g_eapData;
}

int get_eap_data_len()
{
    return g_eapDataLen;
}

void clear_eap_data()
{
    free(g_eapData);
    g_eapData = NULL;
    g_eapDataLen = 0;
}

void set_eap_data(u8* eapData, int eapDataLen)
{
    if (eapData == NULL || eapDataLen <= 0) {
        wpa_printf(MSG_ERROR, "set_eap_data input error");
        return;
    }
    if (g_eapData != NULL) {
        free(g_eapData); // 保险机制
    }

    g_eapDataLen = eapDataLen;
    g_eapData = (u8*)malloc(eapDataLen * sizeof(u8));
    if (g_eapData == NULL) {
        wpa_printf(MSG_ERROR, "set_eap_data malloc error");
        return;
    }
    // 拷贝数据
    if (memcpy_s(g_eapData, eapDataLen, eapData, eapDataLen) != 0) {
        wpa_printf(MSG_ERROR, "set_eap_data memcpy_s error");
        clear_eap_data();
    }
}

static struct eap_sm* g_eapSm = NULL;

void set_eap_sm(struct eap_sm *eapSm)
{
    g_eapSm = eapSm;
}

struct eap_sm* get_eap_sm()
{
    return g_eapSm;
}

static struct encrypt_data g_encryptData;
void set_encrypt_data(struct eap_ssl_data *ssl, int eapType, int version, unsigned char id)
{
    wpa_printf(MSG_DEBUG, "ext_certification set_encrypt_data : eapType : %d , version : %d", eapType,
        vertion, (u8)id);
    g_encryptData.ssl = ssl;
    g_encryptData.eapType = eapType;
    g_encryptData.vertion = vertion;
    g_encryptData.id = id;
}

void set_encrypt_eap_type(int eapType)
{
    wpa_printf(MSG_DEBUG, "ext_certification set_encrypt_eap_type : eapType : %d", eapType);
    g_encryptData.eapType = eapType;
}

struct encrypt_data* get_encrypt_data()
{
    return &g_encryptData;
}

int g_code = 0;

int get_code()
{
    return g_code;
}

void set_code(int code)
{
    g_code = code;
}

#endif /* EXT_AUTHENTICATION_SUPPORT */