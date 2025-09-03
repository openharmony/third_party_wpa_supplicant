/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#ifdef EXT_AUTHENTICATION_SUPPORT
#include "ext_authentication.h"

#include "includes.h"
#include "securec.h"
#include "trace.h"
#include "wpa_debug.h"

#define EXT_AUTH_CODE_SIZE 5
#define EAP_TYPE_SIZE 255

static u8 g_authMap[EXT_AUTH_CODE_SIZE][EAP_TYPE_SIZE] = {0};
static struct encrypt_data g_encryptData;
static bool g_encryptEnable = false;
static bool g_txPrepared = false;
static uint8_t* g_eapData = NULL;
static int g_eapDataLen = 0;
static struct eap_sm* g_eapSm = NULL;
static int g_idx = 0;
static int g_code = 0;
static struct wpabuf *g_decryptBuf = NULL;

void set_decrypt_buf(const struct wpabuf *in)
{
    if (g_decryptBuf != NULL) {
        wpabuf_free(g_decryptBuf);
    }
    g_decryptBuf = wpabuf_alloc(in->size);
	if (g_decryptBuf == NULL) {
		wpa_printf(MSG_ERROR, "wpabuf_alloc fail");
		return;
	}
	wpabuf_put_buf(g_decryptBuf, in);
}

struct wpabuf* get_decrypt_buf()
{
    return g_decryptBuf;
}

const char *g_ifnameToString[] = {
    "unkown",
    "wlan0",
    "eth0"
};

const char *ifname_to_string(int ifname)
{
    if (ifname <= IFNAME_UNKNOWN || ifname >= IFNAME_SIZE) {
        wpa_printf(MSG_ERROR, "ext_certification ifname_to_string : ifname : %d", ifname);
        return g_ifnameToString[0];
    }
    return g_ifnameToString[ifname];
}

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
 
    if (code >= EXT_AUTH_CODE_SUCCESS) {
        for (int idx = 0; idx <= EAP_TYPE_SIZE; ++idx) {
            g_authMap[code][idx] = ifname;
        }
        return true;
    }
 
    g_authMap[code][type] = ifname;
    return true;
}

void clear_ext_auth()
{
    for (int code = 0; code < EXT_AUTH_CODE_SIZE; ++code) {
        for (int type = 0; type < EAP_TYPE_SIZE; ++type) {
            g_authMap[code][type] = IFNAME_UNKNOWN;
        }
    }
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

int get_authentication_idx()
{
    return g_idx;
}

void add_authentication_idx()
{
    int idxMod = 100;
    g_idx = (g_idx + 1) % idxMod;
}

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
    if (g_eapData != NULL) {
        (void)memset_s(g_eapData, g_eapDataLen, 0, g_eapDataLen);
        os_free(g_eapData); 
        g_eapData = NULL;
    }
    
    g_eapDataLen = 0;
}

void set_eap_data(u8* eapData, int eapDataLen)
{
    if (eapData == NULL || eapDataLen <= 0) {
        wpa_printf(MSG_ERROR, "set_eap_data input error");
        return;
    }
    clear_eap_data();
    g_eapDataLen = eapDataLen;
    g_eapData = (u8*)malloc(eapDataLen * sizeof(u8));
    if (g_eapData == NULL) {
        wpa_printf(MSG_ERROR, "set_eap_data malloc error");
        clear_eap_data();
        return;
    }
    // 拷贝数据
    if (memcpy_s(g_eapData, eapDataLen, eapData, eapDataLen) != 0) {
        wpa_printf(MSG_ERROR, "set_eap_data memcpy_s error");
        clear_eap_data();
    }

    g_txPrepared = true;
}

void set_eap_sm(struct eap_sm *eapSm)
{
    g_eapSm = eapSm;
}

struct eap_sm* get_eap_sm()
{
    return g_eapSm;
}

bool get_eap_encrypt_enable()
{
    return g_encryptEnable;
}

void set_encrypt_data(struct eap_ssl_data *ssl, int eapType, int version, unsigned char id)
{
    wpa_printf(MSG_INFO, "ext_certification set_encrypt_data : eapType : %d , version : %d, id : %hhu", eapType,
        version, (u8)id);
    g_encryptData.ssl = ssl;
    g_encryptData.eapType = eapType;
    g_encryptData.version = version;
    g_encryptData.id = id;
    g_encryptEnable = true;
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

int get_code()
{
    wpa_printf(MSG_DEBUG, "ext_certification get_code : code : %d", g_code);
    return g_code;
}

void set_code(int code)
{
    wpa_printf(MSG_DEBUG, "ext_certification set_code : code : %d", code);
    g_code = code;
}

void ext_authentication_eap_init()
{
    (void)memset_s(&g_encryptData, sizeof(struct encrypt_data), 0, sizeof(struct encrypt_data));
    if (g_decryptBuf != NULL) {
        wpabuf_free(g_decryptBuf);
        g_decryptBuf = NULL;
    }
    clear_eap_data();
    g_eapSm = NULL;
    g_encryptEnable = false;
    wpa_printf(MSG_INFO, "ext_authentication_eap_init finished");
}

int get_tx_prepared()
{
    return g_txPrepared;
}

void clear_tx_prepared()
{
    g_txPrepared = false;
}
#endif /* EXT_AUTHENTICATION_SUPPORT */
