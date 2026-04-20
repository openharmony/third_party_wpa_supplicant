/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#ifdef EXT_AUTHENTICATION_SUPPORT
#include "ext_authentication.h"

#include "eapol_supp/eapol_supp_sm.h"
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
static size_t g_eapDataLen = 0;
static struct eap_sm* g_eapSm = NULL;
static int g_extAuthMsgIdx = 0;
static int g_code = 0;
static struct wpabuf *g_decryptBuf = NULL;
static bool g_extAuthPending = false;

enum ext_auth_pending_event_type {
    EXT_AUTH_PENDING_RX_FRAME = 0,
    EXT_AUTH_PENDING_TX_RESPONSE,
};

struct ext_auth_pending_frame {
    struct ext_auth_pending_frame *next;
    enum ext_auth_pending_event_type type;
    union {
        struct {
            struct eapol_sm *sm;
            u8 src[ETH_ALEN];
            u8 *buf;
            size_t len;
            enum frame_encryption encrypted;
        } rx;
        struct {
            struct eap_sm *sm;
        } tx;
    } data;
};

static struct ext_auth_pending_frame *g_pendingFrameHead = NULL;
static struct ext_auth_pending_frame *g_pendingFrameTail = NULL;

static size_t get_pending_ext_auth_frame_count(void)
{
    size_t count = 0;
    struct ext_auth_pending_frame *frame = g_pendingFrameHead;
    while (frame != NULL) {
        ++count;
        frame = frame->next;
    }
    return count;
}

static void clear_pending_ext_auth_frames(void)
{
    size_t count = get_pending_ext_auth_frame_count();
    struct ext_auth_pending_frame *frame = g_pendingFrameHead;
    while (frame != NULL) {
        struct ext_auth_pending_frame *next = frame->next;
        if (frame->type == EXT_AUTH_PENDING_RX_FRAME) {
            os_free(frame->data.rx.buf);
        }
        os_free(frame);
        frame = next;
    }
    g_pendingFrameHead = NULL;
    g_pendingFrameTail = NULL;
    if (count > 0) {
        wpa_printf(MSG_INFO, "ext_authentication clear pending eapol frames, count = %zu", count);
    }
}

bool is_ext_auth_pending()
{
    return g_extAuthPending;
}

void set_ext_auth_pending(bool pending)
{
    if (g_extAuthPending != pending) {
        wpa_printf(MSG_INFO, "ext_authentication pending state change: %d -> %d, queue depth = %zu",
            g_extAuthPending, pending, get_pending_ext_auth_frame_count());
    }
    g_extAuthPending = pending;
}

void abort_ext_auth_pending(bool clearQueue)
{
    bool wasPending = g_extAuthPending;
    size_t count = get_pending_ext_auth_frame_count();

    g_extAuthPending = false;
    g_eapSm = NULL;
    clear_tx_prepared();
    clear_eap_data();

    if (clearQueue) {
        clear_pending_ext_auth_frames();
    }

    if (wasPending || count > 0) {
        wpa_printf(MSG_INFO, "ext_authentication abort pending transaction, clearQueue = %d, remaining queue depth = %zu",
            clearQueue, get_pending_ext_auth_frame_count());
    }
}

int enqueue_ext_auth_pending_frame(struct eapol_sm *sm, const u8 *src, const u8 *buf, size_t len, int encrypted)
{
    if (sm == NULL || src == NULL || buf == NULL || len == 0) {
        wpa_printf(MSG_ERROR, "ext_authentication enqueue pending frame input error");
        return -1;
    }

    struct ext_auth_pending_frame *frame = os_zalloc(sizeof(*frame));
    if (frame == NULL) {
        wpa_printf(MSG_ERROR, "ext_authentication alloc pending frame fail");
        return -1;
    }

    frame->type = EXT_AUTH_PENDING_RX_FRAME;

    frame->data.rx.buf = os_malloc(len);
    if (frame->data.rx.buf == NULL) {
        os_free(frame);
        wpa_printf(MSG_ERROR, "ext_authentication alloc pending frame data fail");
        return -1;
    }

    if (memcpy_s(frame->data.rx.buf, len, buf, len) != 0 ||
        memcpy_s(frame->data.rx.src, sizeof(frame->data.rx.src), src, ETH_ALEN) != 0) {
        os_free(frame->data.rx.buf);
        os_free(frame);
        wpa_printf(MSG_ERROR, "ext_authentication copy pending frame fail");
        return -1;
    }

    frame->data.rx.sm = sm;
    frame->data.rx.len = len;
    frame->data.rx.encrypted = (enum frame_encryption) encrypted;
    if (g_pendingFrameTail == NULL) {
        g_pendingFrameHead = frame;
        g_pendingFrameTail = frame;
    } else {
        g_pendingFrameTail->next = frame;
        g_pendingFrameTail = frame;
    }
    wpa_printf(MSG_INFO, "ext_authentication queue eapol frame, len = %zu, queue depth = %zu, encrypted = %d",
        len, get_pending_ext_auth_frame_count(), encrypted);
    return 0;
}

int enqueue_ext_auth_pending_response(struct eap_sm *sm)
{
    if (sm == NULL) {
        wpa_printf(MSG_ERROR, "ext_authentication enqueue pending response input error");
        return -1;
    }

    struct ext_auth_pending_frame *iter = g_pendingFrameHead;
    while (iter != NULL) {
        if (iter->type == EXT_AUTH_PENDING_TX_RESPONSE && iter->data.tx.sm == sm) {
            wpa_printf(MSG_INFO, "ext_authentication pending response already queued, queue depth = %zu",
                get_pending_ext_auth_frame_count());
            return 0;
        }
        iter = iter->next;
    }

    struct ext_auth_pending_frame *frame = os_zalloc(sizeof(*frame));
    if (frame == NULL) {
        wpa_printf(MSG_ERROR, "ext_authentication alloc pending response fail");
        return -1;
    }

    frame->type = EXT_AUTH_PENDING_TX_RESPONSE;
    frame->data.tx.sm = sm;
    if (g_pendingFrameTail == NULL) {
        g_pendingFrameHead = frame;
        g_pendingFrameTail = frame;
    } else {
        g_pendingFrameTail->next = frame;
        g_pendingFrameTail = frame;
    }
    wpa_printf(MSG_INFO, "ext_authentication queue response upload, queue depth = %zu",
        get_pending_ext_auth_frame_count());
    return 0;
}

void process_ext_auth_pending_frame()
{
    while (!g_extAuthPending && g_pendingFrameHead != NULL) {
        struct ext_auth_pending_frame *frame = g_pendingFrameHead;
        g_pendingFrameHead = frame->next;
        if (g_pendingFrameHead == NULL) {
            g_pendingFrameTail = NULL;
        }
        if (frame->type == EXT_AUTH_PENDING_RX_FRAME) {
            wpa_printf(MSG_INFO, "ext_authentication replay eapol frame, len = %zu, remaining queue depth = %zu",
                frame->data.rx.len, get_pending_ext_auth_frame_count());
            (void)eapol_sm_rx_eapol(frame->data.rx.sm, frame->data.rx.src, frame->data.rx.buf, frame->data.rx.len,
                frame->data.rx.encrypted);
            os_free(frame->data.rx.buf);
        } else {
            wpa_printf(MSG_INFO, "ext_authentication replay response upload, remaining queue depth = %zu",
                get_pending_ext_auth_frame_count());
            ext_auth_upload_pending_response(frame->data.tx.sm);
        }
        os_free(frame);
    }
}

void set_decrypt_buf(const struct wpabuf *in)
{
    if (g_decryptBuf != NULL) {
        wpabuf_free(g_decryptBuf);
    }

    if (in == NULL) {
        return;
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
        for (int idx = 0; idx < EAP_TYPE_SIZE; ++idx) {
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
    return g_extAuthMsgIdx;
}

void add_authentication_idx()
{
    int idxMod = 100;
    g_extAuthMsgIdx = (g_extAuthMsgIdx + 1) % idxMod;
}

uint8_t* get_eap_data()
{
    return g_eapData;
}

size_t get_eap_data_len()
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
    abort_ext_auth_pending(true);
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
