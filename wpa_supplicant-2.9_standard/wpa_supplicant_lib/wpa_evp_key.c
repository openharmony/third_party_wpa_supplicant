/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "wpa_evp_key.h"

#include <stdlib.h>
#include <string.h>
#include <crypto/evp.h>
#include <crypto/rsa/rsa_local.h>
#include <crypto/x509.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "cert_manager_api.h"
#include "common.h"

static char g_key_uri[MAX_LEN_URI];
static RSA_METHOD g_rsa_method;

static int cm_sign(const struct CmBlob *keyUri, const struct CmBlob *message, struct CmBlob *signature)
{
    int32_t ret;
    uint64_t handleValue = 0;
    struct CmBlob handle = { sizeof(uint64_t), (uint8_t *)&handleValue };
    struct CmSignatureSpec spec = { CM_KEY_PURPOSE_SIGN, CM_PADDING_PKCS1_V1_5, CM_DIGEST_NONE };

    ret = CmInit(keyUri, &spec, &handle);
    if (ret != CM_SUCCESS) {
        wpa_printf(MSG_DEBUG, "sign CmInit failed");
        return 0;
    }

    ret = CmUpdate(&handle, message);
    if (ret != CM_SUCCESS) {
        wpa_printf(MSG_DEBUG, "sign CmUpdate failed");
        return 0;
    }

    struct CmBlob inDataFinish = { 0, NULL };
    ret = CmFinish(&handle, &inDataFinish, signature);
    if (ret != CM_SUCCESS) {
        wpa_printf(MSG_DEBUG, "sign CmFinish failed");
        return 0;
    }

    ret = CmAbort(&handle);
    if (ret != CM_SUCCESS) {
        wpa_printf(MSG_DEBUG, "sign CmAbort failed");
    }
    return 1;
}

int rsa_sign(int type, const unsigned char *m, unsigned int m_length,
    unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    int ret;
    struct CmBlob keyUri = { sizeof(g_key_uri), (uint8_t *)g_key_uri };
    struct CmBlob message = { m_length, (uint8_t *)m };
    uint8_t signData[DEFAULT_SIGNATURE_LEN] = { 0 };
    struct CmBlob signature = { DEFAULT_SIGNATURE_LEN, (uint8_t *)signData };

    wpa_printf(MSG_DEBUG, "%s type:%d m:%d m_len:%u", __func__, type, m == NULL, m_length);
    ret = cm_sign(&keyUri, &message, &signature);
    if (ret && signature.size > 0) {
        *siglen = signature.size;
        os_memcpy(sigret, signature.data, signature.size);
        wpa_printf(MSG_ERROR, "%s sign len:%u", __func__, signature.size);
        return 1;
    }
    return 0;
}

static EVP_PKEY *wrap_rsa(const char *key_id, const RSA *public_rsa)
{
    RSA *rsa = RSA_new();
    if (rsa == NULL) {
        wpa_printf(MSG_ERROR, "%s rsa is NULL", __func__);
        return NULL;
    }
    os_memset(&g_rsa_method, 0, sizeof(RSA_METHOD));
    g_rsa_method.rsa_sign = rsa_sign;

    RSA_set_method(rsa, &g_rsa_method);
    rsa->n = BN_dup(public_rsa->n);
    rsa->e = BN_dup(public_rsa->e);
    EVP_PKEY *result = EVP_PKEY_new();
    if (result != NULL && !EVP_PKEY_assign_RSA(result, rsa)) {
        wpa_printf(MSG_ERROR, "%s assign rsa fail", __func__);
        RSA_free(rsa);
        EVP_PKEY_free(result);
        return NULL;
    }

    os_memset(g_key_uri, 0, sizeof(g_key_uri));
    if (strlen(key_id) < sizeof(g_key_uri))
        os_memcpy(g_key_uri, key_id, strlen(key_id));
    return result;
}

static EVP_PKEY* get_pubkey(const char *key_id)
{
    BIO* bio = BIO_from_cm(key_id);
    if (bio == NULL) {
        wpa_printf(MSG_ERROR, "%s bio is null", __func__);
        return NULL;
    }

    X509 *decoded_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (decoded_cert == NULL) {
        wpa_printf(MSG_ERROR, "%s decoded cert is null", __func__);
        return NULL;
    }
    return X509_get_pubkey(decoded_cert);
}

EVP_PKEY *GET_EVP_PKEY(const char *key_id)
{
    int key_type;
    EVP_PKEY *wrap_key = NULL;
    RSA *public_rsa = NULL;
    EVP_PKEY *pub_key = NULL;

    if (key_id == NULL) {
        wpa_printf(MSG_ERROR, "key id is NULL");
        return NULL;
    }
    pub_key = get_pubkey(key_id);
    if (pub_key == NULL) {
        wpa_printf(MSG_ERROR, "pub key is NULL");
        return NULL;
    }

    key_type = EVP_PKEY_type(pub_key->type);
    if (key_type != EVP_PKEY_RSA) {
        wpa_printf(MSG_ERROR, "unsupported key type:%d", key_type);
        EVP_PKEY_free(pub_key);
        return NULL;
    }

    public_rsa = EVP_PKEY_get0_RSA(pub_key);
    if (public_rsa == NULL ) {
        wpa_printf(MSG_ERROR, "public_rsa is NULL");
        EVP_PKEY_free(pub_key);
        return NULL;
    }

    wrap_key = wrap_rsa(key_id, public_rsa);
    EVP_PKEY_free(pub_key);
    return wrap_key;
}

BIO *BIO_from_cm(const char *key_id)
{
    BIO *bio = NULL;
    struct Credential certificate = { 0 };
    uint32_t store = CM_PRI_CREDENTIAL_STORE;
    struct CmBlob keyUri;

    if (key_id == NULL) {
        wpa_printf(MSG_ERROR, "key id is NULL");
        return NULL;
    }
    keyUri.size = strlen(key_id) + 1;
    keyUri.data = (uint8_t *)key_id;

    certificate.credData.data = (uint8_t *)malloc(MAX_LEN_CERTIFICATE_CHAIN);
    if (certificate.credData.data == NULL) {
        wpa_printf(MSG_ERROR, "%s malloc fail", __func__);
        return bio;
    }
    certificate.credData.size = MAX_LEN_CERTIFICATE_CHAIN;
    int ret = CmGetAppCert(&keyUri, store, &certificate);
    if (ret != 0) {
        wpa_printf(MSG_ERROR, "%s key:%s, size:%u, ret:%d", __func__,
            key_id, certificate.credData.size, ret);
        free(certificate.credData.data);
        return bio;
    }

    wpa_printf(MSG_DEBUG, "%s key:%s, size:%u", __func__,
            key_id, certificate.credData.size);

    if (certificate.credData.size > 0)
        bio = BIO_new_mem_buf(certificate.credData.data, certificate.credData.size);

    free(certificate.credData.data);
    return bio;
}
