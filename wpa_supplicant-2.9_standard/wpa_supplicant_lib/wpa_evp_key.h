/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPA_EVP_KEY_H
#define WPA_EVP_KEY_H

#include <openssl/evp.h>
#include "cert_manager_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_SIGNATURE_LEN 1024

EVP_PKEY *GET_EVP_PKEY(const char *key_id);
BIO *BIO_from_cm(const char *key_id);


#ifdef __cplusplus
}
#endif
#endif // WPA_EVP_KEY_H
