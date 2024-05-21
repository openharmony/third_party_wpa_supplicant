/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CM_TYPE_H
#define CM_TYPE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif
#ifndef CM_API_PUBLIC
    #if defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__) || defined(__ICCARM__) /* __ICCARM__ for iar */
        #define CM_API_EXPORT
    #else
        #define CM_API_EXPORT __attribute__ ((visibility("default")))
    #endif
#else
    #define CM_API_EXPORT __attribute__ ((visibility("default")))
#endif

#define MAX_LEN_CERTIFICATE    8196

#define MAX_LEN_CERTIFICATE_CHAIN    (3 * MAX_LEN_CERTIFICATE)

#define MAX_SUFFIX_LEN           16
#define MAX_COUNT_CERTIFICATE    256
#define MAX_LEN_URI              256
#define MAX_AUTH_LEN_URI         256
#define MAX_LEN_CERT_ALIAS       65     /* include 1 byte: the terminator('\0') */
#define MAX_LEN_SUBJECT_NAME     256
#define MAX_LEN_PACKGE_NAME      64
#define MAX_UINT32_LEN           16

#define CM_ARRAY_SIZE(arr) ((sizeof(arr)) / (sizeof((arr)[0])))

/*
 * Align to 4-tuple
 * Before calling this function, ensure that the size does not overflow after 3 is added.
 */
#define ALIGN_SIZE(size) ((((uint32_t)(size) + 3) >> 2) << 2)

#define CM_BITS_PER_BYTE 8

#define CM_CREDENTIAL_STORE             0
#define CM_SYSTEM_TRUSTED_STORE         1
#define CM_USER_TRUSTED_STORE           2
#define CM_PRI_CREDENTIAL_STORE         3
#define CM_SYS_CREDENTIAL_STORE         4

enum CmKeyDigest {
    CM_DIGEST_NONE = 0,
    CM_DIGEST_MD5 = 1,
    CM_DIGEST_SHA1 = 10,
    CM_DIGEST_SHA224 = 11,
    CM_DIGEST_SHA256 = 12,
    CM_DIGEST_SHA384 = 13,
    CM_DIGEST_SHA512 = 14,
};

enum CmKeyPurpose {
    CM_KEY_PURPOSE_ENCRYPT = 1,                   /* Usable with RSA, EC, AES, and SM4 keys. */
    CM_KEY_PURPOSE_DECRYPT = 2,                   /* Usable with RSA, EC, AES, and SM4 keys. */
    CM_KEY_PURPOSE_SIGN = 4,                      /* Usable with RSA, EC keys. */
    CM_KEY_PURPOSE_VERIFY = 8,                    /* Usable with RSA, EC keys. */
    CM_KEY_PURPOSE_DERIVE = 16,                   /* Usable with EC keys. */
    CM_KEY_PURPOSE_WRAP = 32,                     /* Usable with wrap key. */
    CM_KEY_PURPOSE_UNWRAP = 64,                   /* Usable with unwrap key. */
    CM_KEY_PURPOSE_MAC = 128,                     /* Usable with mac. */
    CM_KEY_PURPOSE_AGREE = 256,                   /* Usable with agree. */
};

enum CmKeyPadding {
    CM_PADDING_NONE = 0,
    CM_PADDING_OAEP = 1,
    CM_PADDING_PSS = 2,
    CM_PADDING_PKCS1_V1_5 = 3,
    CM_PADDING_PKCS5 = 4,
    CM_PADDING_PKCS7 = 5,
};

enum CmErrorCode {
    CM_SUCCESS = 0,
    CM_FAILURE = -1,

    CMR_ERROR_NOT_PERMITTED = -2,
    CMR_ERROR_NOT_SUPPORTED = -3,
    CMR_ERROR_STORAGE = -4,
    CMR_ERROR_NOT_FOUND = -5,
    CMR_ERROR_NULL_POINTER = -6,
    CMR_ERROR_INVALID_ARGUMENT = -7,
    CMR_ERROR_MAKE_DIR_FAIL = -8,
    CMR_ERROR_INVALID_OPERATION = -9,
    CMR_ERROR_OPEN_FILE_FAIL = -10,
    CMR_ERROR_READ_FILE_ERROR = -11,
    CMR_ERROR_WRITE_FILE_FAIL = -12,
    CMR_ERROR_REMOVE_FILE_FAIL = -13,
    CMR_ERROR_CLOSE_FILE_FAIL = -14,
    CMR_ERROR_MALLOC_FAIL = -15,
    CMR_ERROR_NOT_EXIST = -16,
    CMR_ERROR_ALREADY_EXISTS = -17,
    CMR_ERROR_INSUFFICIENT_DATA = -18,
    CMR_ERROR_BUFFER_TOO_SMALL = -19,
    CMR_ERROR_INVALID_CERT_FORMAT = -20,
    CMR_ERROR_PARAM_NOT_EXIST = -21,
    CMR_ERROR_SESSION_REACHED_LIMIT = -22,
    CMR_ERROR_PERMISSION_DENIED = -23,
    CMR_ERROR_AUTH_CHECK_FAILED = -24,
    CMR_ERROR_KEY_OPERATION_FAILED = -25,
    CMR_ERROR_NOT_SYSTEMP_APP = -26,
    CMR_ERROR_CERT_NUM_REACHED_LIMIT = -27,
    CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT = -28,
};

enum CMErrorCode { /* temp use */
    CMR_OK = 0,
    CMR_ERROR = -1,
};

enum CmTagType {
    CM_TAG_TYPE_INVALID = 0 << 28,
    CM_TAG_TYPE_INT = 1 << 28,
    CM_TAG_TYPE_UINT = 2 << 28,
    CM_TAG_TYPE_ULONG = 3 << 28,
    CM_TAG_TYPE_BOOL = 4 << 28,
    CM_TAG_TYPE_BYTES = 5 << 28,
};

enum CmTag {
    /* Inner-use TAGS used for ipc serialization */
    CM_TAG_PARAM0_BUFFER = CM_TAG_TYPE_BYTES | 30001,
    CM_TAG_PARAM1_BUFFER = CM_TAG_TYPE_BYTES | 30002,
    CM_TAG_PARAM2_BUFFER = CM_TAG_TYPE_BYTES | 30003,
    CM_TAG_PARAM3_BUFFER = CM_TAG_TYPE_BYTES | 30004,
    CM_TAG_PARAM4_BUFFER = CM_TAG_TYPE_BYTES | 30005,
    CM_TAG_PARAM0_UINT32 = CM_TAG_TYPE_UINT | 30006,
    CM_TAG_PARAM1_UINT32 = CM_TAG_TYPE_UINT | 30007,
    CM_TAG_PARAM2_UINT32 = CM_TAG_TYPE_UINT | 30008,
    CM_TAG_PARAM3_UINT32 = CM_TAG_TYPE_UINT | 30009,
    CM_TAG_PARAM4_UINT32 = CM_TAG_TYPE_UINT | 30010,
    CM_TAG_PARAM0_BOOL = CM_TAG_TYPE_BOOL | 30011,
    CM_TAG_PARAM1_BOOL = CM_TAG_TYPE_BOOL | 30012,
    CM_TAG_PARAM2_BOOL = CM_TAG_TYPE_BOOL | 30013,
    CM_TAG_PARAM3_BOOL = CM_TAG_TYPE_BOOL | 30014,
    CM_TAG_PARAM4_BOOL = CM_TAG_TYPE_BOOL | 30015,
    CM_TAG_PARAM0_NULL = CM_TAG_TYPE_BYTES | 30016,
    CM_TAG_PARAM1_NULL = CM_TAG_TYPE_BYTES | 30017,
    CM_TAG_PARAM2_NULL = CM_TAG_TYPE_BYTES | 30018,
    CM_TAG_PARAM3_NULL = CM_TAG_TYPE_BYTES | 30019,
    CM_TAG_PARAM4_NULL = CM_TAG_TYPE_BYTES | 30020,
};

#define CM_PARAM_BUFFER_NULL_INTERVAL ((CM_TAG_PARAM0_NULL) - (CM_TAG_PARAM0_BUFFER))

enum CmSendType {
    CM_SEND_TYPE_ASYNC = 0,
    CM_SEND_TYPE_SYNC,
};

struct CmBlob {
    uint32_t size;
    uint8_t *data;
};

struct Credential {
    uint32_t isExist;
    char type[MAX_LEN_SUBJECT_NAME];
    char alias[MAX_LEN_CERT_ALIAS];
    char keyUri[MAX_LEN_URI];
    uint32_t certNum;
    uint32_t keyNum;
    struct CmBlob credData;
};

struct CmParam {
    uint32_t tag;
    union {
        bool boolParam;
        int32_t int32Param;
        uint32_t uint32Param;
        uint64_t uint64Param;
        struct CmBlob blob;
    };
};

struct CmParamSet {
    uint32_t paramSetSize;
    uint32_t paramsCnt;
    struct CmParam params[];
};

struct CmSignatureSpec {
    uint32_t purpose;
    uint32_t padding;
    uint32_t digest;
};

static inline bool CmIsAdditionOverflow(uint32_t a, uint32_t b)
{
    return (UINT32_MAX - a) < b;
}

static inline int32_t CmCheckBlob(const struct CmBlob *blob)
{
    if ((blob == NULL) || (blob->data == NULL) || (blob->size == 0)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* CM_TYPE_H */
