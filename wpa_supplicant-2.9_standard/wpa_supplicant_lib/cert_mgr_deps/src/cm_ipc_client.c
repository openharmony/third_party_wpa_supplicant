/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "cm_ipc_client.h"
#include "cm_ipc_client_serialization.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_x509.h"
#include "cm_param.h"
#include "cm_request.h"

static int32_t CmSendParcelInit(struct CmParam *params, uint32_t paramCount,
    struct CmBlob *parcelBlob, struct CmParamSet **sendParamSet)
{
    int32_t ret = CM_SUCCESS;

    ret = CmParamsToParamSet(params, paramCount, sendParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmParamSetPack fail");
        return ret;
    }

    parcelBlob->size = (*sendParamSet)->paramSetSize;
    parcelBlob->data = (uint8_t *)*sendParamSet;
    return ret;
}

static int32_t GetCertListInitOutData(struct CmBlob *outListBlob)
{
    /* buff struct: certCount + MAX_CERT_COUNT * (subjectBlob + status + uriBlob + aliasBlob) */
    uint32_t buffSize = sizeof(uint32_t) + (sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME + sizeof(uint32_t) +
        sizeof(uint32_t) + MAX_LEN_URI + sizeof(uint32_t) +  MAX_LEN_CERT_ALIAS) * MAX_COUNT_CERTIFICATE;
    outListBlob->data = (uint8_t *)CmMalloc(buffSize);
    if (outListBlob->data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    outListBlob->size = buffSize;

    return CM_SUCCESS;
}

static int32_t GetCertificateList(enum CertManagerInterfaceCode type, const uint32_t store,
    struct CertList *certificateList)
{
    int32_t ret;
    struct CmBlob outBlob = { 0, NULL };
    struct CmBlob parcelBlob = { 0, NULL };
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = store },
    };

    do {
        ret = CmSendParcelInit(params, CM_ARRAY_SIZE(params), &parcelBlob, &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get system cert list sendParcel failed");
            break;
        }

        ret = GetCertListInitOutData(&outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("malloc cert list outdata failed");
            break;
        }

        ret = SendRequest(type, &parcelBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertificateList request fail");
            break;
        }

        ret = CmCertificateListUnpackFromService(&outBlob, certificateList);
    } while (0);
    CmFreeParamSet(&sendParamSet);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientGetCertList(const uint32_t store, struct CertList *certificateList)
{
    return GetCertificateList(CM_MSG_GET_CERTIFICATE_LIST, store, certificateList);
}

static int32_t GetCertInfoInitOutData(struct CmBlob *outInfoBlob)
{
    /* buff struct: certDataBlob + status + aliasBlob */
    uint32_t buffSize = sizeof(uint32_t) + MAX_LEN_CERTIFICATE + sizeof(uint32_t) +
        MAX_LEN_CERT_ALIAS + sizeof(uint32_t);

    outInfoBlob->data = (uint8_t *)CmMalloc(buffSize);
    if (outInfoBlob->data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    outInfoBlob->size = buffSize;

    return CM_SUCCESS;
}

static int32_t GetCertificateInfo(enum CertManagerInterfaceCode type, const struct CmBlob *certUri,
    const uint32_t store, struct CertInfo *certificateInfo)
{
    int32_t ret = CM_SUCCESS;
    struct CmBlob outBlob = { 0, NULL };
    struct CmBlob parcelBlob = { 0, NULL };
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *certUri },
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = store },
    };

    do {
        ret = CmSendParcelInit(params, CM_ARRAY_SIZE(params), &parcelBlob, &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get system cert info sendParcel failed");
            break;
        }

        ret = GetCertInfoInitOutData(&outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("malloc system cert info outdata failed");
            break;
        }

        ret = SendRequest(type, &parcelBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get system cert info send request fail");
            break;
        }

        ret = CmCertificateInfoUnpackFromService(&outBlob, certUri, certificateInfo);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertificateInfo unpack failed, ret = %d", ret);
            break;
        }
    } while (0);
    CmFreeParamSet(&sendParamSet);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientGetCertInfo(const struct CmBlob *certUri, const uint32_t store,
    struct CertInfo *certificateInfo)
{
    return GetCertificateInfo(CM_MSG_GET_CERTIFICATE_INFO, certUri, store, certificateInfo);
}

static int32_t SetCertificateStatus(enum CertManagerInterfaceCode type, const struct CmBlob *certUri,
    const uint32_t store, const uint32_t status)
{
    int32_t ret = CM_SUCCESS;
    struct CmBlob parcelBlob = { 0, NULL };
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *certUri },
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = store },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = status },
    };

    do {
        ret = CmSendParcelInit(params, CM_ARRAY_SIZE(params), &parcelBlob, &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("set system cert status sendParcel failed");
            break;
        }

        ret = SendRequest(type, &parcelBlob, NULL);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("set system cert status send request fail");
            break;
        }
    } while (0);
    CmFreeParamSet(&sendParamSet);
    return ret;
}

int32_t CmClientSetCertStatus(const struct CmBlob *certUri, const uint32_t store,
    const uint32_t status)
{
    return SetCertificateStatus(CM_MSG_SET_CERTIFICATE_STATUS, certUri, store, status);
}

static int32_t InstallAppCert(const struct CmBlob *appCert, const struct CmBlob *appCertPwd,
    const struct CmBlob *certAlias, const uint32_t store, struct CmBlob *keyUri)
{
    int32_t ret;
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER,
          .blob = *appCert },
        { .tag = CM_TAG_PARAM1_BUFFER,
          .blob = *appCertPwd },
        { .tag = CM_TAG_PARAM2_BUFFER,
          .blob = *certAlias },
        { .tag = CM_TAG_PARAM3_UINT32,
          .uint32Param = store },
    };
    do {
        ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmParamSetPack fail");
            break;
        }

        struct CmBlob parcelBlob = {
            .size = sendParamSet->paramSetSize,
            .data = (uint8_t *)sendParamSet
        };

        ret = SendRequest(CM_MSG_INSTALL_APP_CERTIFICATE, &parcelBlob, keyUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmParamSet send fail");
            break;
        }
    } while (0);

    CmFreeParamSet(&sendParamSet);
    return ret;
}

int32_t CmClientInstallAppCert(const struct CmBlob *appCert, const struct CmBlob *appCertPwd,
    const struct CmBlob *certAlias, const uint32_t store, struct CmBlob *keyUri)
{
    return InstallAppCert(appCert, appCertPwd, certAlias, store, keyUri);
}

static int32_t UninstallAppCert(enum CertManagerInterfaceCode type, const struct CmBlob *keyUri,
    const uint32_t store)
{
    int32_t ret;
    struct CmParamSet *sendParamSet = NULL;

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER,
          .blob = *keyUri },
        { .tag = CM_TAG_PARAM0_UINT32,
          .uint32Param = store },
    };

    do {
        ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallAppCert CmParamSetPack fail");
            break;
        }

        struct CmBlob parcelBlob = {
            .size = sendParamSet->paramSetSize,
            .data = (uint8_t *)sendParamSet
        };

        ret = SendRequest(type, &parcelBlob, NULL);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallAppCert CmParamSet send fail");
            break;
        }
    } while (0);

    CmFreeParamSet(&sendParamSet);
    return ret;
}

int32_t CmClientUninstallAppCert(const struct CmBlob *keyUri, const uint32_t store)
{
    return UninstallAppCert(CM_MSG_UNINSTALL_APP_CERTIFICATE, keyUri, store);
}

int32_t CmClientUninstallAllAppCert(enum CertManagerInterfaceCode type)
{
    int32_t ret;
    char tempBuff[] = "uninstall all app cert";
    struct CmBlob parcelBlob = {
        .size = sizeof(tempBuff),
        .data = (uint8_t *)tempBuff
    };

    ret = SendRequest(type, &parcelBlob, NULL);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("UninstallAllAppCert request fail");
    }

    return ret;
}

static int32_t GetAppCertListInitBlob(struct CmBlob *outBlob)
{
    uint32_t buffSize = sizeof(uint32_t) + (sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME + sizeof(uint32_t) +
        MAX_LEN_URI + sizeof(uint32_t) + MAX_LEN_CERT_ALIAS) * MAX_COUNT_CERTIFICATE;
    outBlob->data = (uint8_t *)CmMalloc(buffSize);
    if (outBlob->data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    outBlob->size = buffSize;

    return CM_SUCCESS;
}

static int32_t CmAppCertListGetCertCount(const struct CmBlob *outData,
    struct CredentialList *certificateList, uint32_t *offset)
{
    uint32_t credCount = 0;
    int32_t ret = GetUint32FromBuffer(&credCount, outData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("App cert get list faild ret:%d", ret);
        return ret;
    }

    if (credCount == 0) {
        CM_LOG_D("App cert list is null");
    }

    if (credCount > certificateList->credentialCount) {
        CM_LOG_E("Caller buff too small count:%u, count:%u", credCount,
            certificateList->credentialCount);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    certificateList->credentialCount = credCount;

    return CM_SUCCESS;
}

static int32_t CmAppCertListUnpackFromService(const struct CmBlob *outData,
    struct CredentialList *certificateList)
{
    uint32_t offset = 0;
    struct CmBlob blob = { 0, NULL };
    if ((outData == NULL) || (certificateList == NULL) ||
        (outData->data == NULL) || (certificateList->credentialAbstract == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = CmAppCertListGetCertCount(outData, certificateList, &offset);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    for (uint32_t i = 0; i < certificateList->credentialCount; i++) {
        ret = CmGetBlobFromBuffer(&blob, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get type blob failed");
            return ret;
        }
        if (memcpy_s(certificateList->credentialAbstract[i].type, MAX_LEN_SUBJECT_NAME, blob.data, blob.size) != EOK) {
            CM_LOG_E("copy type failed");
            return CMR_ERROR_INVALID_OPERATION;
        }

        ret = CmGetBlobFromBuffer(&blob, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get keyUri blob failed");
            return ret;
        }
        if (memcpy_s(certificateList->credentialAbstract[i].keyUri, MAX_LEN_URI, blob.data, blob.size) != EOK) {
            CM_LOG_E("copy keyUri failed");
            return CMR_ERROR_INVALID_OPERATION;
        }

        ret = CmGetBlobFromBuffer(&blob, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get alias blob failed");
            return ret;
        }
        if (memcpy_s(certificateList->credentialAbstract[i].alias, MAX_LEN_CERT_ALIAS, blob.data, blob.size) != EOK) {
            CM_LOG_E("copy alias failed");
            return CMR_ERROR_INVALID_OPERATION;
        }
    }
    return CM_SUCCESS;
}

static int32_t GetAppCertList(enum CertManagerInterfaceCode type, const uint32_t store,
    struct CredentialList *certificateList)
{
    int32_t ret;
    struct CmBlob outBlob = { 0, NULL };
    struct CmParamSet *sendParamSet = NULL;

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_UINT32,
            .uint32Param = store },
    };

    do {
        ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCertList CmParamSetPack fail");
            break;
        }

        struct CmBlob parcelBlob = {
            .size = sendParamSet->paramSetSize,
            .data = (uint8_t *)sendParamSet
        };

        ret = GetAppCertListInitBlob(&outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCertListInitBlob fail");
            break;
        }

        ret = SendRequest(type, &parcelBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCertList request fail");
            break;
        }

        ret = CmAppCertListUnpackFromService(&outBlob, certificateList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmAppCertListUnpackFromService fail");
            break;
        }
    } while (0);

    CmFreeParamSet(&sendParamSet);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientGetAppCertList(const uint32_t store, struct CredentialList *certificateList)
{
    return GetAppCertList(CM_MSG_GET_APP_CERTIFICATE_LIST, store, certificateList);
}

static int32_t GetAppCertInitBlob(struct CmBlob *outBlob)
{
    uint32_t buffSize = sizeof(uint32_t) + sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME +
        sizeof(uint32_t) + MAX_LEN_CERT_ALIAS + sizeof(uint32_t) + MAX_LEN_URI +
        sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + MAX_LEN_CERTIFICATE_CHAIN;

    outBlob->data = (uint8_t *)CmMalloc(buffSize);
    if (outBlob->data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    outBlob->size = buffSize;

    return CM_SUCCESS;
}

static int32_t CmGetAppCertFromBuffer(struct Credential *certificateInfo,
    const struct CmBlob *outData, uint32_t *offset)
{
    struct CmBlob blob;
    int32_t ret = CmGetBlobFromBuffer(&blob, outData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get type blob failed");
        return ret;
    }
    if (memcpy_s(certificateInfo->type, MAX_LEN_SUBJECT_NAME, blob.data, blob.size) != EOK) {
        CM_LOG_E("copy type failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

    ret = CmGetBlobFromBuffer(&blob, outData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get keyUri blob failed");
        return ret;
    }
    if (memcpy_s(certificateInfo->keyUri, MAX_LEN_URI, blob.data, blob.size) != EOK) {
        CM_LOG_E("copy keyUri failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

    ret = CmGetBlobFromBuffer(&blob, outData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get alias blob failed");
        return ret;
    }
    if (memcpy_s(certificateInfo->alias, MAX_LEN_CERT_ALIAS, blob.data, blob.size) != EOK) {
        CM_LOG_E("copy alias failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

    return ret;
}

static int32_t CmAppCertInfoUnpackFromService(const struct CmBlob *outData, struct Credential *certificateInfo)
{
    uint32_t offset = 0;
    struct CmBlob blob = { 0, NULL };

    if ((outData == NULL) || (certificateInfo == NULL) || (outData->data == NULL) ||
        (certificateInfo->credData.data == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = GetUint32FromBuffer(&certificateInfo->isExist, outData, &offset);
    if (ret != CM_SUCCESS || certificateInfo->isExist == 0) {
        CM_LOG_E("Get certificateInfo->isExist failed ret:%d, is exist:%u", ret, certificateInfo->isExist);
        return ret;
    }

    ret = CmGetAppCertFromBuffer(certificateInfo, outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get AppCert failed");
        return ret;
    }

    ret = GetUint32FromBuffer(&certificateInfo->certNum, outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get certificateInfo->certNum failed");
        return ret;
    }

    ret = GetUint32FromBuffer(&certificateInfo->keyNum, outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get certificateInfo->keyNum failed");
        return ret;
    }

    ret = CmGetBlobFromBuffer(&blob, outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get certificateInfo->credData failed");
        return ret;
    }

    if ((blob.size > certificateInfo->credData.size) || memcpy_s(certificateInfo->credData.data,
        certificateInfo->credData.size, blob.data, blob.size) != EOK) {
        CM_LOG_E("copy credData failed");
        return CMR_ERROR_INVALID_OPERATION;
    }
    certificateInfo->credData.size = blob.size;

    return CM_SUCCESS;
}

static int32_t GetAppCert(enum CertManagerInterfaceCode type, const struct CmBlob *certUri, const uint32_t store,
    struct Credential *certificate)
{
    int32_t ret;
    struct CmBlob outBlob = { 0, NULL };
    struct CmParamSet *sendParamSet = NULL;

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER,
          .blob = *certUri },
        { .tag = CM_TAG_PARAM0_UINT32,
          .uint32Param = store },
    };
    do {
        ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCert CmParamSetPack fail");
            break;
        }

        struct CmBlob parcelBlob = {
            .size = sendParamSet->paramSetSize,
            .data = (uint8_t *)sendParamSet
        };

        ret = GetAppCertInitBlob(&outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCertInitBlob fail");
            break;
        }

        ret = SendRequest(type, &parcelBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCert request fail");
            break;
        }

        ret = CmAppCertInfoUnpackFromService(&outBlob, certificate);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmAppCertInfoUnpackFromService fail");
        }
    } while (0);

    CmFreeParamSet(&sendParamSet);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientGetAppCert(const struct CmBlob *keyUri, const uint32_t store, struct Credential *certificate)
{
    return GetAppCert(CM_MSG_GET_APP_CERTIFICATE, keyUri, store, certificate);
}

static int32_t ClientSerializationAndSend(enum CertManagerInterfaceCode message, struct CmParam *params,
    uint32_t paramCount, struct CmBlob *outBlob)
{
    struct CmParamSet *sendParamSet = NULL;
    int32_t ret = CmParamsToParamSet(params, paramCount, &sendParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("pack params failed, ret = %d", ret);
        return ret;
    }

    struct CmBlob parcelBlob = { sendParamSet->paramSetSize, (uint8_t *)sendParamSet };
    ret = SendRequest(message, &parcelBlob, outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("send request failed, ret = %d", ret);
    }
    CmFreeParamSet(&sendParamSet);

    return ret;
}

static int32_t FormatAppUidList(const struct CmBlob *replyBlob, struct CmAppUidList *appUidList)
{
    if (replyBlob->size < sizeof(uint32_t)) { /* app uid count: 4 bytes */
        CM_LOG_E("invalid reply size[%u]", replyBlob->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    /* get app uid count */
    uint32_t count = 0;
    (void)memcpy_s(&count, sizeof(uint32_t), replyBlob->data, sizeof(uint32_t));
    uint32_t offset = sizeof(uint32_t);

    /* check reply total len */
    if ((count > MAX_OUT_BLOB_SIZE) || (replyBlob->size < (sizeof(uint32_t) + count * sizeof(uint32_t)))) {
        CM_LOG_E("invalid reply size[%u]", replyBlob->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (appUidList->appUidCount < count) {
        CM_LOG_E("input app list count[%u] too small", appUidList->appUidCount);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (count != 0) {
        if (appUidList->appUid == NULL) {
            CM_LOG_E("input appUid NULL");
            return CMR_ERROR_INVALID_ARGUMENT;
        }
        uint32_t uidListSize = count * sizeof(uint32_t);
        (void)memcpy_s(appUidList->appUid, uidListSize, replyBlob->data + offset, uidListSize);
    }
    appUidList->appUidCount = count;
    return CM_SUCCESS;
}

int32_t CmClientGrantAppCertificate(const struct CmBlob *keyUri, uint32_t appUid, struct CmBlob *authUri)
{
    if (CmCheckBlob(keyUri) != CM_SUCCESS || CmCheckBlob(authUri) != CM_SUCCESS) {
        CM_LOG_E("invalid keyUri or authUri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = appUid },
    };

    int32_t ret = ClientSerializationAndSend(CM_MSG_GRANT_APP_CERT, params, CM_ARRAY_SIZE(params), authUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("grant app serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientGetAuthorizedAppList(const struct CmBlob *keyUri, struct CmAppUidList *appUidList)
{
    if (CmCheckBlob(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid keyUri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (appUidList->appUidCount > MAX_OUT_BLOB_SIZE) { /* ensure not out of bounds */
        CM_LOG_E("invalid app uid list count[%u]", appUidList->appUidCount);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t outLen = sizeof(uint32_t) + appUidList->appUidCount * sizeof(uint32_t);
    uint8_t *outData = CmMalloc(outLen);
    if (outData == NULL) {
        CM_LOG_E("malloc out data failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(outData, outLen, 0, outLen);
    struct CmBlob outBlob = { outLen, outData };

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
    };

    int32_t ret = ClientSerializationAndSend(CM_MSG_GET_AUTHED_LIST, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get authed list serialization and send failed, ret = %d", ret);
        CmFree(outData);
        return ret;
    }

    ret = FormatAppUidList(&outBlob, appUidList);
    CmFree(outData);
    return ret;
}

int32_t CmClientIsAuthorizedApp(const struct CmBlob *authUri)
{
    if (CmCheckBlob(authUri) != CM_SUCCESS) {
        CM_LOG_E("invalid authUri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *authUri },
    };

    struct CmBlob outBlob = { 0, NULL };
    int32_t ret = ClientSerializationAndSend(CM_MSG_CHECK_IS_AUTHED_APP, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("check is authed serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientRemoveGrantedApp(const struct CmBlob *keyUri, uint32_t appUid)
{
    if (CmCheckBlob(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid keyUri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = appUid },
    };

    struct CmBlob outBlob = { 0, NULL };
    int32_t ret = ClientSerializationAndSend(CM_MSG_REMOVE_GRANT_APP, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("remove granted app serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientInit(const struct CmBlob *authUri, const struct CmSignatureSpec *spec, struct CmBlob *handle)
{
    if (CmCheckBlob(authUri) != CM_SUCCESS || CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid handle or inData");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmBlob signSpec = { sizeof(struct CmSignatureSpec), (uint8_t *)spec };
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *authUri },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = signSpec },
    };

    int32_t ret = ClientSerializationAndSend(CM_MSG_INIT, params, CM_ARRAY_SIZE(params), handle);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("update serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientUpdate(const struct CmBlob *handle, const struct CmBlob *inData)
{
    if (CmCheckBlob(handle) != CM_SUCCESS || CmCheckBlob(inData) != CM_SUCCESS) {
        CM_LOG_E("invalid handle or inData");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *handle },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = *inData },
    };

    struct CmBlob outBlob = { 0, NULL };
    int32_t ret = ClientSerializationAndSend(CM_MSG_UPDATE, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("update serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientFinish(const struct CmBlob *handle, const struct CmBlob *inData, struct CmBlob *outData)
{
    if (CmCheckBlob(handle) != CM_SUCCESS) { /* finish: inData and outData can be {0, NULL} */
        CM_LOG_E("invalid handle");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *handle },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = *inData },
    };

    int32_t ret = ClientSerializationAndSend(CM_MSG_FINISH, params, CM_ARRAY_SIZE(params), outData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("finish serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientAbort(const struct CmBlob *handle)
{
    if (CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid handle");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *handle },
    };

    struct CmBlob outBlob = { 0, NULL };
    int32_t ret = ClientSerializationAndSend(CM_MSG_ABORT, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("abort serialization and send failed, ret = %d", ret);
    }
    return ret;
}

static int32_t GetUserCertList(enum CertManagerInterfaceCode type, const uint32_t store,
    struct CertList *certificateList)
{
    int32_t ret = CM_SUCCESS;
    struct CmBlob outBlob = {0, NULL};
    struct CmBlob parcelBlob = {0, NULL};
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = store },
    };

    do {
        ret = CmSendParcelInit(params, CM_ARRAY_SIZE(params), &parcelBlob, &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get cert list sendParcel failed");
            break;
        }

        ret = GetCertListInitOutData(&outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("malloc getcertlist outdata failed");
            break;
        }

        ret = SendRequest(type, &parcelBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertList request failed, ret: %d", ret);
            break;
        }

        ret = CmCertificateListUnpackFromService(&outBlob, certificateList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("getcertlist unpack from service failed");
            break;
        }
    } while (0);

    CmFreeParamSet(&sendParamSet);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientGetUserCertList(const uint32_t store, struct CertList *certificateList)
{
    return GetUserCertList(CM_MSG_GET_USER_CERTIFICATE_LIST, store, certificateList);
}

static int32_t GetUserCertInfo(enum CertManagerInterfaceCode type, const struct CmBlob *certUri,
    const uint32_t store, struct CertInfo *userCertInfo)
{
    int32_t ret = CM_SUCCESS;
    struct CmBlob outBlob = {0, NULL};
    struct CmBlob parcelBlob = {0, NULL};
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *certUri },
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = store },
    };

    do {
        ret = CmSendParcelInit(params, CM_ARRAY_SIZE(params), &parcelBlob, &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get cert info sendParcel failed");
            break;
        }

        ret = GetCertInfoInitOutData(&outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("malloc getcertinfo outdata failed");
            break;
        }

        ret = SendRequest(type, &parcelBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertInfo request failed, ret: %d", ret);
            break;
        }

        ret = CmCertificateInfoUnpackFromService(&outBlob, certUri, userCertInfo);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("getcertinfo unpack from service failed");
            break;
        }
    } while (0);
    CmFreeParamSet(&sendParamSet);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientGetUserCertInfo(const struct CmBlob *certUri, const uint32_t store,
    struct CertInfo *certificateInfo)
{
    return GetUserCertInfo(CM_MSG_GET_USER_CERTIFICATE_INFO, certUri, store, certificateInfo);
}

static int32_t SetUserCertStatus(enum CertManagerInterfaceCode type, const struct CmBlob *certUri,
    const uint32_t store, const uint32_t status)
{
    int32_t ret = CM_SUCCESS;
    struct CmBlob parcelBlob = {0, NULL};
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *certUri },
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = store },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = status },
    };

    do {
        ret = CmSendParcelInit(params, CM_ARRAY_SIZE(params), &parcelBlob, &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("set cert status sendParcel failed");
            break;
        }

        ret = SendRequest(type, &parcelBlob, NULL);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("SetCertStatus request failed, ret: %d", ret);
            break;
        }
    } while (0);
    CmFreeParamSet(&sendParamSet);
    return ret;
}

int32_t CmClientSetUserCertStatus(const struct CmBlob *certUri, const uint32_t store,
    const uint32_t status)
{
    return SetUserCertStatus(CM_MSG_SET_USER_CERTIFICATE_STATUS, certUri, store, status);
}

static int32_t InstallUserCert(enum CertManagerInterfaceCode type, const struct CmBlob *userCert,
    const struct CmBlob *certAlias, struct CmBlob *certUri)
{
    int32_t ret = CM_SUCCESS;
    struct CmBlob parcelBlob = {0, NULL};
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *userCert },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = *certAlias },
    };

    do {
        ret = CmSendParcelInit(params, CM_ARRAY_SIZE(params), &parcelBlob, &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("install user cert sendParcel failed");
            break;
        }

        ret = SendRequest(type, &parcelBlob, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("InstallUserCert request failed, ret: %d", ret);
            break;
        }
    } while (0);
    CmFreeParamSet(&sendParamSet);
    return ret;
}

int32_t CmClientInstallUserTrustedCert(const struct CmBlob *userCert, const struct CmBlob *certAlias,
    struct CmBlob *certUri)
{
    return InstallUserCert(CM_MSG_INSTALL_USER_CERTIFICATE, userCert, certAlias, certUri);
}

static int32_t UninstallUserCert(enum CertManagerInterfaceCode type, const struct CmBlob *certUri)
{
    int32_t ret = CM_SUCCESS;
    struct CmBlob parcelBlob = {0, NULL};
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *certUri },
    };

    do {
        ret = CmSendParcelInit(params, CM_ARRAY_SIZE(params), &parcelBlob, &sendParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("uninstall user cert sendParcel failed");
            break;
        }

        ret = SendRequest(type, &parcelBlob, NULL);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallUserCert request failed, ret: %d", ret);
            break;
        }
    } while (0);
    CmFreeParamSet(&sendParamSet);
    return ret;
}

int32_t CmClientUninstallUserTrustedCert(const struct CmBlob *certUri)
{
    return UninstallUserCert(CM_MSG_UNINSTALL_USER_CERTIFICATE, certUri);
}

static int32_t UninstallAllUserCert(enum CertManagerInterfaceCode type)
{
    int ret = CM_SUCCESS;
    uint8_t temp[4] = {0}; /* only use to construct parcelBlob */
    struct CmBlob parcelBlob = { sizeof(temp), temp };

    ret = SendRequest(type, &parcelBlob, NULL);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("UninstallAllUserCert request failed, ret: %d", ret);
    }
    return ret;
}

int32_t CmClientUninstallAllUserTrustedCert(void)
{
    return UninstallAllUserCert(CM_MSG_UNINSTALL_ALL_USER_CERTIFICATE);
}

