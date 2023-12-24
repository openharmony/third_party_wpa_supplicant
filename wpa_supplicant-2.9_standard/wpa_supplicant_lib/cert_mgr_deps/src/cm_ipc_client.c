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
#include "cm_param.h"
#include "cm_request.h"

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

