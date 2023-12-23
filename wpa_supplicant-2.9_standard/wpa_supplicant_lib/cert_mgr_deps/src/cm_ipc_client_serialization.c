/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "cm_ipc_client_serialization.h"

#include "cm_log.h"
#include "cm_mem.h"

#include "cm_param.h"
#include "cm_x509.h"

int32_t GetUint32FromBuffer(uint32_t *value, const struct CmBlob *srcBlob, uint32_t *srcOffset)
{
    if ((*srcOffset > srcBlob->size) || (srcBlob->size - *srcOffset < sizeof(uint32_t))) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (memcpy_s(value, sizeof(uint32_t), srcBlob->data + *srcOffset, sizeof(uint32_t)) != EOK) {
        return CMR_ERROR_INVALID_OPERATION;
    }

    *srcOffset += sizeof(uint32_t);
    return CM_SUCCESS;
}

int32_t CmGetBlobFromBuffer(struct CmBlob *blob, const struct CmBlob *srcBlob, uint32_t *srcOffset)
{
    if ((*srcOffset > srcBlob->size) || ((srcBlob->size - *srcOffset) < sizeof(uint32_t))) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    uint32_t size = *((uint32_t *)(srcBlob->data + *srcOffset));
    if (ALIGN_SIZE(size) > srcBlob->size - *srcOffset - sizeof(uint32_t)) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    blob->size = size;
    *srcOffset += sizeof(blob->size);
    blob->data = (uint8_t *)(srcBlob->data + *srcOffset);
    *srcOffset += ALIGN_SIZE(blob->size);
    return CM_SUCCESS;
}

static int32_t CmCertListGetCertCount(const struct CmBlob *outData, struct CertList *certificateList,
    uint32_t *offset)
{
    uint32_t certsCount = 0;
    int32_t ret = GetUint32FromBuffer(&certsCount, outData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get certificateList->certsCount failed");
        return ret;
    }

    if (certsCount > certificateList->certsCount) {
        CM_LOG_E("Caller Buffer too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    certificateList->certsCount = certsCount;

    return CM_SUCCESS;
}

int32_t CmCertificateListUnpackFromService(const struct CmBlob *outData, struct CertList *certificateList)
{
    if (CmCheckBlob(outData) != CM_SUCCESS || (certificateList == NULL) || (certificateList->certAbstract == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    uint32_t offset = 0;
    int32_t ret = CmCertListGetCertCount(outData, certificateList, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get Cert list count failed");
        return ret;
    }

    for (uint32_t i = 0; i < certificateList->certsCount; i++) {
        struct CmBlob blob = { 0, NULL };
        ret = CmGetBlobFromBuffer(&blob, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get subjectNameBlob FromBuffer failed");
            return ret;
        }
        if (memcpy_s(certificateList->certAbstract[i].subjectName, MAX_LEN_SUBJECT_NAME, blob.data, blob.size) != EOK) {
            CM_LOG_E("copy subjectName failed");
            return CMR_ERROR_INVALID_OPERATION;
        }

        uint32_t status = 0;
        ret = GetUint32FromBuffer(&status, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get status failed");
            return ret;
        }
        certificateList->certAbstract[i].status = (status >= 1) ? false : true;

        ret = CmGetBlobFromBuffer(&blob, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get uri failed");
            return ret;
        }
        if (memcpy_s(certificateList->certAbstract[i].uri, MAX_LEN_URI, blob.data, blob.size) != EOK) {
            CM_LOG_E("copy uri failed");
            return CMR_ERROR_INVALID_OPERATION;
        }

        ret = CmGetBlobFromBuffer(&blob, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get certAlias failed");
            return ret;
        }
        if (memcpy_s(certificateList->certAbstract[i].certAlias, MAX_LEN_CERT_ALIAS, blob.data, blob.size) != EOK) {
            CM_LOG_E("copy certAlias failed");
            return CMR_ERROR_INVALID_OPERATION;
        }
    }
    return CM_SUCCESS;
}

static int32_t GetInfoFromX509Cert(X509 *x509cert, struct CertInfo *cInfo)
{
#if 0
    int32_t subjectNameLen = GetX509SubjectNameLongFormat(x509cert, cInfo->subjectName, MAX_LEN_SUBJECT_NAME);
    if (subjectNameLen <= 0) {
        CM_LOG_E("get cert subjectName failed");
        return CM_FAILURE;
    }

    int32_t issuerNameLen = GetX509IssueNameLongFormat(x509cert, cInfo->issuerName, MAX_LEN_ISSUER_NAME);
    if (issuerNameLen <= 0) {
        CM_LOG_E("get cert issuerName failed");
        return CM_FAILURE;
    }

    int32_t serialLen = GetX509SerialNumber(x509cert, cInfo->serial, MAX_LEN_SERIAL);
    if (serialLen <= 0) {
        CM_LOG_E("get cert serial failed");
        return CM_FAILURE;
    }

    int32_t notBeforeLen = GetX509NotBefore(x509cert, cInfo->notBefore, MAX_LEN_NOT_BEFORE);
    if (notBeforeLen <= 0) {
        CM_LOG_E("get cert notBefore failed");
        return CM_FAILURE;
    }

    int32_t notAfterLen = GetX509NotAfter(x509cert, cInfo->notAfter, MAX_LEN_NOT_AFTER);
    if (notAfterLen <= 0) {
        CM_LOG_E("get cert notAfter failed");
        return CM_FAILURE;
    }

    int32_t fingerprintLen = GetX509Fingerprint(x509cert, cInfo->fingerprintSha256, MAX_LEN_FINGER_PRINT_SHA256);
    if (fingerprintLen <= 0) {
        CM_LOG_E("get cert fingerprintSha256 failed");
        return CM_FAILURE;
    }
#endif
    return CM_SUCCESS;
}

static int32_t GetInfoFromCertData(struct CertInfo *cInfo)
{
    X509 *cert = InitCertContext(cInfo->certInfo.data, cInfo->certInfo.size);
    if (cert == NULL) {
        CM_LOG_E("Parse X509 cert fail");
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }

    int32_t ret = GetInfoFromX509Cert(cert, cInfo);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("failed get cert info from x509 cert");
        FreeCertContext(cert);
        return ret;
    }

    FreeCertContext(cert);
    return CM_SUCCESS;
}

int32_t CmCertificateInfoUnpackFromService(const struct CmBlob *outData, const struct CmBlob *certUri,
    struct CertInfo *cInfo)
{
    if (CmCheckBlob(&(cInfo->certInfo))) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmBlob bufBlob = { 0, NULL };
    uint32_t offset = 0;
    int32_t ret = CmGetBlobFromBuffer(&bufBlob, outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get cert data faild");
        return ret;
    }
    if (memcpy_s(cInfo->certInfo.data, cInfo->certInfo.size, bufBlob.data, bufBlob.size) != EOK) {
        CM_LOG_E("copy cert data failed");
        return CMR_ERROR_INVALID_OPERATION;
    }
    cInfo->certInfo.size = bufBlob.size;

    ret = GetInfoFromCertData(cInfo);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    uint32_t status = 0;
    ret = GetUint32FromBuffer(&(status), outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy status failed");
        return ret;
    }
    cInfo->status = (status >= 1) ? false : true;

    ret = CmGetBlobFromBuffer(&bufBlob, outData, &offset);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    (void)memset_s(cInfo->certAlias, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);
    if (memcpy_s(cInfo->certAlias, MAX_LEN_CERT_ALIAS, bufBlob.data, bufBlob.size) != EOK) {
        CM_LOG_E("copy alias failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

    (void)memset_s(cInfo->uri, MAX_LEN_URI, 0, MAX_LEN_URI); /* uri */
    if (memcpy_s(cInfo->uri, MAX_LEN_URI, certUri->data, certUri->size) != EOK) {
        CM_LOG_E("copy uri failed");
        return CMR_ERROR_INVALID_OPERATION;
    }
    return CM_SUCCESS;
}

int32_t CmParamsToParamSet(struct CmParam *params, uint32_t cnt, struct CmParamSet **outParamSet)
{
    struct CmParamSet *newParamSet = NULL;

    int32_t ret = CmInitParamSet(&newParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("init param set failed");
        return ret;
    }

    do {
        uint8_t tmpData = 0;
        struct CmBlob tmpBlob = { sizeof(tmpData), &tmpData };
        for (uint32_t i = 0; i < cnt; ++i) {
            if ((GetTagType(params[i].tag) == CM_TAG_TYPE_BYTES) &&
                (params[i].blob.size == 0 || params[i].blob.data == NULL)) {
                params[i].tag += CM_PARAM_BUFFER_NULL_INTERVAL;
                params[i].blob = tmpBlob;
            }
        }

        ret = CmAddParams(newParamSet, params, cnt);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("add in params failed");
            break;
        }

        ret = CmBuildParamSet(&newParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("build paramset failed!");
            break;
        }
    } while (0);
    if (ret != CM_SUCCESS) {
        CmFreeParamSet(&newParamSet);
        return ret;
    }

    *outParamSet = newParamSet;

    return ret;
}
