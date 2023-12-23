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

#include "cert_manager_api.h"

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_ipc_client.h"
#include "cm_type.h"

CM_API_EXPORT int32_t CmGetAppCert(const struct CmBlob *keyUri, const uint32_t store,
    struct Credential *certificate)
{
    CM_LOG_D("enter get app certificate");
    if (keyUri == NULL || certificate == NULL || (store != CM_CREDENTIAL_STORE &&
        store != CM_PRI_CREDENTIAL_STORE)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetAppCert(keyUri, store, certificate);
    CM_LOG_D("leave get app certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmInit(const struct CmBlob *authUri, const struct CmSignatureSpec *spec, struct CmBlob *handle)
{
    CM_LOG_D("enter cert manager init");
    if ((authUri == NULL) || (spec == NULL) || (handle == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientInit(authUri, spec, handle);
    CM_LOG_D("leave cert manager init, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUpdate(const struct CmBlob *handle, const struct CmBlob *inData)
{
    CM_LOG_D("enter cert manager update");
    if ((handle == NULL) || (inData == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientUpdate(handle, inData);
    CM_LOG_D("leave cert manager update, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmFinish(const struct CmBlob *handle, const struct CmBlob *inData, struct CmBlob *outData)
{
    CM_LOG_D("enter cert manager finish");
    if ((handle == NULL) || (inData == NULL) || (outData == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientFinish(handle, inData, outData);
    CM_LOG_D("leave cert manager finish, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmAbort(const struct CmBlob *handle)
{
    CM_LOG_D("enter cert manager abort");
    if (handle == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientAbort(handle);
    CM_LOG_D("leave cert manager abort, result = %d", ret);
    return ret;
}