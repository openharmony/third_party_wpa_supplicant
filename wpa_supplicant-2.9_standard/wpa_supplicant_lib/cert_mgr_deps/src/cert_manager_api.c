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

CM_API_EXPORT int32_t CmGetCertList(uint32_t store, struct CertList *certificateList)
{
    CM_LOG_D("enter get certificate list");
    if (certificateList == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_NULL_POINTER;
    }

    if ((certificateList->certAbstract == NULL) || (store != CM_SYSTEM_TRUSTED_STORE)) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetCertList(store, certificateList);
    CM_LOG_D("leave get certificate list, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetCertInfo(const struct CmBlob *certUri, uint32_t store,
    struct CertInfo *certificateInfo)
{
    CM_LOG_D("enter get certificate info");
    if ((certUri == NULL) || (certificateInfo == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_NULL_POINTER;
    }

    if ((certificateInfo->certInfo.data == NULL) || (certificateInfo->certInfo.size == 0) ||
        (store != CM_SYSTEM_TRUSTED_STORE)) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetCertInfo(certUri, store, certificateInfo);
    CM_LOG_D("leave get certificate info, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmSetCertStatus(const struct CmBlob *certUri, const uint32_t store,
    const bool status)
{
    CM_LOG_D("enter set certificate status");
    if (certUri == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_NULL_POINTER;
    }

    if (store != CM_SYSTEM_TRUSTED_STORE) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t uStatus = status ? 0 : 1; // 0 indicates the certificate enabled status

    int32_t ret = CmClientSetCertStatus(certUri, store, uStatus);
    CM_LOG_D("leave set certificate status, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmInstallAppCert(const struct CmBlob *appCert, const struct CmBlob *appCertPwd,
    const struct CmBlob *certAlias, const uint32_t store, struct CmBlob *keyUri)
{
    CM_LOG_D("enter install app certificate");
    if (appCert == NULL || appCertPwd == NULL || certAlias == NULL ||
        keyUri == NULL || keyUri->data == NULL || (store != CM_CREDENTIAL_STORE &&
        store != CM_PRI_CREDENTIAL_STORE)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientInstallAppCert(appCert, appCertPwd, certAlias, store, keyUri);
    CM_LOG_D("leave install app certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUninstallAppCert(const struct CmBlob *keyUri, const uint32_t store)
{
    CM_LOG_D("enter uninstall app certificate");
    if (keyUri == NULL || (store != CM_CREDENTIAL_STORE &&
        store != CM_PRI_CREDENTIAL_STORE)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientUninstallAppCert(keyUri, store);
    CM_LOG_D("leave uninstall app certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUninstallAllAppCert(void)
{
    CM_LOG_D("enter uninstall all app certificate");

    int32_t ret = CmClientUninstallAllAppCert(CM_MSG_UNINSTALL_ALL_APP_CERTIFICATE);

    CM_LOG_D("leave uninstall all app certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetAppCertList(const uint32_t store, struct CredentialList *certificateList)
{
    CM_LOG_D("enter get app certificatelist");
    if (certificateList == NULL || (store != CM_CREDENTIAL_STORE &&
        store != CM_PRI_CREDENTIAL_STORE)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetAppCertList(store, certificateList);
    CM_LOG_D("leave get app certificatelist, result = %d", ret);
    return ret;
}

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

CM_API_EXPORT int32_t CmGrantAppCertificate(const struct CmBlob *keyUri, uint32_t appUid, struct CmBlob *authUri)
{
    CM_LOG_D("enter grant app certificate");
    if ((keyUri == NULL) || (authUri == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGrantAppCertificate(keyUri, appUid, authUri);
    CM_LOG_D("leave grant app certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetAuthorizedAppList(const struct CmBlob *keyUri, struct CmAppUidList *appUidList)
{
    CM_LOG_D("enter get authorized app list");
    if ((keyUri == NULL) || (appUidList == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetAuthorizedAppList(keyUri, appUidList);
    CM_LOG_D("leave get authorized app list, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmIsAuthorizedApp(const struct CmBlob *authUri)
{
    CM_LOG_D("enter check is app authed");
    if (authUri == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientIsAuthorizedApp(authUri);
    CM_LOG_D("leave check is app authed, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmRemoveGrantedApp(const struct CmBlob *keyUri, uint32_t appUid)
{
    CM_LOG_D("enter remove granted app");
    if (keyUri == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientRemoveGrantedApp(keyUri, appUid);
    CM_LOG_D("leave remove granted app, result = %d", ret);
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

CM_API_EXPORT int32_t CmGetUserCertList(uint32_t store, struct CertList *certificateList)
{
    CM_LOG_D("enter get cert list");
    if (certificateList == NULL) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = CmClientGetUserCertList(store, certificateList);
    CM_LOG_D("leave get cert list, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetUserCertInfo(const struct CmBlob *certUri, uint32_t store, struct CertInfo *certificateInfo)
{
    CM_LOG_D("enter get cert info");
    if ((certUri == NULL) || (certificateInfo == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = CmClientGetUserCertInfo(certUri, store, certificateInfo);
    CM_LOG_D("leave get cert info, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmSetUserCertStatus(const struct CmBlob *certUri, uint32_t store, const bool status)
{
    CM_LOG_D("enter set cert status");
    if (certUri == NULL) {
        return CMR_ERROR_NULL_POINTER;
    }

    uint32_t uStatus = status ? 0 : 1; // 0 indicates the certificate enabled status

    int32_t ret = CmClientSetUserCertStatus(certUri, store, uStatus);
    CM_LOG_D("leave set cert status, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmInstallUserTrustedCert(const struct CmBlob *userCert, const struct CmBlob *certAlias,
    struct CmBlob *certUri)
{
    CM_LOG_D("enter install user trusted cert");
    if ((userCert == NULL) || (certAlias == NULL) || (certUri == NULL)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientInstallUserTrustedCert(userCert, certAlias, certUri);
    CM_LOG_D("leave install user trusted cert, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUninstallUserTrustedCert(const struct CmBlob *certUri)
{
    CM_LOG_D("enter uninstall user trusted cert");
    if (certUri == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientUninstallUserTrustedCert(certUri);
    CM_LOG_D("leave uninstall user trusted cert, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUninstallAllUserTrustedCert(void)
{
    CM_LOG_D("enter uninstall all user trusted cert");

    int32_t ret = CmClientUninstallAllUserTrustedCert();
    CM_LOG_D("leave uninstall all user trusted cert, result = %d", ret);
    return ret;
}

