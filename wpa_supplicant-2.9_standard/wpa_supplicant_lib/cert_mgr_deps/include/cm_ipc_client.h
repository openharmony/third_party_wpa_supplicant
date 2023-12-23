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

#ifndef CM_CLIENT_IPC_H
#define CM_CLIENT_IPC_H

#include "cm_request.h"
#include "cm_type_inner.h"

#ifdef __cplusplus
extern "C"
{
#endif

int32_t CmClientGetCertList(const uint32_t store, struct CertList *certificateList);

int32_t CmClientGetCertInfo(const struct CmBlob *certUri, const uint32_t store,
    struct CertInfo *certificateInfo);

int32_t CmClientSetCertStatus(const struct CmBlob *certUri, const uint32_t store,
    const uint32_t status);

int32_t CmClientInstallAppCert(const struct CmBlob *appCert, const struct CmBlob *appCertPwd,
    const struct CmBlob *certAlias, const uint32_t store, struct CmBlob *keyUri);

int32_t CmClientUninstallAppCert(const struct CmBlob *keyUri, const uint32_t store);

int32_t CmClientUninstallAllAppCert(enum CertManagerInterfaceCode type);

int32_t CmClientGetAppCertList(const uint32_t store, struct CredentialList *certificateList);

int32_t CmClientGetAppCert(const struct CmBlob *keyUri, const uint32_t store, struct Credential *certificate);

int32_t CmClientGrantAppCertificate(const struct CmBlob *keyUri, uint32_t appUid, struct CmBlob *authUri);

int32_t CmClientGetAuthorizedAppList(const struct CmBlob *keyUri, struct CmAppUidList *appUidList);

int32_t CmClientIsAuthorizedApp(const struct CmBlob *authUri);

int32_t CmClientRemoveGrantedApp(const struct CmBlob *keyUri, uint32_t appUid);

int32_t CmClientInit(const struct CmBlob *authUri, const struct CmSignatureSpec *spec, struct CmBlob *handle);

int32_t CmClientUpdate(const struct CmBlob *handle, const struct CmBlob *inData);

int32_t CmClientFinish(const struct CmBlob *handle, const struct CmBlob *inData, struct CmBlob *outData);

int32_t CmClientAbort(const struct CmBlob *handle);

int32_t CmClientGetUserCertList(const uint32_t store, struct CertList *certificateList);

int32_t CmClientGetUserCertInfo(const struct CmBlob *certUri, const uint32_t store,
    struct CertInfo *certificateInfo);

int32_t CmClientSetUserCertStatus(const struct CmBlob *certUri, const uint32_t store,
    const uint32_t status);

int32_t CmClientInstallUserTrustedCert(const struct CmBlob *userCert, const struct CmBlob *certAlias,
    struct CmBlob *certUri);

int32_t CmClientUninstallUserTrustedCert(const struct CmBlob *certUri);

int32_t CmClientUninstallAllUserTrustedCert(void);

#ifdef __cplusplus
}
#endif

#endif /* CM_CLIENT_IPC_H */
