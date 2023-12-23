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

#ifndef CERT_MANGAGER_API_H
#define CERT_MANGAGER_API_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

CM_API_EXPORT int32_t CmGetAppCert(const struct CmBlob *keyUri, const uint32_t store, struct Credential *certificate);

CM_API_EXPORT int32_t CmInit(const struct CmBlob *authUri, const struct CmSignatureSpec *spec, struct CmBlob *handle);

CM_API_EXPORT int32_t CmUpdate(const struct CmBlob *handle, const struct CmBlob *inData);

CM_API_EXPORT int32_t CmFinish(const struct CmBlob *handle, const struct CmBlob *inData, struct CmBlob *outData);

CM_API_EXPORT int32_t CmAbort(const struct CmBlob *handle);

#ifdef __cplusplus
}
#endif

#endif /* CERT_MANGAGER_API_H */