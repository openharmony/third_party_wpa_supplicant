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

#ifndef CM_REQUEST_H
#define CM_REQUEST_H

#include "cert_manager_service_ipc_interface_code.h"
#include "cm_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SendRequest - Send the request message to target module by function call or ipc or other ways.
 * @type:        the request message type.
 * @inBlob:      the input serialized data blob.
 * @outBlob:     the output serialized data blob, can be null.
 */

int32_t SendRequest(enum CertManagerInterfaceCode type, const struct CmBlob *inBlob,
    struct CmBlob *outBlob);

#ifdef __cplusplus
}
#endif

#endif /* CM_REQUEST_H */
