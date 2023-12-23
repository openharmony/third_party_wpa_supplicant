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

#ifndef CM_IPC_MSG_CODE_H
#define CM_IPC_MSG_CODE_H

#ifdef __cplusplus
extern "C" {
#endif

/* SAID: 3512 */
enum CertManagerInterfaceCode {
    CM_MSG_BASE = 0,

    CM_MSG_GEN_KEY = CM_MSG_BASE,
    CM_MSG_GET_CERTIFICATE_LIST,
    CM_MSG_GET_CERTIFICATE_INFO,
    CM_MSG_SET_CERTIFICATE_STATUS,
    CM_MSG_INSTALL_APP_CERTIFICATE,
    CM_MSG_UNINSTALL_APP_CERTIFICATE,
    CM_MSG_UNINSTALL_ALL_APP_CERTIFICATE,
    CM_MSG_GET_APP_CERTIFICATE_LIST,
    CM_MSG_GET_APP_CERTIFICATE,
    CM_MSG_GRANT_APP_CERT,
    CM_MSG_GET_AUTHED_LIST,
    CM_MSG_CHECK_IS_AUTHED_APP,
    CM_MSG_REMOVE_GRANT_APP,
    CM_MSG_INIT,
    CM_MSG_UPDATE,
    CM_MSG_FINISH,
    CM_MSG_ABORT,
    CM_MSG_GET_USER_CERTIFICATE_LIST,
    CM_MSG_GET_USER_CERTIFICATE_INFO,
    CM_MSG_SET_USER_CERTIFICATE_STATUS,
    CM_MSG_INSTALL_USER_CERTIFICATE,
    CM_MSG_UNINSTALL_USER_CERTIFICATE,
    CM_MSG_UNINSTALL_ALL_USER_CERTIFICATE,

    /* new cmd type must be added before CM_MSG_MAX */
    CM_MSG_MAX,
};

#ifdef __cplusplus
}
#endif
#endif
