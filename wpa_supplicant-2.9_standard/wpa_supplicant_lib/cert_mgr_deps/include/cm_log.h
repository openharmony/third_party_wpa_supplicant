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

#ifndef CM_LOG_H
#define CM_LOG_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _CM_LOG_ENABLE_
#undef LOG_TAG
#define LOG_TAG "CertManager"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002F09 /* CertManager's domain id */
#endif

enum CmLogLevel {
    CM_LOG_LEVEL_I,
    CM_LOG_LEVEL_E,
    CM_LOG_LEVEL_W,
    CM_LOG_LEVEL_D,
};

#ifdef _CM_LOG_ENABLE_
void CmLog(uint32_t logLevel, const char *funcName, uint32_t lineNo, const char *format, ...);

#define CM_LOG_I(...) CmLog(CM_LOG_LEVEL_I, __func__, __LINE__, __VA_ARGS__)
#define CM_LOG_W(...) CmLog(CM_LOG_LEVEL_W, __func__, __LINE__, __VA_ARGS__)
#define CM_LOG_E(...) CmLog(CM_LOG_LEVEL_E, __func__, __LINE__, __VA_ARGS__)
#define CM_LOG_D(...) CmLog(CM_LOG_LEVEL_D, __func__, __LINE__, __VA_ARGS__)
#else
#define CM_LOG_I(...)
#define CM_LOG_W(...)
#define CM_LOG_E(...)
#define CM_LOG_D(...)
#endif

#ifdef __cplusplus
}
#endif

#endif /* CM_LOG_H */
