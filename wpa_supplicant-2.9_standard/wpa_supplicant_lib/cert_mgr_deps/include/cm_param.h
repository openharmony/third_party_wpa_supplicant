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

#ifndef CM_PARAM_H
#define CM_PARAM_H

#include "cm_type.h"

#define CM_PARAM_SET_MAX_SIZE (4 * 1024 * 1024)
#define CM_DEFAULT_PARAM_SET_SIZE 512
#define CM_DEFAULT_PARAM_CNT ((uint32_t)((CM_DEFAULT_PARAM_SET_SIZE - sizeof(struct CmParamSet)) / \
    sizeof(struct CmParam)))
#define CM_TAG_TYPE_MASK (0xF << 28)

#ifdef __cplusplus
extern "C" {
#endif

enum CmTagType GetTagType(enum CmTag tag);

int32_t CmInitParamSet(struct CmParamSet **paramSet);

int32_t CmBuildParamSet(struct CmParamSet **paramSet);

void CmFreeParamSet(struct CmParamSet **paramSet);

int32_t CmGetParam(const struct CmParamSet *paramSet, uint32_t tag, struct CmParam **param);

int32_t CmGetParamSet(const struct CmParamSet *inParamSet, uint32_t inParamSetSize, struct CmParamSet **outParamSet);

int32_t CmAddParams(struct CmParamSet *paramSet, const struct CmParam *params, uint32_t paramCnt);

#ifdef __cplusplus
}
#endif
#endif
