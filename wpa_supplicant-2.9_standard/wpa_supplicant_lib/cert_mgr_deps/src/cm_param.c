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

#include "cm_param.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type_inner.h"

enum CmTagType GetTagType(enum CmTag tag)
{
    return (enum CmTagType)((uint32_t)tag & CM_TAG_TYPE_MASK);
}

int32_t CmInitParamSet(struct CmParamSet **paramSet)
{
    if (paramSet == NULL) {
        CM_LOG_E("invalid init params!");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    *paramSet = (struct CmParamSet *)CmMalloc(CM_DEFAULT_PARAM_SET_SIZE);
    if (*paramSet == NULL) {
        CM_LOG_E("malloc init param set failed!");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (*paramSet)->paramsCnt = 0;
    (*paramSet)->paramSetSize = sizeof(struct CmParamSet);
    return CM_SUCCESS;
}

static int32_t CmCheckParamSet(const struct CmParamSet *paramSet, uint32_t size)
{
    if (paramSet == NULL) {
        return CMR_ERROR_NULL_POINTER;
    }

    if ((size < sizeof(struct CmParamSet)) || (size > CM_PARAM_SET_MAX_SIZE) ||
        (paramSet->paramSetSize != size) ||
        (paramSet->paramsCnt > ((size - sizeof(struct CmParamSet)) / sizeof(struct CmParam)))) {
        CM_LOG_E("invalid param set!");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

static int32_t CmFreshParamSet(struct CmParamSet *paramSet, bool isCopy)
{
    if (paramSet == NULL) {
        CM_LOG_E("invalid NULL paramSet");
        return CMR_ERROR_NULL_POINTER;
    }
    int32_t ret = CmCheckParamSet(paramSet, paramSet->paramSetSize);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("invalid fresh paramSet");
        return ret;
    }

    uint32_t size = paramSet->paramSetSize;
    uint32_t offset = sizeof(struct CmParamSet) + sizeof(struct CmParam) * paramSet->paramsCnt;

    for (uint32_t i = 0; i < paramSet->paramsCnt; i++) {
        if (offset > size) {
            CM_LOG_E("invalid param set offset!");
            return CMR_ERROR_INVALID_ARGUMENT;
        }
        if (GetTagType(paramSet->params[i].tag) == CM_TAG_TYPE_BYTES) {
            if (CmIsAdditionOverflow(offset, paramSet->params[i].blob.size)) {
                CM_LOG_E("blob size overflow!");
                return CMR_ERROR_INVALID_ARGUMENT;
            }

            if (isCopy && (memcpy_s((uint8_t *)paramSet + offset, size - offset,
                paramSet->params[i].blob.data, paramSet->params[i].blob.size) != EOK)) {
                CM_LOG_E("copy param blob failed!");
                return CMR_ERROR_INVALID_OPERATION;
            }
            paramSet->params[i].blob.data = (uint8_t *)paramSet + offset;
            offset += paramSet->params[i].blob.size;
        }
    }

    if (paramSet->paramSetSize != offset) {
        CM_LOG_E("invalid param set size!");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

static int32_t BuildParamSet(struct CmParamSet **paramSet)
{
    struct CmParamSet *freshParamSet = *paramSet;
    uint32_t size = freshParamSet->paramSetSize;
    uint32_t offset = sizeof(struct CmParamSet) + sizeof(struct CmParam) * freshParamSet->paramsCnt;

    if (size > CM_DEFAULT_PARAM_SET_SIZE) {
        freshParamSet = (struct CmParamSet *)CmMalloc(size);
        if (freshParamSet == NULL) {
            CM_LOG_E("malloc params failed!");
            return CMR_ERROR_MALLOC_FAIL;
        }
        if (memcpy_s(freshParamSet, size, *paramSet, offset) != EOK) {
            CM_FREE_PTR(freshParamSet);
            CM_LOG_E("copy params failed!");
            return CMR_ERROR_INVALID_OPERATION;
        }
        CM_FREE_PTR(*paramSet);
        *paramSet = freshParamSet;
    }

    return CmFreshParamSet(freshParamSet, true);
}

int32_t CmBuildParamSet(struct CmParamSet **paramSet)
{
    if ((paramSet == NULL) || (*paramSet == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int ret = CmCheckParamSet(*paramSet, (*paramSet)->paramSetSize);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("invalid build params!");
        return ret;
    }

    return BuildParamSet(paramSet);
}

void CmFreeParamSet(struct CmParamSet **paramSet)
{
    if (paramSet == NULL) {
        CM_LOG_E("invalid free paramset!");
        return;
    }
    CM_FREE_PTR(*paramSet);
}

int32_t CmGetParam(const struct CmParamSet *paramSet, uint32_t tag, struct CmParam **param)
{
    if ((paramSet == NULL) || (param == NULL)) {
        CM_LOG_E("invalid params!");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CmCheckParamSet(paramSet, paramSet->paramSetSize) != CM_SUCCESS) {
        CM_LOG_E("invalid paramSet!");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    for (uint32_t i = 0; i < paramSet->paramsCnt; i++) {
        if (tag == paramSet->params[i].tag) {
            *param = (struct CmParam *)&paramSet->params[i];
            return CM_SUCCESS;
        }
    }

    return CMR_ERROR_PARAM_NOT_EXIST;
}

static int32_t FreshParamSet(struct CmParamSet *paramSet, bool isCopy)
{
    uint32_t size = paramSet->paramSetSize;
    uint32_t offset = sizeof(struct CmParamSet) + sizeof(struct CmParam) * paramSet->paramsCnt;

    for (uint32_t i = 0; i < paramSet->paramsCnt; i++) {
        if (offset > size) {
            CM_LOG_E("FreshParamSet invalid param set offset!");
            return CMR_ERROR_INVALID_ARGUMENT;
        }
        if (GetTagType(paramSet->params[i].tag) == CM_TAG_TYPE_BYTES) {
            if (CmIsAdditionOverflow(offset, paramSet->params[i].blob.size)) {
                CM_LOG_E("FreshParamSet blob size overflow!");
                return CMR_ERROR_INVALID_ARGUMENT;
            }
            if (isCopy && memcpy_s((uint8_t *)paramSet + offset, size - offset,
                paramSet->params[i].blob.data, paramSet->params[i].blob.size) != EOK) {
                CM_LOG_E("FreshParamSet copy param blob failed!");
                return CMR_ERROR_INVALID_OPERATION;
            }
            paramSet->params[i].blob.data = (uint8_t *)paramSet + offset;
            offset += paramSet->params[i].blob.size;
        }
    }

    if (paramSet->paramSetSize != offset) {
        CM_LOG_E("FreshParamSet invalid param set size!");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t CmGetParamSet(const struct CmParamSet *inParamSet, uint32_t inParamSetSize, struct CmParamSet **outParamSet)
{
    int32_t ret = CmCheckParamSet(inParamSet, inParamSetSize);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    uint32_t size = inParamSet->paramSetSize;
    struct CmParamSet *buf = (struct CmParamSet *)CmMalloc(size);
    if (buf == NULL) {
        CM_LOG_E("malloc from param set failed!");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(buf, size, inParamSet, size);

    ret = FreshParamSet(buf, false);
    if (ret != CM_SUCCESS) {
        CM_FREE_PTR(buf);
        return ret;
    }
    *outParamSet = buf;
    return CM_SUCCESS;
}

static int32_t CheckBeforeAddParams(const struct CmParamSet *paramSet, const struct CmParam *params,
    uint32_t paramCnt)
{
    if ((params == NULL) || (paramSet == NULL) || (paramSet->paramSetSize > CM_PARAM_SET_MAX_SIZE) ||
        (paramCnt > CM_DEFAULT_PARAM_CNT) || ((paramSet->paramsCnt + paramCnt) > CM_DEFAULT_PARAM_CNT)) {
        CM_LOG_E("invalid params or paramset!");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    for (uint32_t i = 0; i < paramCnt; i++) {
        if ((GetTagType(params[i].tag) == CM_TAG_TYPE_BYTES) &&
            (params[i].blob.data == NULL)) {
            CM_LOG_E("invalid blob param!");
            return CMR_ERROR_INVALID_ARGUMENT;
        }
    }
    return CM_SUCCESS;
}

int32_t CmAddParams(struct CmParamSet *paramSet, const struct CmParam *params, uint32_t paramCnt)
{
    int32_t ret = CheckBeforeAddParams(paramSet, params, paramCnt);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    for (uint32_t i = 0; i < paramCnt; i++) {
        paramSet->paramSetSize += sizeof(struct CmParam);
        if (GetTagType(params[i].tag) == CM_TAG_TYPE_BYTES) {
            if (CmIsAdditionOverflow(paramSet->paramSetSize, params[i].blob.size)) {
                CM_LOG_E("params size overflow!");
                paramSet->paramSetSize -= sizeof(struct CmParam);
                return CMR_ERROR_INVALID_ARGUMENT;
            }
            paramSet->paramSetSize += params[i].blob.size;
        }
        (void)memcpy_s(&paramSet->params[paramSet->paramsCnt++], sizeof(struct CmParam), &params[i],
            sizeof(struct CmParam));
    }
    return CM_SUCCESS;
}
