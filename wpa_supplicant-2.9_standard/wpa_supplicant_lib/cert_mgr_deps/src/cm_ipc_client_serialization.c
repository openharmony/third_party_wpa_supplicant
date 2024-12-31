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
