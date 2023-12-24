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

#include "cm_mem.h"

#include <string.h>

#ifdef CM_SUPPORT_PRODUCT_GT_WATCH
#include "ohos_mem_pool.h"

void *CmMalloc(size_t size)
{
    return OhosMalloc(MEM_TYPE_HICHAIN, size);
}

void CmFree(void *ptr)
{
    OhosFree(ptr);
}
#else
void *CmMalloc(size_t size)
{
    return malloc(size);
}

void CmFree(void *ptr)
{
    free(ptr);
}
#endif