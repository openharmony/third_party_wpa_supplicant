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

#include "cm_log.h"

#include "securec.h"

#include "hilog/log.h"
#include "cm_mem.h"

#define MAX_LOG_BUFF_LEN 512

void CmLog(uint32_t logLevel, const char *funcName, uint32_t lineNo, const char *format, ...)
{
    char *buf = (char *)CmMalloc(MAX_LOG_BUFF_LEN);
    if (buf == NULL) {
        HILOG_ERROR(LOG_CORE, "certificate manager log malloc fail");
        return;
    }
    (void)memset_s(buf, MAX_LOG_BUFF_LEN, 0, MAX_LOG_BUFF_LEN);

    va_list ap;
    va_start(ap, format);
    int32_t ret = vsnprintf_s(buf, MAX_LOG_BUFF_LEN, MAX_LOG_BUFF_LEN - 1, format, ap);
    va_end(ap);
    if (ret < 0) {
        HILOG_ERROR(LOG_CORE, "certificate manager log concatenate error.");
        CM_FREE_PTR(buf);
        return;
    }

    switch (logLevel) {
        case CM_LOG_LEVEL_I:
            HILOG_INFO(LOG_CORE, "%{public}s[%{public}u]: %{public}s\n", funcName, lineNo, buf);
            break;
        case CM_LOG_LEVEL_E:
            HILOG_ERROR(LOG_CORE, "%{public}s[%{public}u]: %{public}s\n", funcName, lineNo, buf);
            break;
        case CM_LOG_LEVEL_W:
            HILOG_WARN(LOG_CORE, "%{public}s[%{public}u]: %{public}s\n", funcName, lineNo, buf);
            break;
        case CM_LOG_LEVEL_D:
            HILOG_DEBUG(LOG_CORE, "%{public}s[%{public}u]: %{private}s\n", funcName, lineNo, buf);
            break;
        default:
            CM_FREE_PTR(buf);
            return;
    }

    CM_FREE_PTR(buf);
}
