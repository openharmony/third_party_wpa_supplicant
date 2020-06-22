/*
 * Copyright (c) 2020 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "wpa_hal_service.h"
#include "wpa_hal_event.h"
#include "sidecar.h"
#include "message_router.h"
#include "osal/hdf_log.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

ErrorCode WifiWpaEventMsg(const RequestContext *context, const DataBlock *reqData, DataBlock *rspData)
{
    uint32_t ret;
    uint8_t event;
    char *ifname = NULL;
    uint32_t ifnameLen = 0;

    if (PopNextStringSegment(reqData, &ifname, &ifnameLen) != ME_SUCCESS) {
        HDF_LOGE("%s: fail to get ifname", __func__);
        return ME_ERROR_PARA_WRONG;
    }
    if (PopNextU8Segment(reqData, &event) != ME_SUCCESS) {
        HDF_LOGE("%s: fail to get event", __func__);
        return ME_ERROR_PARA_WRONG;
    }
    ret = WifiWpaDriverEventProcess(ifname, event, reqData);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("WifiWpaEventMsg failed cmd=%u, ret=%d", event, ret);
    }

    return ret;
}

ServiceDefStart(WPAMsg, WPA_MSG_SERVICE_ID) 
    Massage(WIFI_WPA_EVENT_MSG, WifiWpaEventMsg, 2) 
ServiceDefEnd;

Service *g_wpaService;

int16_t WpaMsgServiceInit(void)
{
    int rc;

    rc = StartMessageRouter(MESSAGE_NODE_LOCAL | MESSAGE_NODE_REMOTE_USERSPACE_CLIENT);
    if (rc != 0) {
        HDF_LOGE("%s StartMessageRouter failed rc=%d", __func__, rc);
        return rc;
    }

    ServiceCfg cfg = {
        .dispatcherID = DEFAULT_DISPATCHER_ID
    };

    g_wpaService = CreateService(WPAMsg, &cfg);
    if (g_wpaService == NULL) {
        HDF_LOGE("%s Create WPAMsg service failed.", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t WifiWpaCmdSyncSend(const uint32_t cmd, void *buf, uint32_t len, DataBlock *respData)
{
    int32_t ret = HDF_FAILURE;

    if (buf == NULL) {
        return ret;
    }

    if (g_wpaService != NULL && g_wpaService->SendSyncMessage != NULL) {
        ret = g_wpaService->SendSyncMessage(g_wpaService, WAL_MSG_SERVICE_ID, cmd, buf, len, respData);
    }
    HDF_LOGE("WifiWpaCmdSyncSend info cmd=%d, ret=%d", cmd, ret);

    return ret;
}

int32_t WifiWpaCmdBlockSyncSend(const uint32_t cmd, DataBlock *data, DataBlock *respData)
{
    return WifiWpaCmdSyncSend(cmd, data->data, data->size, respData);
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif