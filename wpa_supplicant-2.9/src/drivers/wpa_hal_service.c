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
#include "hdf_log.h"
#include "hdf_sbuf.h"
#include "utils/hdf_base.h"
#include "hdf_remote_service.h"
#include "hdf_syscall_adapter.h"


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int OnWiFiEvents(void *priv, uint32_t id, struct HdfSBuf *data)
{
    (void)priv;
    if (data == NULL) {
        HDF_LOGE("%s: params is NULL", __func__);
        return HDF_FAILURE;
    }
    const char *ifname = HdfSbufReadString(data);
    if (ifname == NULL) {
        HDF_LOGE("%s: fail to get ifname", __func__);
        return HDF_FAILURE;
    }
    uint32_t ret = WifiWpaDriverEventProcess(ifname, id, data);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("WifiWpaEventMsg failed cmd=%u, ret=%d", id, ret);
    }
    return ret;
}

static struct HdfRemoteService *g_wifiService = NULL;

const char *DRIVER_SERVICE_NAME = "hdfwifi";

static struct HdfDevEventlistener g_wifiEventListener = {
    .callBack = OnWiFiEvents,
    .priv = NULL
};

int32_t WpaMsgServiceInit(void)
{
    g_wifiService = HdfRemoteServiceBind(DRIVER_SERVICE_NAME, 0);
    if (g_wifiService == NULL) {
        HDF_LOGE("%s: fail to get remote service!", __func__);
        return HDF_FAILURE;
    }

    if (HdfDeviceRegisterEventListener(g_wifiService, &g_wifiEventListener) != HDF_SUCCESS) {
        HDF_LOGE("%s: fail to register event listener", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

void WpaMsgServiceDeinit(void)
{
    if (HdfDeviceUnregisterEventListener(g_wifiService, &g_wifiEventListener)) {
        HDF_LOGE("fail to  unregister listener");
        return;
    }

    HdfRemoteServiceRecycle(g_wifiService);
}

int32_t WifiWpaCmdBlockSyncSend(const uint32_t cmd, struct HdfSBuf *reqData, struct HdfSBuf *respData)
{
    if (reqData == NULL) {
        HDF_LOGE("%s params is NULL", __func__);
        return HDF_FAILURE;
    }
    if (g_wifiService == NULL || g_wifiService->dispatcher == NULL || g_wifiService->dispatcher->Dispatch == NULL) {
        HDF_LOGE("%s:bad remote service found!", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = g_wifiService->dispatcher->Dispatch(&g_wifiService->object, cmd, reqData, respData);
    HDF_LOGI("%s: cmd=%d, ret=%d", __func__, cmd, ret);
    return ret;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif