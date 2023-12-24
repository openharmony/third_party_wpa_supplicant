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

#include "cm_request.h"

#include <chrono>
#include <string>
#include <thread>

#include "securec.h"

#include "cm_load_sa.h"
#include "cm_log.h"

#include "iservice_registry.h"

using namespace std;
using namespace OHOS;

namespace {
    constexpr int SA_ID_KEYSTORE_SERVICE = 3512;
    constexpr uint32_t MAX_SA_BOOT_DELAY_TIME = 30;
    const std::u16string SA_KEYSTORE_SERVICE_DESCRIPTOR = u"ohos.security.cm.service";
}

static sptr<IRemoteObject> CmLoadSystemAbility(void)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        CM_LOG_E("GetCmProxy registry is null");
        return {};
    }

    auto object = saManager->CheckSystemAbility(SA_ID_KEYSTORE_SERVICE);
    if (object != nullptr) {
        return object;
    }

    string servers = "CertManager";
    sptr<OnDemandLoadCertManagerCallback> loadCallBack = new (std::nothrow)OnDemandLoadCertManagerCallback(servers);
    if (loadCallBack == nullptr) {
        CM_LOG_E("new OnDemandLoadCertManagerCallback failed");
        return {};
    }

    int32_t ret = saManager->LoadSystemAbility(SA_ID_KEYSTORE_SERVICE, loadCallBack);
    if (ret != ERR_OK) {
        CM_LOG_E("systemAbilityId:%d load failed,result code:%d", SA_ID_KEYSTORE_SERVICE, ret);
        return {};
    }

    return loadCallBack->Promise();
}

static int32_t CmReadRequestReply(MessageParcel &reply, struct CmBlob *outBlob)
{
    int32_t ret = reply.ReadInt32();
    if (ret != CM_SUCCESS) {
        CM_LOG_D("CmReadRequestReply start");
        return ret;
    }

    size_t outLen = reply.ReadUint32();
    if (outLen == 0) {
        if (outBlob != nullptr) {
            outBlob->size = 0;
        }
        return ret;
    }
    if (CmCheckBlob(outBlob) != CM_SUCCESS) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    const uint8_t *outData = reply.ReadBuffer(outLen);
    if (outData == nullptr) {
        return CMR_ERROR_NULL_POINTER;
    }
    if (outBlob->size < outLen) {
        CM_LOG_E("outBlob size[%u] smaller than outLen[%u]", outBlob->size, outLen);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    if (memcpy_s(outBlob->data, outBlob->size, outData, outLen) != EOK) {
        return CMR_ERROR_INVALID_OPERATION;
    }
    outBlob->size = outLen;
    return CM_SUCCESS;
}

int32_t SendRequest(enum CertManagerInterfaceCode type, const struct CmBlob *inBlob,
    struct CmBlob *outBlob)
{
    uint32_t i = 0;
    sptr<IRemoteObject> cmProxy = CmLoadSystemAbility();
    while ((cmProxy == nullptr) && i < MAX_SA_BOOT_DELAY_TIME) {
        CM_LOG_E("cmProxy is nullptr, i = %u", i);
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); /* 100 is time */
        i++;
    }

    cmProxy = CmLoadSystemAbility();
    if (cmProxy == nullptr) {
        CM_LOG_E("Certtificate manager Proxy is null.");
        return CMR_ERROR_NULL_POINTER;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option = MessageOption::TF_SYNC;

    data.WriteInterfaceToken(SA_KEYSTORE_SERVICE_DESCRIPTOR);
    if (outBlob == nullptr) {
        data.WriteUint32(0);
    } else {
        data.WriteUint32(outBlob->size);
    }
    data.WriteUint32(inBlob->size);
    data.WriteBuffer(inBlob->data, static_cast<size_t>(inBlob->size));

    int error = cmProxy->SendRequest(static_cast<uint32_t>(type), data, reply, option);
    if (error != 0) {
        CM_LOG_E("SendRequest error:%d", error);
        return error;
    }
    return CmReadRequestReply(reply, outBlob);
}

void OnDemandLoadCertManagerCallback::OnLoadSystemAbilitySuccess(int32_t systemAbilityId,
    const sptr<IRemoteObject> &remoteObject)
{
    CM_LOG_D("OnLoadSystemAbility Success systemAbilityId: %d, IRemoteObject result:%s",
        systemAbilityId, ((remoteObject != nullptr) ? "succeed" : "failed"));
    promise_.set_value(remoteObject);
}

void OnDemandLoadCertManagerCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    CM_LOG_E("OnLoadSystemAbility Fail systemAbilityId: %d", systemAbilityId);
    promise_.set_value(nullptr);
}

sptr<IRemoteObject> OnDemandLoadCertManagerCallback::Promise(void)
{
    return promise_.get_future().get();
}
