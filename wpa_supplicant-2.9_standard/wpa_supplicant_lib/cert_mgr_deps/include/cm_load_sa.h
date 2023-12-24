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

#ifndef CM_LOAD_SA_H
#define CM_LOAD_SA_H

#include <future>
#include <string>
#include "iremote_object.h"
#include "system_ability_load_callback_stub.h"

class OnDemandLoadCertManagerCallback : public OHOS::SystemAbilityLoadCallbackStub {
public:
    OnDemandLoadCertManagerCallback(std::string servers);
    void OnLoadSystemAbilitySuccess(int32_t systemAbilityId,
        const OHOS::sptr<IRemoteObject>& remoteObject) override;
    void OnLoadSystemAbilityFail(int32_t systemAbilityId) override;
    OHOS::sptr<IRemoteObject> Promise(void);
private:
    std::string servers;
    std::promise<OHOS::sptr<IRemoteObject>> promise_;
};

#endif /* CM_LOAD_SA_H */