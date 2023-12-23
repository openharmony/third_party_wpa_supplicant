 /*
  * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 
 #ifndef AP_CTRL_IFACE_H
 #define AP_CTRL_IFACE_H
 
int hostapd_ctrl_iface_set(struct hostapd_data *hapd, char *cmd);
 
int hostapd_ctrl_iface_acl_add_mac(struct mac_acl_entry **acl, int *num,
				const char *cmd);

int hostapd_ctrl_iface_acl_del_mac(struct mac_acl_entry **acl, int *num,
				const char *txtaddr);

void hostapd_disassoc_deny_mac(struct hostapd_data *hapd);

int hostapd_ctrl_iface_enable(struct hostapd_iface *iface);

int hostapd_ctrl_iface_disable(struct hostapd_iface *iface);

 #endif
