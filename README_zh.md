# Wpa Supplicant
# 简介
[wpa_supplicant](https://w1.fi/wpa_supplicant/)是跨平台的开源软件，支持WPA、WPA2、WPA3（IEEE 802.11i）等Wlan接入技术，可用于台式机、笔记本电脑、手机和其他嵌入式系统。
在OpenHarmony中，wpa_supplicant用来提供Wi-Fi接入和Wi-Fi热点开启的协议栈。

# OpenHarmony中wpa_supplicant架构介绍
wpa_supplicant的软件上下文如图所示。
![wpa_supplicant软件上下文](https://foruda.gitee.com/images/1663914145839018363/98121b90_7809085.png "wpa_supplicant软件上下文")
 **接口层** ：提供wpa_supplicant与Wi-Fi服务通信的接口。
 **wpa协议栈** ：提供Wi-Fi接入与热点功能，其中wpa_supplicant负责Wi-Fi接入，hostapd负责热点功能。
 **HAL**： wpa_supplicant支持多种驱动形式，当前OpenHarmony支持HDF驱动和NL80211驱动。

> 说明：系统开发者可以通过在产品的配置文件中对使用何驱动进行配置。
例如[RK3568使用NL80211驱动](https://gitee.com/openharmony/vendor_hihope/pulls/375)。

# 目录结构
``` shell
/third_party/wpa_supplicant
|-- CONTRIBUTIONS                       # 贡献说明
|-- COPYING                             # 版权说明
|-- wpa_supplicant-2.9                  # 轻量级系统的wpa_supplicant
|   |-- hostapd                         # Wi-Fi热点相关功能（Access Point）
|   |-- hs20                            # 热点2.0（Hotspot2.0）相关功能
|   |-- src                             # Wi-Fi热点与Wi-Fi接入点共用的代码
|   |-- wpa_supplicant                  # Wi-Fi接入相关功能（Station）
|   `-- wpa_supplicant_lib              # OpenHarmony对Wi-Fi新开发的业务代码
`-- wpa_supplicant-2.9_standard         # 标准系统的wpa_supplicant
|   |-- hostapd                         # Wi-Fi热点相关功能（Access Point）
|   |-- hs20                            # 热点2.0（Hotspot2.0）相关功能
|   |-- src                             # Wi-Fi热点与Wi-Fi接入点共用的代码
|   |-- wpa_supplicant                  # Wi-Fi接入相关功能（Station）
|   `-- wpa_supplicant_lib              # OpenHarmony对Wi-Fi新开发的业务代码

```
> 说明：由于轻量级系统与标准系统采用的编译链不同，当前暂时按不同的目录隔离。

# 约束
- 开发语言：C