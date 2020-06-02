/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: wpa msg header file
 * Author: zhaifengwei
 * Create: 2020-05-19
 */

#ifndef _WPA_MSG_SERVICE_H_
#define _WPA_MSG_SERVICE_H_

#include "sidecar.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define WPA_MSG_SERVICE_ID 0x3
#define WAL_MSG_SERVICE_ID 0x4
#define IFNAMSIZ 16

// IOCTL消息定义
#define WIFI_WPA_IOCTL_MSG 0
typedef struct {
    char ifname[IFNAMSIZ + 1];
    void *buf;
} IoctlMsgObj;

// Event消息定义
#define WIFI_WPA_EVENT_MSG 0
typedef struct {
    char ifname[IFNAMSIZ];
    int32_t event;
    int32_t length;
    uint8_t buf[0];
} EventMsgObj;

extern SideCar g_wpaSideCar;
int16_t WpaMsgServiceInit(void);
int32_t WifiWpaCmdSyncSend(const char *ifname, void *buf);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif


#endif /* _WPA_MSG_SERVICE_H_ */