/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: wpa msg header file
 * Author: zhaifengwei
 * Create: 2020-05-19
 */
#include "wpa_msg_service.h"
#include "sidecar.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

extern int32_t hisi_driver_send_event(const char *ifname, int32_t cmd, const uint8_t *buf, uint32_t length);
/*
 * WIFI驱动上报事件
 */
void WifiWpaEventMsg(MessageContext* context)
{
    uint32_t ret;
    EventMsgObj *evtObj = NULL;

    evtObj = (EventMsgObj *)context->reqData.data;
    ret = hisi_driver_send_event(evtObj->ifname, evtObj->event, evtObj->buf, evtObj->length);
    if (ret != HDF_SUCCESS) {
        printf("error: driver_send_event cmd=%u, lret=%d.\n", evtObj->event, ret);
    }
    return;
}

MassageDefineBegin(WpaMsg) = {
    Massage(WIFI_WPA_EVENT_MSG, WifiWpaEventMsg, 2),
};

ServiceDef(WPA_MSG_SERVICE_ID, WpaMsg);

SideCar g_wpaSideCar;

int16_t WpaMsgServiceInit(void)
{
    int rc;

    rc = StartMessageRouter(MESSAGE_NODE_LOCAL | MESSAGE_NODE_REMOTE_USERSPACE_CLIENT);
    if (rc != 0) {
        return rc;
    }

    rc = RegistService(DEFAULT_DISPATCHER_ID, &Service(WpaMsg));
    if (rc != 0) {
        return rc;
    }

    rc = ConstructSideCar(&g_wpaSideCar, WPA_MSG_SERVICE_ID);
    if (rc != 0) {
        return rc;
    }

    struct MassageMapper mapper = {.serviceID = WAL_MSG_SERVICE_ID, .messagesLength = 0,.messages = NULL};
    // HDF_LOGE("Regist remote service.ServiceID=%d", WAL_MSG_SERVICE_ID);
    rc = RegistRemoteService(0,&mapper);
    if (rc != ME_SUCCESS){
        // HDF_LOGE("Regist remote service failed!ret=%d",rc);
        return rc;
    }

    return HDF_SUCCESS;
}

int32_t WifiWpaCmdSyncSend(const char *ifname, void *buf)
{
    int32_t ret = HDF_FAILURE;
    IoctlMsgObj msgObj;
    DataBlock sendData;

    if (buf == NULL) {
        return ret;
    }
    if (strncpy_s(msgObj.ifname, IFNAMSIZ, ifname, strlen(ifname)) != 0) {
        return ret;
    }
    msgObj.buf = buf;

    sendData.data = &msgObj;
    sendData.size = sizeof(IoctlMsgObj);
    if (g_wpaSideCar.SendSyncMessage != NULL) {
        DataBlock response = {0,0};
        uint16_t responseStatus = 0;
        ret = g_wpaSideCar.SendSyncMessage(&g_wpaSideCar, WAL_MSG_SERVICE_ID, WIFI_WPA_IOCTL_MSG, &sendData,&response,&responseStatus);
    }
    printf("\r\n WifiWpaCmdSyncSend end.\r\n");
    return ret;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
