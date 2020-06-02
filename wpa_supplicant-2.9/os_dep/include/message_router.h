/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: base data type
 * Author: duxiaobo
 * Create: 2020-4-27
 */

#ifndef __MESSAGE_ROUTER_H__
#define __MESSAGE_ROUTER_H__
#include "message_config.h"
#include "message_dispatcher.h"

#define DEFAULT_DISPATCHER_ID 0
#define BAD_DISPATCHER_ID 255

typedef uint8_t DispatcherID;
#define DEFAULT_SERVICE_ID 0
#define BAD_SERVICE_ID 254

#ifdef __cplusplus
extern "C" {
#endif

enum MessageNodeType {
    MESSAGE_NODE_LOCAL = 1,
#ifdef KERNEL_SERVER_SUPPORT
    MESSAGE_NODE_REMOTE_KERNEL_SERVER = 2,
#endif
#ifdef USERSPACE_CLIENT_SUPPORT
    MESSAGE_NODE_REMOTE_USERSPACE_CLIENT = 4
#endif
};

ErrorCode StartMessageRouter(uint8_t nodesConfig);

ErrorCode ShutdownMessageRouter(void);

ErrorCode RegistDispatcher(DispatcherID dispatcherID, MessageDispatcher *config);

ErrorCode RegistNewDispatcher(DispatcherID dispatcherID, DispatcherConfig *config);

/*
dispatcherID: 要绑定到的DispatcherID
mapper：服务的消息映射
*/
ErrorCode RegistService(DispatcherID dispatcherID, struct MassageMapper *mapper);

ErrorCode RegistRemoteService(DispatcherID dispatcherID, struct MassageMapper *mapper);
ErrorCode UnregistRemoteService(ServiceID serviceID);

ErrorCode RouteMessage(MessageContext *context);

/*
commandID : 消息的唯一标识
sendData : 要发送的数据
callback : 回调函数。NULL代表不回调。对方业务返回消息时回回调该接口，提供调用返回值 + 返回数据.
*/
ErrorCode SendAsyncMessage(
    ServiceID sender, ServiceID receiver, uint32_t commandID, DataBlock sendData, MessageCallBack callback);

/*
[out]recvData: 调用者提供一个可用的DataBlock结构体指针。调用完成时，接口会完成填值
[out]responseStatus: 返回状态码
*/
ErrorCode SendSyncMessage(ServiceID sender, ServiceID receiver, uint32_t commandID, const DataBlock* sendData,
    DataBlock* recvData, uint16_t* responseStatus);

ErrorCode SendOneWayMessage(ServiceID sender, ServiceID receiver, uint32_t commandID, const DataBlock sendData);

/*
调换发送方与接收方，发送响应消息。
*/
ErrorCode SendResponse(MessageContext *context);

typedef struct MessageNode_ {
    enum MessageNodeType type;
    ErrorCode (*Init)(struct MessageNode_ *);
    ErrorCode (*Deinit)(struct MessageNode_ *);
    ErrorCode (*DispatchMessage)(struct MessageNode_ *, DispatcherID dispatcherID, MessageContext *context);
    void (*Destory)(struct MessageNode_ *);
} MessageNode;

typedef struct LocalMessageNode_ {
    MessageNode baseNodeOps;
    MessageDispatcher *dispatchers[MESSAGE_ENGINE_MAX_DISPATCHER];
} LocalMessageNode;

typedef struct RemoteMessageNode_ {
    MessageNode baseNodeOps;
    ErrorCode (*RegistRemoteService)(struct RemoteMessageNode_ *, const struct MassageMapper *mapper);
    ErrorCode (*UnregistRemoteService)(struct RemoteMessageNode_ *, const ServiceID serviceID);
    void *privateData;
} RemoteMessageNode;

#define MESSAGE_DEVICE "/dev/wifi_msg"
#define MESSAGE_DEVICE_MODE 0666
enum IOCTL_CMD {
    MESSAGE_IOCTL_CMD_REG_SERVICE = 0,
    MESSAGE_IOCTL_CMD_UNREG_SERVICE,
    MESSAGE_IOCTL_CMD_SEND_MESSAGE,
    MESSAGE_IOCTL_CMD_RECEIVE_NEXT_MESSAGE,
    MESSAGE_IOCTL_CMD_RECEIVE_MESSAGE_DATA,
    WIFI_MSG_DIRECT_CALL,
};

#ifdef KERNEL_SERVER_SUPPORT
ErrorCode CreateKernelServerNode(MessageNode **node);
#endif

#ifdef USERSPACE_CLIENT_SUPPORT
ErrorCode CreateUserspaceClientNode(MessageNode **node);
#endif

#ifdef __cplusplus
}
#endif

#endif
