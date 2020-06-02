/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: base data type
 * Author: duxiaobo
 * Create: 2020-4-27
 */

#ifndef __MESSAGEDISPATCHER_H__
#define __MESSAGEDISPATCHER_H__
#include "stdint.h"
#include "osal/hdf_sem.h"
#include "message_types.h"
#include "message_config.h"

#define MAX_PRI_LEVEL_COUNT 3

#ifdef __cplusplus
extern "C" {
#endif

struct DataBlock {
    void *data;
    uint32_t size;
};

#define MAX_BLOCK_SIZE 4000

#define QUEUE_OPER_TIMEOUT 5000

typedef struct DataBlock DataBlock;

struct MessageContext;

typedef void (*MessageCallBack)(struct MessageContext *context);

enum MessageType {
    MESSAGE_REQ_START = 0,
    MESSAGE_TYPE_SYNC_REQ,
    MESSAGE_TYPE_ASYNC_REQ,
    MESSAGE_TYPE_ONEWAY_REQ,

    MESSAGE_RSP_START,
    MESSAGE_TYPE_SYNC_RSP,
    MESSAGE_TYPE_ASYNC_RSP
};

struct MessageContext {
    uint32_t commandID;
    uint8_t senderID;
    uint8_t receiverID;
    uint8_t requestType; // Sync or Async
    uint16_t responseStatus;
    struct DataBlock reqData;
    struct DataBlock rspData;
    union {
        MessageCallBack callback;
        HDF_DECLARE_SEMAPHORE(rspSemaphore);
    };
    uint16_t messageID; // Only used to cross node
    bool corssNode;
};

typedef struct MessageContext MessageContext;

typedef void (*MessageHandler)(MessageContext *context);

struct MessageDef {
    const MessageHandler handler;
    uint8_t pri;
};

struct MassageMapper {
    ServiceID serviceID;
    uint8_t messagesLength;
    struct MessageDef *messages;
};

enum DispatcherStatus {
    DISPATCHER_STATUS_STOPPED = 0,
    DISPATCHER_STATUS_STARTTING,
    DISPATCHER_STATUS_RUNNING,
    DISPATCHER_STATUS_STPPING
};

struct BasicDispatcherData_;
typedef struct BasicDispatcherData_ BasicDispatcherData;

#define INHERT_DISPATCHER_DATA void *messageQueue;                                               \
    const struct MassageMapper *services[MESSAGE_ENGINE_MAX_SERVICE]; \
    volatile uint8_t status

struct BasicDispatcherData_ {
    INHERT_DISPATCHER_DATA;
};

struct MessageDispatcher_;
typedef struct MessageDispatcher_ MessageDispatcher;

#define INHERT_MESSAGE_DISPATCHER                                                           \
    ErrorCode (*DispatchMessage)(MessageDispatcher *, MessageContext * context);            \
    ErrorCode (*ProcessMessage)(MessageDispatcher *, MessageContext * context);             \
    ErrorCode (*BindService)(MessageDispatcher *, const struct MassageMapper *mapper);      \
    ErrorCode (*Start)(MessageDispatcher * dispatcher);                                     \
    ErrorCode (*Shutdown)(MessageDispatcher * dispatcher);                                  \
    ErrorCode (*GetStatus)(MessageDispatcher * dispatcher, enum DispatcherStatus * status); \
    ErrorCode (*Destory)(MessageDispatcher *);                                              \
    void *privateData;

struct MessageDispatcher_ {
    INHERT_MESSAGE_DISPATCHER;
};

typedef struct DispatcherConfig_ {
    uint8_t priorityLevelCount;
    uint16_t queueSize;
} DispatcherConfig;

/*
maxServiceCount: 1-200 allowed
*/
ErrorCode CreateMessageDispatcher(MessageDispatcher **, const DispatcherConfig *config);


#ifdef __cplusplus
}
#endif

#define MassageDefineBegin(ServiceName) static struct MessageDef MessageHandlers_##ServiceName[]
#define Massage(CMDID, HANDLER, PRI) [CMDID] = {                      \
        .handler = HANDLER,          \
        .pri = PRI                   \
    }

#define ServiceDef(ServiceID, ServiceName) struct MassageMapper MessageMapper_##ServiceName = {         \
        .serviceID = ServiceID,                                  \
        .messagesLength = sizeof(MessageHandlers_##ServiceName), \
        .messages = MessageHandlers_##ServiceName                \
    }

#define ServiceExtern(ServiceName) extern struct MassageMapper MessageMapper_##ServiceName

#define Service(ServiceName) MessageMapper_##ServiceName


#endif
