#ifndef __SIDECAR_H__
#define __SIDECAR_H__
#include "message_router.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SideCar_ {
    /*
    sendData 中指针只能使用堆内存
    */
    ErrorCode (*SendOneWayMessage)(struct SideCar_ *sideCar, ServiceID receiver, uint32_t commandID,
        DataBlock sendData);

    /*
    注意sendData 和 recvData中的内存需要调用方释放。sendData和responseStatus中可以使用栈内存，recvData一定是堆内存
    */
    ErrorCode (*SendSyncMessage)(struct SideCar_ *sideCar, ServiceID receiver, uint32_t commandID,
        const DataBlock *sendData, DataBlock *recvData, uint16_t *responseStatus);

    /*
    commandID : 消息的唯一标识
    sendData : 要发送的数据，其中data指针必须使用堆内存
    callback : 回调函数。NULL代表不回调。对方业务返回消息时回回调该接口。callback中如果主动释放内存一定将data和size都置0，如果不释放系统会尝试回收。
    */
    ErrorCode (*SendAsyncMessage)(struct SideCar_ *sideCar, ServiceID receiver, uint32_t commandID, DataBlock sendData,
        MessageCallBack callback);

    void *privateData;
} SideCar;

ErrorCode ConstructSideCar(SideCar *sideCar, ServiceID serviceID);

ErrorCode DeconstructSideCar(SideCar *sideCar);

#ifdef __cplusplus
}
#endif

#endif