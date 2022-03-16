/* Copyright (c) 2021 Huawei Device Co., Ltd.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "libwpa.h"

pthread_t g_apThread;

char* g_apArg[20] ={0};
int g_apArgc = 0;

static void* ThreadMain()
{
    printf("[HostapdSample]init hostapd.\n");
    int ret = ap_main(g_apArgc, g_apArg);
    printf("[HostapdSample]run ap_main result is %d.\n", ret);
    return NULL;
}

int main(int argc, char *argv[])
{
    g_apArgc = argc;
    for (int i = 0; i < g_apArgc; i++) {
        g_apArg[i] = argv[i];
    }
    int ret = pthread_create(&g_apThread, NULL, ThreadMain, NULL);
    if (ret != 0) {
        printf("[HostapdSample]create thread failed, errorNumberis %s.\n", strerror(ret));
        return -1;
    }
    pthread_join(g_apThread, NULL);
    return 0;
}