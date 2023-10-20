/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */


#include "utils/includes.h"

int __attribute__((weak)) vendor_ext_test1()
{
    printf("%s: weak func.\n", __func__);
    return 0;
}

