/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

