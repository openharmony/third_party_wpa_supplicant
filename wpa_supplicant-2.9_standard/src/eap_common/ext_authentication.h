/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#ifndef EXT_AUTHENTICATION_H
#define EXT_AUTHENTICATION_H

#ifdef EXT_AUTHENTICATION_SUPPORT
#include <stdbool.h>
#include <stdio.h>

#define TYPE_OFFSET 4
#define IFNAME_LENGTH 2
#define BUF_SIZE 2048
#define PARAM_LEN 30
#define BASE64_NUM 3

enum Ifname {
     IFNAME_UNKNOWN = 0,
     IFNAME_WIFI0 = 1,
     IFNAME_ETH0 = 2,
     IFNAME_SIZE = 3
 };

 extern const char* g_ifnameToString[];

 bool reg_ext_auth(int code, int type, int ifname);
 bool un_reg_ext_auth(int code, int type);
 int get_ext_auth(int code, int type);

// 递增的数字标识符
int get_authentication_idx();
void add_authentication_idx();

uint8_t* get_eap_data();
int get_eap_data_len();
void clear_eap_data();
void set_eap_data(uint8_t* eapData, int eapDataLen);

struct eap_sm;
void set_eap_sm(struct eap *eapSm);
struct eap_sm* get_eap_sm();

struct eap_ssl_data;
struct encrypt_data{
    struct eap_ssl_data *ssl;
    int eapType;
    int version;
    unsigned char id;
};

void set_encrypt_data(struct eap_ssl_data *ssl, int eapType, int version, unsigned char id);
void set_encrypt_eap_type(int eapType);
struct encrypt_data* get_encrypt_data();

int get_code();
void set_code(int code);
#endif /* EXT_AUTHENTICATION_SUPPORT */
#endif /* EXT_AUTHENTICATION_H */