#ifdef EXT_AUTHENTICATION_SUPPORT
#include <stdbool.h>
#include <stdio.h>
#include "common.h"
#define TYPE_OFFSET 4
#define IFNAME_LENGTH 2
#define BUF_SIZE 2048
#define PARAM_LEN 30
#define BASE64_NUM 3
#define TLS_DATA_OFFSET 6
#define EXT_AUTH_CODE_SUCCESS 3
#define EXT_AUTH_CODE_FAIL 4
enum Ifname {
     IFNAME_UNKNOWN = 0,
     IFNAME_WIFI0 = 1,
     IFNAME_ETH0 = 2,
     IFNAME_SIZE = 3
 };

const char *ifname_to_string(int ifname);

bool reg_ext_auth(int code, int type, int ifname);
void clear_ext_auth();
int get_ext_auth(int code, int type);

// 递增的数字标识符
int get_authentication_idx();
void add_authentication_idx();
 
uint8_t* get_eap_data();
int get_eap_data_len();
void clear_eap_data();
void set_eap_data(uint8_t* eapData, int eapDataLen);
 
struct eap_sm;
void set_eap_sm(struct eap_sm *eapSm);
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
bool get_eap_encrypt_enable();
void ext_authentication_eap_init();
void set_decrypt_buf(const struct wpabuf *in);
struct wpabuf* get_decrypt_buf();
int get_tx_prepared();
void clear_tx_prepared();
#endif /* EXT_AUTHENTICATION_SUPPORT */
#endif /* EXT_AUTHENTICATION_H */