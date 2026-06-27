/*
 * EAP peer state machine functions (RFC 4137)
 * Copyright (c) 2004-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef EXT_AUTH_EAP_PEAP_H
#define EXT_AUTH_EAP_PEAP_H

#ifdef EXT_AUTHENTICATION_SUPPORT
#include "eap_tls_common.h"
// 复制代码，不作修改
struct eap_peap_data {
	struct eap_ssl_data ssl;

	int peap_version, force_peap_version, force_new_label;

	const struct eap_method *phase2_method;
	void *phase2_priv;
	int phase2_success;
	int phase2_eap_success;
	int phase2_eap_started;

	struct eap_method_type phase2_type;
	struct eap_method_type *phase2_types;
	size_t num_phase2_types;

	int peap_outer_success; /* 0 = PEAP terminated on Phase 2 inner
				 * EAP-Success
				 * 1 = reply with tunneled EAP-Success to inner
				 * EAP-Success and expect AS to send outer
				 * (unencrypted) EAP-Success after this
				 * 2 = reply with PEAP/TLS ACK to inner
				 * EAP-Success and expect AS to send outer
				 * (unencrypted) EAP-Success after this */
	int resuming; /* starting a resumed session */
	int reauth; /* reauthentication */
	u8 *key_data;
	u8 *session_id;
	size_t id_len;

	struct wpabuf *pending_phase2_req;
	struct wpabuf *pending_resp;
	enum { NO_BINDING, OPTIONAL_BINDING, REQUIRE_BINDING } crypto_binding;
	int crypto_binding_used;
	u8 binding_nonce[32];
	u8 ipmk[40];
	u8 cmk[20];
	int soh; /* Whether IF-TNCCS-SOH (Statement of Health; Microsoft NAP)
		  * is enabled. */
};
#endif
#endif