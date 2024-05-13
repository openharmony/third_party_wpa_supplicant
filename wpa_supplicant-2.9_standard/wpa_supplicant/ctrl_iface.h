/*
 * WPA Supplicant / UNIX domain socket -based control interface
 * Copyright (c) 2004-2020, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef CTRL_IFACE_H
#define CTRL_IFACE_H

#ifdef CONFIG_CTRL_IFACE

#ifndef CTRL_IFACE_MAX_LEN
#define CTRL_IFACE_MAX_LEN 8192
#endif /* CTRL_IFACE_MAX_LEN */

/* Shared functions from ctrl_iface.c; to be called by ctrl_iface backends */

/**
 * wpa_supplicant_ctrl_iface_process - Process ctrl_iface command
 * @wpa_s: Pointer to wpa_supplicant data
 * @buf: Received command buffer (nul terminated string)
 * @resp_len: Variable to be set to the response length
 * Returns: Response (*resp_len bytes) or %NULL on failure
 *
 * Control interface backends call this function when receiving a message that
 * they do not process internally, i.e., anything else than ATTACH, DETACH,
 * and LEVEL. The return response value is then sent to the external program
 * that sent the command. Caller is responsible for freeing the buffer after
 * this. If %NULL is returned, *resp_len can be set to two special values:
 * 1 = send "FAIL\n" response, 2 = send "OK\n" response. If *resp_len has any
 * other value, no response is sent.
 */
char * wpa_supplicant_ctrl_iface_process(struct wpa_supplicant *wpa_s,
					 char *buf, size_t *resp_len);

/**
 * wpa_supplicant_global_ctrl_iface_process - Process global ctrl_iface command
 * @global: Pointer to global data from wpa_supplicant_init()
 * @buf: Received command buffer (nul terminated string)
 * @resp_len: Variable to be set to the response length
 * Returns: Response (*resp_len bytes) or %NULL on failure
 *
 * Control interface backends call this function when receiving a message from
 * the global ctrl_iface connection. The return response value is then sent to
 * the external program that sent the command. Caller is responsible for
 * freeing the buffer after this. If %NULL is returned, *resp_len can be set to
 * two special values: 1 = send "FAIL\n" response, 2 = send "OK\n" response. If
 * *resp_len has any other value, no response is sent.
 */
char * wpa_supplicant_global_ctrl_iface_process(struct wpa_global *global,
						char *buf, size_t *resp_len);


/* Functions that each ctrl_iface backend must implement */

/**
 * wpa_supplicant_ctrl_iface_init - Initialize control interface
 * @wpa_s: Pointer to wpa_supplicant data
 * Returns: Pointer to private data on success, %NULL on failure
 *
 * Initialize the control interface and start receiving commands from external
 * programs.
 *
 * Required to be implemented in each control interface backend.
 */
struct ctrl_iface_priv *
wpa_supplicant_ctrl_iface_init(struct wpa_supplicant *wpa_s);

/**
 * wpa_supplicant_ctrl_iface_deinit - Deinitialize control interface
 * @wpa_s: Pointer to wpa_supplicant data
 * @priv: Pointer to private data from wpa_supplicant_ctrl_iface_init()
 *
 * Deinitialize the control interface that was initialized with
 * wpa_supplicant_ctrl_iface_init() and any data related to the wpa_s instance.
 * @priv may be %NULL if the control interface has not yet been initialized.
 *
 * Required to be implemented in each control interface backend.
 */
void wpa_supplicant_ctrl_iface_deinit(struct wpa_supplicant *wpa_s,
				      struct ctrl_iface_priv *priv);

/**
 * wpa_supplicant_ctrl_iface_wait - Wait for ctrl_iface monitor
 * @priv: Pointer to private data from wpa_supplicant_ctrl_iface_init()
 *
 * Wait until the first message from an external program using the control
 * interface is received. This function can be used to delay normal startup
 * processing to allow control interface programs to attach with
 * %wpa_supplicant before normal operations are started.
 *
 * Required to be implemented in each control interface backend.
 */
void wpa_supplicant_ctrl_iface_wait(struct ctrl_iface_priv *priv);

/**
 * wpa_supplicant_global_ctrl_iface_init - Initialize global control interface
 * @global: Pointer to global data from wpa_supplicant_init()
 * Returns: Pointer to private data on success, %NULL on failure
 *
 * Initialize the global control interface and start receiving commands from
 * external programs.
 *
 * Required to be implemented in each control interface backend.
 */
struct ctrl_iface_global_priv *
wpa_supplicant_global_ctrl_iface_init(struct wpa_global *global);

/**
 * wpa_supplicant_global_ctrl_iface_deinit - Deinitialize global ctrl interface
 * @priv: Pointer to private data from wpa_supplicant_global_ctrl_iface_init()
 *
 * Deinitialize the global control interface that was initialized with
 * wpa_supplicant_global_ctrl_iface_init().
 *
 * Required to be implemented in each control interface backend.
 */
void wpa_supplicant_global_ctrl_iface_deinit(struct ctrl_iface_global_priv *priv);

void wpas_ctrl_radio_work_flush(struct wpa_supplicant *wpa_s);

int wpa_supplicant_ctrl_iface_add_network(struct wpa_supplicant *wpa_s, char *buf, size_t buflen);

int wpa_supplicant_ctrl_iface_remove_network(struct wpa_supplicant *wpa_s, char *cmd);

int wpa_supplicant_ctrl_iface_disable_network(struct wpa_supplicant *wpa_s, char *cmd);

int wpa_supplicant_ctrl_iface_set_network(struct wpa_supplicant *wpa_s, char *cmd);

int wpa_supplicant_ctrl_iface_list_networks(struct wpa_supplicant *wpa_s, char *cmd, char *buf, size_t buflen);

int wpa_supplicant_ctrl_iface_select_network(struct wpa_supplicant *wpa_s, char *cmd);

int wpa_supplicant_ctrl_iface_enable_network(struct wpa_supplicant *wpa_s, char *cmd);

int wpa_supplicant_ctrl_iface_get_network(struct wpa_supplicant *wpa_s, char *cmd, char *buf, size_t buflen);

int wpa_supplicant_ctrl_iface_status(struct wpa_supplicant *wpa_s, const char *params, char *buf, size_t buflen);

int wpa_supplicant_global_iface_add(struct wpa_global *global, char *cmd);

int wpa_supplicant_global_iface_remove(struct wpa_global *global, char *cmd);

void wpas_ctrl_scan(struct wpa_supplicant *wpa_s, char *params, char *reply, int reply_size, int *reply_len);

int wpa_supplicant_ctrl_iface_scan_results(struct wpa_supplicant *wpa_s, char *buf, size_t buflen);

int p2p_ctrl_set(struct wpa_supplicant *wpa_s, char *cmd);
int wpa_supplicant_ctrl_iface_set(struct wpa_supplicant *wpa_s, char *cmd);
int p2p_ctrl_find(struct wpa_supplicant *wpa_s, char *cmd);
int p2p_ctrl_prov_disc(struct wpa_supplicant *wpa_s, char *cmd);
int p2p_ctrl_group_add(struct wpa_supplicant *wpa_s, char *cmd);
int p2p_ctrl_service_add(struct wpa_supplicant *wpa_s, char *cmd);
int p2p_ctrl_service_del(struct wpa_supplicant *wpa_s, char *cmd);
void p2p_ctrl_flush(struct wpa_supplicant *wpa_s);
int p2p_ctrl_invite(struct wpa_supplicant *wpa_s, char *cmd);
int p2p_ctrl_ext_listen(struct wpa_supplicant *wpa_s, char *cmd);
int p2p_ctrl_serv_disc_req(struct wpa_supplicant *wpa_s, char *cmd, char *buf, size_t buflen);
int p2p_ctrl_serv_disc_cancel_req(struct wpa_supplicant *wpa_s, char *cmd);
int p2p_ctrl_serv_disc_external(struct wpa_supplicant *wpa_s, char *cmd);
int p2p_ctrl_serv_disc_resp(struct wpa_supplicant *wpa_s, char *cmd);
int p2p_ctrl_connect(struct wpa_supplicant *wpa_s, char *cmd, char *buf, size_t buflen);
int p2p_ctrl_peer(struct wpa_supplicant *wpa_s, char *cmd, char *buf, size_t buflen);
int magiclink_p2p_ctrl_connect(struct wpa_supplicant *wpa_s, char *cmd);
int p2p_wifi_display_subelem_set(struct wpa_global *global, char *cmd);

#ifndef CONFIG_NO_CONFIG_WRITE
int wpa_supplicant_ctrl_iface_save_config(struct wpa_supplicant *wpa_s);
#endif

#ifdef CONFIG_WPS
int wpa_supplicant_ctrl_iface_wps_pbc(struct wpa_supplicant *wpa_s,  char *cmd);
int wpa_supplicant_ctrl_iface_wps_pin(struct wpa_supplicant *wpa_s, char *cmd, char *buf, size_t buflen);
#endif

int wpa_supplicant_driver_cmd(struct wpa_supplicant *wpa_s, char *cmd, char *buf, size_t buflen);

#ifdef CONFIG_MAGICLINK
int hw_magiclink_ctrl_iface_update_network(
	struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
	char *name, char *value);
#endif /* CONFIG_MAGICLINK */

#else /* CONFIG_CTRL_IFACE */

static inline struct ctrl_iface_priv *
wpa_supplicant_ctrl_iface_init(struct wpa_supplicant *wpa_s)
{
	return (void *) -1;
}

static inline void
wpa_supplicant_ctrl_iface_deinit(struct wpa_supplicant *wpa_s,
				 struct ctrl_iface_priv *priv)
{
}

static inline void
wpa_supplicant_ctrl_iface_send(struct ctrl_iface_priv *priv, int level,
			       char *buf, size_t len)
{
}

static inline void
wpa_supplicant_ctrl_iface_wait(struct ctrl_iface_priv *priv)
{
}

static inline struct ctrl_iface_global_priv *
wpa_supplicant_global_ctrl_iface_init(struct wpa_global *global)
{
	return (void *) 1;
}

static inline void
wpa_supplicant_global_ctrl_iface_deinit(struct ctrl_iface_global_priv *priv)
{
}

static inline void wpas_ctrl_radio_work_flush(struct wpa_supplicant *wpa_s)
{
}

#endif /* CONFIG_CTRL_IFACE */

#ifdef CONFIG_HUAWEI_WIFI_RPT
#if defined(CONFIG_OPEN_HARMONY_PATCH) && defined(OPEN_HARMONY_MIRACAST_SINK_OPT)
int channel_to_frequency(int chan, int band);
#endif
#endif

#endif /* CTRL_IFACE_H */
