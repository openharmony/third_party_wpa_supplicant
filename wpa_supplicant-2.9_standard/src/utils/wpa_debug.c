/*
 * wpa_supplicant/hostapd / Debug prints
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <time.h>

#include "common.h"

#ifdef CONFIG_DEBUG_SYSLOG
#include <syslog.h>
#endif /* CONFIG_DEBUG_SYSLOG */

#ifdef CONFIG_DEBUG_LINUX_TRACING
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static FILE *wpa_debug_tracing_file = NULL;

#define WPAS_TRACE_PFX "wpas <%d>: "
#endif /* CONFIG_DEBUG_LINUX_TRACING */

#define HIDDEN_CHAR '*'
int wpa_debug_level = MSG_DEBUG;
int wpa_debug_show_keys = 1;
int wpa_debug_timestamp = 0;
int wpa_debug_syslog = 0;
#ifndef CONFIG_NO_STDOUT_DEBUG
static FILE *out_file = NULL;
#endif /* CONFIG_NO_STDOUT_DEBUG */


#ifdef CONFIG_ANDROID_LOG

#include <android/log.h>

#ifndef ANDROID_LOG_NAME
#define ANDROID_LOG_NAME	"wpa_supplicant"
#endif /* ANDROID_LOG_NAME */

static int wpa_to_android_level(int level)
{
	if (level == MSG_ERROR)
		return ANDROID_LOG_ERROR;
	if (level == MSG_WARNING)
		return ANDROID_LOG_WARN;
	if (level == MSG_INFO)
		return ANDROID_LOG_INFO;
	return ANDROID_LOG_DEBUG;
}

#endif /* CONFIG_ANDROID_LOG */

#ifndef CONFIG_NO_STDOUT_DEBUG

#ifdef CONFIG_DEBUG_FILE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif /* CONFIG_DEBUG_FILE */
#define WPA_MAX_ANONYMIZE_LENGTH 256

#ifndef WPA_MAX_TOKEN_LEN
#define WPA_MAX_TOKEN_LEN 5
#endif /* WPA_MAX_TOKEN_LEN */


void wpa_debug_print_timestamp(void)
{
#ifndef CONFIG_ANDROID_LOG
	struct os_time tv;

	if (!wpa_debug_timestamp)
		return;

	os_get_time(&tv);
#ifdef CONFIG_DEBUG_FILE
	if (out_file)
		fprintf(out_file, "%ld.%06u: ", (long) tv.sec,
			(unsigned int) tv.usec);
#endif /* CONFIG_DEBUG_FILE */
	if (!out_file && !wpa_debug_syslog)
		printf("%ld.%06u: ", (long) tv.sec, (unsigned int) tv.usec);
#endif /* CONFIG_ANDROID_LOG */
}


#ifdef CONFIG_DEBUG_SYSLOG
#ifndef LOG_HOSTAPD
#define LOG_HOSTAPD LOG_DAEMON
#endif /* LOG_HOSTAPD */

void wpa_debug_open_syslog(void)
{
	openlog("wpa_supplicant", LOG_PID | LOG_NDELAY, LOG_HOSTAPD);
	wpa_debug_syslog++;
}


void wpa_debug_close_syslog(void)
{
	if (wpa_debug_syslog)
		closelog();
}


static int syslog_priority(int level)
{
	switch (level) {
	case MSG_MSGDUMP:
	case MSG_DEBUG:
		return LOG_DEBUG;
	case MSG_INFO:
		return LOG_NOTICE;
	case MSG_WARNING:
		return LOG_WARNING;
	case MSG_ERROR:
		return LOG_ERR;
	}
	return LOG_INFO;
}
#endif /* CONFIG_DEBUG_SYSLOG */


#ifdef CONFIG_DEBUG_LINUX_TRACING

int wpa_debug_open_linux_tracing(void)
{
	int mounts, trace_fd;
	char buf[4096] = {};
	ssize_t buflen;
	char *line, *tmp1, *path = NULL;

	mounts = open("/proc/mounts", O_RDONLY);
	if (mounts < 0) {
		printf("no /proc/mounts\n");
		return -1;
	}

	buflen = read(mounts, buf, sizeof(buf) - 1);
	close(mounts);
	if (buflen < 0) {
		printf("failed to read /proc/mounts\n");
		return -1;
	}
	buf[buflen] = '\0';

	line = strtok_r(buf, "\n", &tmp1);
	while (line) {
		char *tmp2, *tmp_path, *fstype;
		/* "<dev> <mountpoint> <fs type> ..." */
		strtok_r(line, " ", &tmp2);
		tmp_path = strtok_r(NULL, " ", &tmp2);
		fstype = strtok_r(NULL, " ", &tmp2);
		if (fstype && strcmp(fstype, "debugfs") == 0) {
			path = tmp_path;
			break;
		}

		line = strtok_r(NULL, "\n", &tmp1);
	}

	if (path == NULL) {
		printf("debugfs mountpoint not found\n");
		return -1;
	}

	snprintf(buf, sizeof(buf) - 1, "%s/tracing/trace_marker", path);

	trace_fd = open(buf, O_WRONLY);
	if (trace_fd < 0) {
		printf("failed to open trace_marker file\n");
		return -1;
	}
	wpa_debug_tracing_file = fdopen(trace_fd, "w");
	if (wpa_debug_tracing_file == NULL) {
		close(trace_fd);
		printf("failed to fdopen()\n");
		return -1;
	}

	return 0;
}


void wpa_debug_close_linux_tracing(void)
{
	if (wpa_debug_tracing_file == NULL)
		return;
	fclose(wpa_debug_tracing_file);
	wpa_debug_tracing_file = NULL;
}

#endif /* CONFIG_DEBUG_LINUX_TRACING */

#ifdef CONFIG_OPEN_HARMONY_PATCH
#include "hilog/log.h"
#include "parameter.h"

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif // LOG_DOMAIN
#ifdef LOG_TAG
#undef LOG_TAG
#endif // LOG_TAG
#define LOG_DOMAIN 0xD005200
#define LOG_TAG "wpa_supplicant"
#define WPA_MAX_LOG_CHAR 8196
#define WPA_PROP_KEY_DEBUG_ON "persist.sys.wpa_debug_on"
#define PARAM_VALUE_MAX_LEN 10

enum {
	WPA_HILOG_UNKNOWN, WPA_HILOG_UNSET, WPA_HILOG_SET
};

int32_t wpa_debug_hilog_switch = WPA_HILOG_UNKNOWN;

static bool wpa_can_hilog()
{
	switch (wpa_debug_hilog_switch) {
		case WPA_HILOG_UNSET:
			return false;
		case WPA_HILOG_SET:
			return true;
		default:
			break;
	}

	wpa_debug_hilog_switch = WPA_HILOG_SET;
	return true;
}
#endif // CONFIG_OPEN_HARMONY_PATCH

static int is_char_hexadecimal(char *for_check)
{
	if ((('0' <= *for_check) && ('9' >= *for_check)) || (('a' <= *for_check) && ('f' >= *for_check))
		|| (('A' <= *for_check) && ('F' >= *for_check))) {
		return 1;
	}
	return 0;
}

static int is_symbol_logical(char *for_check, size_t i)
{
	const int macIndexThr = 3;
	const int macIndexSix = 6;
	const int macIndexNine = 9;
	const int macIndexTwelve = 12;
	if ((':' == *(for_check + i)) && (':' == *(for_check + i + macIndexThr)) 
		&& (':' == *(for_check + i + macIndexSix)) && (':' == *(for_check + i + macIndexNine)) 
	    && (':' == *(for_check + i + macIndexTwelve))) {
		return 1;
	}
	return 0;
}

static void change_mac_address(char *input)
{
	const int operandsThree = 3;
	const int operandsNine = 9;
	const int operandsFourteen = 14;
	const int operandsFifteen = 15;
	const int macMaxLen = 17;
	if (input == NULL) {
		return;
	}
	size_t len = strlen(input);
	if (len < macMaxLen) {
		return;
	}
	size_t i = 2;
	while ('\0' != *(input + i + operandsFourteen)) {
		int is_mac_address = 1;
		if (is_symbol_logical(input, i)) {
			int j = -2;
			while (operandsFifteen != j) {
				if (0 == j % operandsThree) {
					++j;
					continue;
				}
				if (is_char_hexadecimal(input + i + j)) {
					++j;
					continue;
				} else {
					++j;
					is_mac_address = 0;
					break;
				}
			}
		} else {
			is_mac_address = 0;
		}
		if (!is_mac_address) {
			++i;
		} else {
			int m =1;
			while (operandsNine != m) {
				if (0 == m % operandsThree) {
					++m;
					continue;
				} else {
					*(input + i + m) = '*';
					++m;
				}
			}
			if (i + macMaxLen + operandsFifteen > len) {
				break;
			} else {
				i += macMaxLen;
			}
		}
	}
	return;
}

/**
 * wpa_printf - conditional printf
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration.
 *
 * Note: New line '\n' is added to the end of the text when printing to stdout.
 */
void wpa_printf(int level, const char *fmt, ...)
{
#ifdef CONFIG_OPEN_HARMONY_PATCH
	if (wpa_can_hilog()) {
		int32_t ulPos = 0;
		char szStr[WPA_MAX_LOG_CHAR] = {0};
		va_list arg = {0};
		int32_t ret;

		va_start(arg, fmt);
		ret = vsprintf(&szStr[ulPos], fmt, arg);
		if (!disable_anonymized_print()) {
			change_mac_address(szStr);
		}
		va_end(arg);
		if (ret > 0) {
			switch (level) {
				case MSG_ERROR:
					HILOG_ERROR(LOG_CORE, "%{public}s", szStr);
					break;
				case MSG_WARNING:
					HILOG_WARN(LOG_CORE, "%{public}s", szStr);
					break;
				case MSG_INFO:
					HILOG_INFO(LOG_CORE, "%{public}s", szStr);
					break;
				default:
					HILOG_DEBUG(LOG_CORE, "%{public}s", szStr);
					break;
			}
		}
		return;
	}
#endif

#ifdef CONFIG_WPA_NO_LOG
    return;
#else
	va_list ap;

	if (level >= wpa_debug_level) {
#ifdef CONFIG_ANDROID_LOG
		va_start(ap, fmt);
		__android_log_vprint(wpa_to_android_level(level),
				     ANDROID_LOG_NAME, fmt, ap);
		va_end(ap);
#else /* CONFIG_ANDROID_LOG */
#ifdef CONFIG_DEBUG_SYSLOG
		if (wpa_debug_syslog) {
			va_start(ap, fmt);
			vsyslog(syslog_priority(level), fmt, ap);
			va_end(ap);
		}
#endif /* CONFIG_DEBUG_SYSLOG */
		wpa_debug_print_timestamp();
#ifdef CONFIG_DEBUG_FILE
		if (out_file) {
			va_start(ap, fmt);
			vfprintf(out_file, fmt, ap);
			fprintf(out_file, "\n");
			va_end(ap);
		}
#endif /* CONFIG_DEBUG_FILE */
		if (!wpa_debug_syslog && !out_file) {
			va_start(ap, fmt);
			vprintf(fmt, ap);
			printf("\n");
			va_end(ap);
		}
#endif /* CONFIG_ANDROID_LOG */
	}

#ifdef CONFIG_DEBUG_LINUX_TRACING
	if (wpa_debug_tracing_file != NULL) {
		va_start(ap, fmt);
		fprintf(wpa_debug_tracing_file, WPAS_TRACE_PFX, level);
		vfprintf(wpa_debug_tracing_file, fmt, ap);
		fprintf(wpa_debug_tracing_file, "\n");
		fflush(wpa_debug_tracing_file);
		va_end(ap);
	}
#endif /* CONFIG_DEBUG_LINUX_TRACING */
#endif /* CONFIG_WPA_NO_LOG */
}


static void _wpa_hexdump(int level, const char *title, const u8 *buf,
			 size_t len, int show, int only_syslog)
{
#ifdef CONFIG_WPA_NO_LOG
    return;
#else
	size_t i;
#ifdef CONFIG_OPEN_HARMONY_PATCH
	if (wpa_can_hilog()) {
		const char *display;
		char *strbuf = NULL;
		size_t slen = len;
		if (buf == NULL) {
			display = " [NULL]";
		} else if (len == 0) {
			display = "";
		} else if (show && len) {
			if (slen > 32)
				slen = 32;
			strbuf = os_malloc(1 + 3 * slen);
			if (strbuf == NULL) {
				wpa_printf(MSG_ERROR, "wpa_hexdump: Failed to "
				                      "allocate message buffer");
				return;
			}

			for (i = 0; i < slen; i++)
				os_snprintf(&strbuf[i * 3], 4, " %02x",
				            buf[i]);

			display = strbuf;
		} else {
			display = " [REMOVED]";
		}
		switch (level) {
			case MSG_ERROR:
				HILOG_ERROR(LOG_CORE, "%{public}s - hexdump(len=%{public}lu):%{public}s%{public}s",
					title, (long unsigned int) len, display, len > slen ? " ..." : "");
				break;
			case MSG_WARNING:
				HILOG_WARN(LOG_CORE, "%{public}s - hexdump(len=%{public}lu):%{public}s%{public}s",
					title, (long unsigned int) len, display, len > slen ? " ..." : "");
				break;
			case MSG_INFO:
				HILOG_INFO(LOG_CORE, "%{public}s - hexdump(len=%{public}lu):%{public}s%{public}s",
					title, (long unsigned int) len, display, len > slen ? " ..." : "");
				break;
			default:
				HILOG_DEBUG(LOG_CORE, "%{public}s - hexdump(len=%{public}lu):%{public}s%{public}s",
					title, (long unsigned int) len, display, len > slen ? " ..." : "");
				break;
		}
		bin_clear_free(strbuf, 1 + 3 * slen);
		return;
	}
#endif

#ifdef CONFIG_DEBUG_LINUX_TRACING
	if (wpa_debug_tracing_file != NULL) {
		fprintf(wpa_debug_tracing_file,
			WPAS_TRACE_PFX "%s - hexdump(len=%lu):",
			level, title, (unsigned long) len);
		if (buf == NULL) {
			fprintf(wpa_debug_tracing_file, " [NULL]\n");
		} else if (!show) {
			fprintf(wpa_debug_tracing_file, " [REMOVED]\n");
		} else {
			for (i = 0; i < len; i++)
				fprintf(wpa_debug_tracing_file,
					" %02x", buf[i]);
		}
		fflush(wpa_debug_tracing_file);
	}
#endif /* CONFIG_DEBUG_LINUX_TRACING */

	if (level < wpa_debug_level)
		return;
#ifdef CONFIG_ANDROID_LOG
	{
		const char *display;
		char *strbuf = NULL;
		size_t slen = len;
		if (buf == NULL) {
			display = " [NULL]";
		} else if (len == 0) {
			display = "";
		} else if (show && len) {
			/* Limit debug message length for Android log */
			if (slen > 32)
				slen = 32;
			strbuf = os_malloc(1 + 3 * slen);
			if (strbuf == NULL) {
				wpa_printf(MSG_ERROR, "wpa_hexdump: Failed to "
					   "allocate message buffer");
				return;
			}

			for (i = 0; i < slen; i++)
				os_snprintf(&strbuf[i * 3], 4, " %02x",
					    buf[i]);

			display = strbuf;
		} else {
			display = " [REMOVED]";
		}

		__android_log_print(wpa_to_android_level(level),
				    ANDROID_LOG_NAME,
				    "%s - hexdump(len=%lu):%s%s",
				    title, (long unsigned int) len, display,
				    len > slen ? " ..." : "");
		bin_clear_free(strbuf, 1 + 3 * slen);
		return;
	}
#else /* CONFIG_ANDROID_LOG */
#ifdef CONFIG_DEBUG_SYSLOG
	if (wpa_debug_syslog) {
		const char *display;
		char *strbuf = NULL;

		if (buf == NULL) {
			display = " [NULL]";
		} else if (len == 0) {
			display = "";
		} else if (show && len) {
			strbuf = os_malloc(1 + 3 * len);
			if (strbuf == NULL) {
				wpa_printf(MSG_ERROR, "wpa_hexdump: Failed to "
					   "allocate message buffer");
				return;
			}

			for (i = 0; i < len; i++)
				os_snprintf(&strbuf[i * 3], 4, " %02x",
					    buf[i]);

			display = strbuf;
		} else {
			display = " [REMOVED]";
		}

		syslog(syslog_priority(level), "%s - hexdump(len=%lu):%s",
		       title, (unsigned long) len, display);
		bin_clear_free(strbuf, 1 + 3 * len);
		if (only_syslog)
			return;
	}
#endif /* CONFIG_DEBUG_SYSLOG */
	wpa_debug_print_timestamp();
#ifdef CONFIG_DEBUG_FILE
	if (out_file) {
		fprintf(out_file, "%s - hexdump(len=%lu):",
			title, (unsigned long) len);
		if (buf == NULL) {
			fprintf(out_file, " [NULL]");
		} else if (show) {
			for (i = 0; i < len; i++)
				fprintf(out_file, " %02x", buf[i]);
		} else {
			fprintf(out_file, " [REMOVED]");
		}
		fprintf(out_file, "\n");
	}
#endif /* CONFIG_DEBUG_FILE */
	if (!wpa_debug_syslog && !out_file) {
		printf("%s - hexdump(len=%lu):", title, (unsigned long) len);
		if (buf == NULL) {
			printf(" [NULL]");
		} else if (show) {
			for (i = 0; i < len; i++)
				printf(" %02x", buf[i]);
		} else {
			printf(" [REMOVED]");
		}
		printf("\n");
	}
#endif /* CONFIG_ANDROID_LOG */
#endif /* CONFIG_WPA_NO_LOG */
}

int disable_anonymized_print()
{
	char prop[PARAM_VALUE_MAX_LEN] = { 0 };
	if (GetParameter(WPA_PROP_KEY_DEBUG_ON, "0", prop, sizeof(prop)) > 0) {
		if (atoi(prop) > 0) {
			return 1;
		}
	}
	return 0;
}

long get_realtime_microsecond()
{
	struct timespec ts = {0};

	clock_gettime(CLOCK_REALTIME, &ts);
	long microseconds = ts.tv_nsec / 1000;
	return microseconds;
}

const char *anonymize_ssid(const char *str)
{
	if (str == NULL || *str == '\0') {
		return str;
	}

	static char s[WPA_MAX_ANONYMIZE_LENGTH];
	int strLen = os_strlen(str);
	os_strlcpy(s, str, sizeof(s));

	if (disable_anonymized_print()) {
		return s;
	}
	const char hiddenChar = HIDDEN_CHAR;
	const int minHiddenSize = 3;
	const int headKeepSize = 3;
	const int tailKeepSize = 3;

	if (strLen < minHiddenSize) {
		os_memset(s, hiddenChar, strLen);
		return s;
	}

	if (strLen < minHiddenSize + headKeepSize + tailKeepSize) {
		int beginIndex = 1;
		int hiddenSize = strLen - minHiddenSize + 1;
		hiddenSize = hiddenSize > minHiddenSize ? minHiddenSize : hiddenSize;
		os_memset(s + beginIndex, hiddenChar, hiddenSize);
		return s;
	}
	os_memset(s + headKeepSize, hiddenChar, strLen - headKeepSize - tailKeepSize);
	return s;
}

const char *anonymize_token(const u8 num)
{
    int res;
    static char str[WPA_MAX_TOKEN_LEN] = { 0 };
    res = os_snprintf(str, WPA_MAX_TOKEN_LEN, "%u", num);
    if (os_snprintf_error(WPA_MAX_TOKEN_LEN, res)) {
        wpa_printf(MSG_ERROR, "anonymize_token: Failed %d", res);
        return str;
    }
    return anonymize_common(str);
}

const char *anonymize_common(const char *str)
{
	static char temp[WPA_MAX_ANONYMIZE_LENGTH] = { 0 };

	if (str == NULL || *str == '\0') {
		return temp;
	}
	int strLen = os_strlen(str);
	os_strlcpy(temp, str, sizeof(temp));

	if (disable_anonymized_print()) {
		return temp;
	}
	const char hiddenChar = HIDDEN_CHAR;
	const int minHiddenSize = 3;
	const int headKeepSize = 3;
	const int tailKeepSize = 3;

	if (strLen < minHiddenSize) {
		os_memset(temp, hiddenChar, strLen);
		return temp;
	}

	if (strLen < minHiddenSize + headKeepSize + tailKeepSize) {
		int beginIndex = 1;
		int hiddenSize = strLen - minHiddenSize + 1;
		hiddenSize = hiddenSize > minHiddenSize ? minHiddenSize : hiddenSize;
		os_memset(temp + beginIndex, hiddenChar, hiddenSize);
		return temp;
	}
	os_memset(temp + headKeepSize, hiddenChar, strLen - headKeepSize - tailKeepSize);
	return temp;
}

const char *anonymize_ip(const char *str)
{
	if (str == NULL || *str == '\0') {
		return str;
	}
	int colonCount = 0;
	const int maxDisplayNum = 2;
	static char s[40];
	int start = 0;
	os_strlcpy(s, str, sizeof(s));
	if (disable_anonymized_print()) {
		return s;
	}
	// ipv4 or ipv6 anonymize
	for (int i = 0; i < os_strlen(s); i++) {
		if (s[i] == ':' || s[i] == '.') {
			colonCount++;
			if (colonCount == maxDisplayNum) {
				start = i + 1;
			}
		}
	}
	for (int j = start; j < os_strlen(s); j++) {
		if (s[j] != ':' && s[j] != '.') {
			s[j] = HIDDEN_CHAR;
		}
	}
	return s;
}


const char *get_anonymized_result_setnetwork(const char *str)
{
	if (str == NULL || *str == '\0') {
		return str;
	}
	static char cmd[WPA_MAX_ANONYMIZE_LENGTH];
	os_strlcpy(cmd, str, sizeof(cmd));
	if (disable_anonymized_print()) {
		return cmd;
	}
	// cmd include ssid or identity
	if (os_strchr(cmd, '\"') && (os_strstr(cmd, "ssid") || os_strstr(cmd, "identity"))) {
		char tempssid[WPA_MAX_ANONYMIZE_LENGTH];
		os_strlcpy(tempssid, os_strchr(cmd, '\"') + 1, sizeof(tempssid));
		tempssid[os_strrchr(cmd, '\"') - os_strchr(cmd, '\"') - 1] = '\0';
		static char tempStr[WPA_MAX_ANONYMIZE_LENGTH];
		char *strOfStrtok = strtok(cmd, "\"");
		if (strOfStrtok == NULL) {
			return cmd;
		}
		os_strlcpy(tempStr, strOfStrtok, sizeof(tempStr));
		os_snprintf(cmd, sizeof(cmd), "%s\"%s\"", tempStr, anonymize_ssid(tempssid));
		return cmd;
	}
	//cmd include password or psk
	if (os_strchr(cmd, '\"') && (os_strstr(cmd, "password") || os_strstr(cmd, "psk"))) {
		char tempNumbel[WPA_MAX_ANONYMIZE_LENGTH];
		os_strlcpy(tempNumbel, os_strchr(cmd, '\"') + 1, sizeof(tempNumbel));
		tempNumbel[os_strrchr(cmd, '\"') - os_strchr(cmd, '\"') - 1] = '\0';
		for (int i = 0; i < os_strlen(tempNumbel); i++) {
			tempNumbel[i] = HIDDEN_CHAR;
		}
		static char tempStr[WPA_MAX_ANONYMIZE_LENGTH];
		char *strOfStrtok = strtok(cmd, "\"");
		if (strOfStrtok == NULL) {
			return cmd;
		}
		os_strlcpy(tempStr, strOfStrtok, sizeof(tempStr));
		os_snprintf(cmd, sizeof(cmd), "%s\"%s\"", tempStr, tempNumbel);
		os_memset(tempNumbel, 0, sizeof(tempNumbel));
		return cmd;
	}
	return cmd;
}

const char *get_anonymized_result_setnetwork_for_bssid(const char *str)
{
	if (str == NULL || *str == '\0') {
		return str;
	}
	static const int colonCountNum = 2;
	static const int maxHiddenNum = 9;
	static char cmd[WPA_MAX_ANONYMIZE_LENGTH];
	os_strlcpy(cmd, str, sizeof(cmd));
	if (disable_anonymized_print()) {
		return cmd;
	}
	//cmd include bssid
	if (os_strchr(cmd, ':')) {
		int colonCount = 0;
		int start = 0;
		for (int j = 0; j < os_strlen(cmd); j++) {
			if (cmd[j] == ':') {
				colonCount++;
			}
			if (colonCount == colonCountNum) {
				start = j + 1;
				break;
			}
		}
		if (colonCount != colonCountNum) {
			return cmd;
		}
		for (int k = start; k < start + maxHiddenNum; k++) {
			if (cmd[k] != ':') {
				cmd[k] = HIDDEN_CHAR;
			}
		}
		return cmd;
	}
	return cmd;
}

const char *get_anonymized_result_for_set(const char *str)
{
	if (str == NULL || *str == '\0') {
		return str;
	}
	static char cmd[WPA_MAX_ANONYMIZE_LENGTH];
	os_strlcpy(cmd, str, sizeof(cmd));
	if (disable_anonymized_print()) {
		return cmd;
	}
	if (os_strstr(cmd, "wpa_passphrase")) {
		char *value = os_strchr(cmd, ' ') + 1;
		if (value == NULL) {
			return cmd;
		}
		os_memset(value, HIDDEN_CHAR, os_strlen(value));
		return cmd;
	} else if (os_strstr(cmd, "ssid")) {
		char *value = os_strchr(cmd, ' ') + 1;
		os_snprintf(cmd, sizeof(cmd), "ssid=%s", anonymize_ssid(value));
		return cmd;
	} else if (os_strstr(cmd, "P2P_CONNECT")) {
		char *value = os_strchr(cmd, ' ') + 1;
		if (value == NULL) {
			return cmd;
		}
		os_snprintf(cmd, sizeof(cmd), "P2P_CONNECT=%s", get_anonymized_result_setnetwork_for_bssid(value));
		return cmd;
	}
	return cmd;
}

void wpa_hexdump(int level, const char *title, const void *buf, size_t len)
{
	_wpa_hexdump(level, title, buf, len, 1, 0);
}


void wpa_hexdump_key(int level, const char *title, const void *buf, size_t len)
{
	_wpa_hexdump(level, title, buf, len, wpa_debug_show_keys, 0);
}


static void _wpa_hexdump_ascii(int level, const char *title, const void *buf,
			       size_t len, int show)
{
#ifdef CONFIG_WPA_NO_LOG
    return;
#else
	size_t i, llen;
	const u8 *pos = buf;
	const size_t line_len = 16;

#ifdef CONFIG_DEBUG_LINUX_TRACING
	if (wpa_debug_tracing_file != NULL) {
		fprintf(wpa_debug_tracing_file,
			WPAS_TRACE_PFX "%s - hexdump_ascii(len=%lu):",
			level, title, (unsigned long) len);
		if (buf == NULL) {
			fprintf(wpa_debug_tracing_file, " [NULL]\n");
		} else if (!show) {
			fprintf(wpa_debug_tracing_file, " [REMOVED]\n");
		} else {
			/* can do ascii processing in userspace */
			for (i = 0; i < len; i++)
				fprintf(wpa_debug_tracing_file,
					" %02x", pos[i]);
		}
		fflush(wpa_debug_tracing_file);
	}
#endif /* CONFIG_DEBUG_LINUX_TRACING */

	if (level < wpa_debug_level)
		return;
#ifdef CONFIG_ANDROID_LOG
	_wpa_hexdump(level, title, buf, len, show, 0);
#else /* CONFIG_ANDROID_LOG */
#ifdef CONFIG_DEBUG_SYSLOG
	if (wpa_debug_syslog)
		_wpa_hexdump(level, title, buf, len, show, 1);
#endif /* CONFIG_DEBUG_SYSLOG */
	wpa_debug_print_timestamp();
#ifdef CONFIG_DEBUG_FILE
	if (out_file) {
		if (!show) {
			fprintf(out_file,
				"%s - hexdump_ascii(len=%lu): [REMOVED]\n",
				title, (unsigned long) len);
			goto file_done;
		}
		if (buf == NULL) {
			fprintf(out_file,
				"%s - hexdump_ascii(len=%lu): [NULL]\n",
				title, (unsigned long) len);
			goto file_done;
		}
		fprintf(out_file, "%s - hexdump_ascii(len=%lu):\n",
			title, (unsigned long) len);
		while (len) {
			llen = len > line_len ? line_len : len;
			fprintf(out_file, "    ");
			for (i = 0; i < llen; i++)
				fprintf(out_file, " %02x", pos[i]);
			for (i = llen; i < line_len; i++)
				fprintf(out_file, "   ");
			fprintf(out_file, "   ");
			for (i = 0; i < llen; i++) {
				if (isprint(pos[i]))
					fprintf(out_file, "%c", pos[i]);
				else
					fprintf(out_file, "_");
			}
			for (i = llen; i < line_len; i++)
				fprintf(out_file, " ");
			fprintf(out_file, "\n");
			pos += llen;
			len -= llen;
		}
	}
file_done:
#endif /* CONFIG_DEBUG_FILE */
	if (!wpa_debug_syslog && !out_file) {
		if (!show) {
			printf("%s - hexdump_ascii(len=%lu): [REMOVED]\n",
			       title, (unsigned long) len);
			return;
		}
		if (buf == NULL) {
			printf("%s - hexdump_ascii(len=%lu): [NULL]\n",
			       title, (unsigned long) len);
			return;
		}
		printf("%s - hexdump_ascii(len=%lu):\n", title,
		       (unsigned long) len);
		while (len) {
			llen = len > line_len ? line_len : len;
			printf("    ");
			for (i = 0; i < llen; i++)
				printf(" %02x", pos[i]);
			for (i = llen; i < line_len; i++)
				printf("   ");
			printf("   ");
			for (i = 0; i < llen; i++) {
				if (isprint(pos[i]))
					printf("%c", pos[i]);
				else
					printf("_");
			}
			for (i = llen; i < line_len; i++)
				printf(" ");
			printf("\n");
			pos += llen;
			len -= llen;
		}
	}
#endif /* CONFIG_ANDROID_LOG */
#endif /* CONFIG_WPA_NO_LOG */
}


void wpa_hexdump_ascii(int level, const char *title, const void *buf,
		       size_t len)
{
	_wpa_hexdump_ascii(level, title, buf, len, 1);
}


void wpa_hexdump_ascii_key(int level, const char *title, const void *buf,
			   size_t len)
{
	_wpa_hexdump_ascii(level, title, buf, len, wpa_debug_show_keys);
}


#ifdef CONFIG_DEBUG_FILE
static char *last_path = NULL;
#endif /* CONFIG_DEBUG_FILE */

int wpa_debug_reopen_file(void)
{
#ifdef CONFIG_DEBUG_FILE
	int rv;
	char *tmp;

	if (!last_path)
		return 0; /* logfile not used */

	tmp = os_strdup(last_path);
	if (!tmp)
		return -1;

	wpa_debug_close_file();
	rv = wpa_debug_open_file(tmp);
	os_free(tmp);
	return rv;
#else /* CONFIG_DEBUG_FILE */
	return 0;
#endif /* CONFIG_DEBUG_FILE */
}


int wpa_debug_open_file(const char *path)
{
#ifdef CONFIG_DEBUG_FILE
	int out_fd;

	if (!path)
		return 0;

	if (last_path == NULL || os_strcmp(last_path, path) != 0) {
		/* Save our path to enable re-open */
		os_free(last_path);
		last_path = os_strdup(path);
	}

	out_fd = open(path, O_CREAT | O_APPEND | O_WRONLY,
		      S_IRUSR | S_IWUSR | S_IRGRP);
	if (out_fd < 0) {
		wpa_printf(MSG_ERROR,
			   "%s: Failed to open output file descriptor, using standard output",
			   __func__);
		return -1;
	}

#ifdef __linux__
	if (fcntl(out_fd, F_SETFD, FD_CLOEXEC) < 0) {
		wpa_printf(MSG_DEBUG,
			   "%s: Failed to set FD_CLOEXEC - continue without: %s",
			   __func__, strerror(errno));
	}
#endif /* __linux__ */

	out_file = fdopen(out_fd, "a");
	if (out_file == NULL) {
		wpa_printf(MSG_ERROR, "wpa_debug_open_file: Failed to open "
			   "output file, using standard output");
		close(out_fd);
		return -1;
	}
#ifndef _WIN32
	setvbuf(out_file, NULL, _IOLBF, 0);
#endif /* _WIN32 */
#else /* CONFIG_DEBUG_FILE */
	(void)path;
#endif /* CONFIG_DEBUG_FILE */
	return 0;
}


void wpa_debug_stop_log(void)
{
#ifdef CONFIG_DEBUG_FILE
	if (!out_file)
		return;
	fclose(out_file);
	out_file = NULL;
#endif /* CONFIG_DEBUG_FILE */
}


void wpa_debug_close_file(void)
{
#ifdef CONFIG_DEBUG_FILE
	wpa_debug_stop_log();
	os_free(last_path);
	last_path = NULL;
#endif /* CONFIG_DEBUG_FILE */
}


void wpa_debug_setup_stdout(void) __attribute__((no_sanitize("cfi")))
{
#ifndef _WIN32
	setvbuf(stdout, NULL, _IOLBF, 0);
#endif /* _WIN32 */
}

#endif /* CONFIG_NO_STDOUT_DEBUG */


#ifndef CONFIG_NO_WPA_MSG
static wpa_msg_cb_func wpa_msg_cb = NULL;

void wpa_msg_register_cb(wpa_msg_cb_func func)
{
	wpa_msg_cb = func;
}


static wpa_msg_get_ifname_func wpa_msg_ifname_cb = NULL;

void wpa_msg_register_ifname_cb(wpa_msg_get_ifname_func func)
{
	wpa_msg_ifname_cb = func;
}


void wpa_msg(void *ctx, int level, const char *fmt, ...) __attribute__((no_sanitize("cfi")))
{
	va_list ap;
	char *buf;
	int buflen;
	int len;
	char prefix[130];

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "wpa_msg: Failed to allocate message "
			   "buffer");
		return;
	}
	va_start(ap, fmt);
	prefix[0] = '\0';
	if (wpa_msg_ifname_cb) {
		const char *ifname = wpa_msg_ifname_cb(ctx);
		if (ifname) {
			int res = os_snprintf(prefix, sizeof(prefix), "%s: ",
					      ifname);
			if (os_snprintf_error(sizeof(prefix), res))
				prefix[0] = '\0';
		}
	}
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	wpa_printf(level, "%s%s", prefix, get_anonymized_result_setnetwork_for_bssid(buf));
	if (wpa_msg_cb)
		wpa_msg_cb(ctx, level, WPA_MSG_PER_INTERFACE, buf, len);
	bin_clear_free(buf, buflen);
}

void wpa_msg_only_for_cb(void *ctx, int level, const char *fmt, ...) __attribute__((no_sanitize("cfi")))
{
	va_list ap;
	char *buf;
	int buflen;
	int len;
	char prefix[130];

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "wpa_msg: Failed to allocate message "
			"buffer");
		return;
	}
	va_start(ap, fmt);
	prefix[0] = '\0';
	if (wpa_msg_ifname_cb) {
		const char *ifname = wpa_msg_ifname_cb(ctx);
		if (ifname) {
			int res = os_snprintf(prefix, sizeof(prefix), "%s: ",
				ifname);
			if (os_snprintf_error(sizeof(prefix), res))
				prefix[0] = '\0';
		}
	}
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	if (wpa_msg_cb)
		wpa_msg_cb(ctx, level, WPA_MSG_PER_INTERFACE, buf, len);
	bin_clear_free(buf, buflen);
}


void wpa_msg_ctrl(void *ctx, int level, const char *fmt, ...) __attribute__((no_sanitize("cfi")))
{
	va_list ap;
	char *buf;
	int buflen;
	int len;

	if (!wpa_msg_cb)
		return;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "wpa_msg_ctrl: Failed to allocate "
			   "message buffer");
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	wpa_msg_cb(ctx, level, WPA_MSG_PER_INTERFACE, buf, len);
	bin_clear_free(buf, buflen);
}


void wpa_msg_global(void *ctx, int level, const char *fmt, ...) __attribute__((no_sanitize("cfi")))
{
	va_list ap;
	char *buf;
	int buflen;
	int len;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "wpa_msg_global: Failed to allocate "
			   "message buffer");
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	if (wpa_msg_cb)
		wpa_msg_cb(ctx, level, WPA_MSG_GLOBAL, buf, len);
	bin_clear_free(buf, buflen);
}


void wpa_msg_global_ctrl(void *ctx, int level, const char *fmt, ...) __attribute__((no_sanitize("cfi")))
{
	va_list ap;
	char *buf;
	int buflen;
	int len;

	if (!wpa_msg_cb)
		return;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR,
			   "wpa_msg_global_ctrl: Failed to allocate message buffer");
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	wpa_msg_cb(ctx, level, WPA_MSG_GLOBAL, buf, len);
	bin_clear_free(buf, buflen);
}


void wpa_msg_no_global(void *ctx, int level, const char *fmt, ...) __attribute__((no_sanitize("cfi")))
{
	va_list ap;
	char *buf;
	int buflen;
	int len;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "wpa_msg_no_global: Failed to allocate "
			   "message buffer");
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	if (wpa_msg_cb)
		wpa_msg_cb(ctx, level, WPA_MSG_NO_GLOBAL, buf, len);
	bin_clear_free(buf, buflen);
}


void wpa_msg_global_only(void *ctx, int level, const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int buflen;
	int len;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "%s: Failed to allocate message buffer",
			   __func__);
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	wpa_printf(level, "%s", get_anonymized_result_setnetwork_for_bssid(buf));
	if (wpa_msg_cb)
		wpa_msg_cb(ctx, level, WPA_MSG_ONLY_GLOBAL, buf, len);
	os_free(buf);
}

#endif /* CONFIG_NO_WPA_MSG */


#ifndef CONFIG_NO_HOSTAPD_LOGGER
static hostapd_logger_cb_func hostapd_logger_cb = NULL;

void hostapd_logger_register_cb(hostapd_logger_cb_func func)
{
	hostapd_logger_cb = func;
}


void hostapd_logger(void *ctx, const u8 *addr, unsigned int module, int level,
		    const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int buflen;
	int len;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "hostapd_logger: Failed to allocate "
			   "message buffer");
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	if (hostapd_logger_cb)
		hostapd_logger_cb(ctx, addr, module, level, buf, len);
	else if (addr)
		wpa_printf(MSG_DEBUG, "hostapd_logger: STA " MACSTR_SEC " - %s",
			   MAC2STR_SEC(addr), get_anonymized_result_setnetwork_for_bssid(buf));
	else
		wpa_printf(MSG_DEBUG, "hostapd_logger: %s", get_anonymized_result_setnetwork_for_bssid(buf));
	bin_clear_free(buf, buflen);
}

void hostapd_logger_only_for_cb(void *ctx, const u8 *addr, unsigned int module, int level,
			const char *fmt, ...)
{
	va_list ap;
	char *buf;
	int buflen;
	int len;

	va_start(ap, fmt);
	buflen = vsnprintf(NULL, 0, fmt, ap) + 1;
	va_end(ap);

	buf = os_malloc(buflen);
	if (buf == NULL) {
		wpa_printf(MSG_ERROR, "hostapd_logger: Failed to allocate "
			"message buffer");
		return;
	}
	va_start(ap, fmt);
	len = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	if (hostapd_logger_cb) {
		hostapd_logger_cb(ctx, addr, module, level, buf, len);
	}
	bin_clear_free(buf, buflen);
}

#endif /* CONFIG_NO_HOSTAPD_LOGGER */


const char * debug_level_str(int level)
{
	switch (level) {
	case MSG_EXCESSIVE:
		return "EXCESSIVE";
	case MSG_MSGDUMP:
		return "MSGDUMP";
	case MSG_DEBUG:
		return "DEBUG";
	case MSG_INFO:
		return "INFO";
	case MSG_WARNING:
		return "WARNING";
	case MSG_ERROR:
		return "ERROR";
	default:
		return "?";
	}
}


int str_to_debug_level(const char *s)
{
	if (os_strcasecmp(s, "EXCESSIVE") == 0)
		return MSG_EXCESSIVE;
	if (os_strcasecmp(s, "MSGDUMP") == 0)
		return MSG_MSGDUMP;
	if (os_strcasecmp(s, "DEBUG") == 0)
		return MSG_DEBUG;
	if (os_strcasecmp(s, "INFO") == 0)
		return MSG_INFO;
	if (os_strcasecmp(s, "WARNING") == 0)
		return MSG_WARNING;
	if (os_strcasecmp(s, "ERROR") == 0)
		return MSG_ERROR;
	return -1;
}
