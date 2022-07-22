ifeq ($(KERNEL_TYPE), linux)
CC = arm-himix410-linux-gcc
AR = arm-himix410-linux-ar
LD=arm-himix410-linux-ld
CFLAGS  := -MMD -O2 -g -w -fsigned-char
else
CC = ../../../../prebuilts/gcc/linux-x86/arm/arm-linux-ohoseabi-gcc/bin/arm-linux-ohoseabi-gcc
AR = ../../../../prebuilts/gcc/linux-x86/arm/arm-linux-ohoseabi-gcc/bin/arm-linux-ohoseabi-ar
CFLAGS  := -flto -MMD -O2 -g -w -fsigned-char
endif

ifeq ($(COMPILER_TYPE), clang)
SYSROOT_PATH ?= ../../../../sysroot
ARCH_CFLAGS ?= --target=arm-liteos-ohos -march=armv7-a -mfloat-abi=softfp
CC := $(COMPILER_DIR)/bin/clang
AR := $(COMPILER_DIR)/bin/llvm-ar
CFLAGS += --sysroot=$(SYSROOT_PATH) $(ARCH_CFLAGS)
CFLAGS += -I$(abspath ../../../../drivers/peripheral/wlan/client/include)
LDFLAGS += --sysroot=$(SYSROOT_PATH) $(ARCH_CFLAGS)
LDFLAGS += -lc
LDFLAGS += -v
endif

#TEST_AP = testap
#TEST_WPA = testwpa

WPA_LDFLAGS = -L$(DEPDIR) -lsec_shared -lrt -lm -lpthread -lhilog_shared -lwifi_driver_client
TEST_LDFLAGS = -L./ -lwpa -L$(DEPDIR) -lsec_shared -lrt -lm -lpthread -lhilog_shared -lwifi_driver_client

WPA_SHARED = libwpa.so
WPA_STATIC = libwpa.a
#OBJS_WPA = test_wpa.o
#OBJS_AP = test_hostapd.o

CDEPS = $(patsubst %.c,%.d,test_wpa.c test_hostapd.c)

ifeq ($(LIB_TYPE), 1)
all : $(WPA_SHARED)
else
all : $(WPA_STATIC)
endif

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(WPA_SHARED) :
ifeq ($(KERNEL_TYPE), linux)
	$(CC)  -O2  -shared -fPIC -Wl,-z,defs objs/*.o -o $@ $(WPA_LDFLAGS) $(LDFLAGS)
else
	$(CC)  -flto -O2  -shared -fPIC -Wl,-z,defs objs/*.o -o $@ $(WPA_LDFLAGS) $(LDFLAGS)
endif

$(WPA_STATIC) :
	$(AR) -crs $@ objs/*.o

$(TEST_WPA) : $(OBJS_WPA)
	$(CC) -o $@ $< $(TEST_LDFLAGS) $(LDFLAGS)
	rm -f $(CDEPS)

$(TEST_AP) : $(OBJS_AP)
	$(CC) -o $@ $< $(TEST_LDFLAGS) $(LDFLAGS)
	rm -f $(CDEPS)


clean:
	rm -f $(WPA_SHARED)
	rm -f $(WPA_STATIC)
	rm -f $(OBJS_AP)
	rm -f $(TEST_AP)
	rm -f $(OBJS_WPA)
	rm -f $(TEST_WPA)
	rm -f $(CDEPS)
