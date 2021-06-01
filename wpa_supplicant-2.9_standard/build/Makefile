#ifeq ($(KERNEL_TYPE), linux)
#CC = arm-himix410-linux-gcc
#AR = arm-himix410-linux-ar
#LD=arm-himix410-linux-ld
#CFLAGS  := -MMD -O2 -g -w -fsigned-char
#else
#CC = ../../../../prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.9/bin/arm-linux-androideabi-gcc
#AR = ../../../../prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.9/bin/arm-linux-androideabi-ar
#CFLAGS  := -flto -MMD -O2 -g -w -fsigned-char
#endif

ifeq ($(COMPILER_TYPE), clang)
CC := $(abspath ../../../../prebuilts/clang/host/linux-x86/clang-r353983c/bin/clang)
AR := $(abspath ../../../../prebuilts/clang/host/linux-x86/clang-r353983c/bin/llvm-ar)
CFLAGS += --target=arm-linux-androideabi
CFLAGS += -march=armv7-a
CFLAGS += -mfloat-abi=softfp
CFLAGS += --sysroot=../../../../${AOSP_LIBS_DIR}/ndk/platforms/current/arch-arm
CFLAGS += -I$(abspath ../../../../drivers/peripheral/wlan/client/include)

LDFLAGS = -fuse-ld=lld
LDFLAGS += --target=arm-linux-androideabi
LDFLAGS += --sysroot=../../../../${AOSP_LIBS_DIR}/ndk/platforms/current/arch-arm
DEPDIR_LIBC = $(abspath ../../../../${AOSP_LIBS_DIR}/ndk/platforms/current/arch-arm/usr/lib)
LDFLAGS += -L$(DEPDIR_LIBC) -lc -ldl
LDFLAGS += -nodefaultlibs
LDFLAGS += -Wl,--exclude-libs=libunwind_llvm.a
LDFLAGS += -lunwind_llvm
LDFLAGS += -Wl,--exclude-libs=libclang_rt.builtins-arm-android.a
LDFLAGS += $(abspath ../../../../prebuilts/clang/host/linux-x86/clang-r353983c/lib64/clang/9.0.3/lib/linux/libclang_rt.builtins-arm-android.a)
LDFLAGS += -v
LDFLAGS += -Wl,-soname,libwpa.so
endif

#TEST_AP = testap
#TEST_WPA = testwpa

DEPDIR_WIFIDRIVERCLIENT = $(abspath ../../../../out/ohos-arm-release/common/common)
DEPDIR_HDFUTILS = $(abspath ../../../../out/ohos-arm-release/hdf/hdf)
DEPDIR_HILOG = $(abspath ../../../../out/ohos-arm-release/hiviewdfx/hilog/)
DEPDIR_SEC = $(abspath ../../../../device/hisilicon/hispark_taurus/sdk_linux/soc/lib/)
WPA_LDFLAGS = -L$(DEPDIR_HDFUTILS) -lhdf_utils.z -L$(DEPDIR_HILOG) -lhilog -L$(DEPDIR_WIFIDRIVERCLIENT) -lwifi_driver_client.z -lm -L$(DEPDIR_SEC) -lsecurec
TEST_LDFLAGS = -L./ -lwpa -L$(DEPDIR_HDFUTILS) -lhdf_utils.z -L$(DEPDIR_HILOG) -lhilog -L$(DEPDIR_WIFIDRIVERCLIENT) -lwifi_driver_client.z -lm -L$(DEPDIR_SEC) -lsecurec

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
