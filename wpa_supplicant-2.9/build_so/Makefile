CC = ../../../../prebuilts/gcc/linux-x86/arm/arm-linux-harmonyeabi-gcc/bin/arm-linux-harmonyeabi-gcc

CFLAGS  := -flto -MMD -O2 -g -w -fsigned-char

#TEST_AP = testap
#TEST_WPA = testwpa

LIBS = -L./ -lwpa -L$(DEPDIR) -lhdf_core -lhdf_osal -lsec_shared -lrt -lm -lpthread

WPA_SO_LIB = -L$(DEPDIR) -lhdf_core -lhdf_osal -lsec_shared -lrt -lm -lpthread

WPA_SO = libwpa.so
#OBJS_WPA = test_wpa.o
#OBJS_AP = test_hostapd.o

CDEPS = $(patsubst %.c,%.d,test_wpa.c test_hostapd.c)

all : $(WPA_SO)

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(WPA_SO) :
	$(CC)  -flto -O2  -shared -fPIC -Wl,-z,defs objs/*.o -o $@ $(WPA_SO_LIB)

$(TEST_WPA) : $(OBJS_WPA)
	$(CC) -o $@ $< $(LIBS)
	rm -f $(CDEPS)

$(TEST_AP) : $(OBJS_AP)
	$(CC) -o $@ $< $(LIBS)
	rm -f $(CDEPS)


clean:
	rm -f $(WPA_SO)
	rm -f $(OBJS_AP)
	rm -f $(TEST_AP)
	rm -f $(OBJS_WPA)
	rm -f $(TEST_WPA)
	rm -f $(CDEPS)
