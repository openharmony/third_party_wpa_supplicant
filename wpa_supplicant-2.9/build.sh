OUT_DIR=$1
ROOT_DIR=$(dirname "$0")
make -C $ROOT_DIR/wpa_supplicant/ clean
make -C $ROOT_DIR/wpa_supplicant/ -j
make -C $ROOT_DIR/hostapd/ clean
make -C $ROOT_DIR/hostapd/ -j
cp $ROOT_DIR/wpa_supplicant/libwpa.so $OUT_DIR
cp $ROOT_DIR/hostapd/libhostapd.so $OUT_DIR
cp $ROOT_DIR/os_dep/lib/*.so $OUT_DIR
