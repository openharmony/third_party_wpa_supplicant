#!/bin/bash

set -e
OUT_DIR=$1
ROOT_DIR=$(dirname "$0")
BIN_DIR=$OUT_DIR/bin/usr

if [ -d "$ROOT_DIR/build/objs" ]; then
rm -rf $ROOT_DIR/build/objs
fi
mkdir -p $ROOT_DIR/build/objs

make -C $ROOT_DIR/wpa_supplicant/ clean
make DEPDIR=$OUT_DIR -C $ROOT_DIR/wpa_supplicant/ -j
make -C $ROOT_DIR/hostapd/ clean
make DEPDIR=$OUT_DIR -C $ROOT_DIR/hostapd/ -j

make -C $ROOT_DIR/build/ clean
make DEPDIR=$OUT_DIR -C $ROOT_DIR/build/

$ROOT_DIR/../../../prebuilts/gcc/linux-x86/arm/arm-linux-harmonyeabi-gcc/bin/arm-linux-harmonyeabi-strip $ROOT_DIR/build/libwpa.so
cp $ROOT_DIR/build/libwpa.so $OUT_DIR
rm -rf $ROOT_DIR/build/objs

make DEPDIR=$OUT_DIR -C $ROOT_DIR/wpa_supplicant/ libwpa_client.so -j
$ROOT_DIR/../../../prebuilts/gcc/linux-x86/arm/arm-linux-harmonyeabi-gcc/bin/arm-linux-harmonyeabi-strip $ROOT_DIR/wpa_supplicant/libwpa_client.so
cp $ROOT_DIR/wpa_supplicant/libwpa_client.so $OUT_DIR

if [ "$2" = true ]; then
cp $ROOT_DIR/wpa_supplicant/libwpa_client.so $OUT_DIR/ndk/sysroot/usr/lib
cp $ROOT_DIR/build/libwpa.so $OUT_DIR/ndk/sysroot/usr/lib
cp $ROOT_DIR/src/common/wpa_ctrl.h $OUT_DIR/ndk/sysroot/usr/include
fi
