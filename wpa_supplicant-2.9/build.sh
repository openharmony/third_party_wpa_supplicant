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
make DEPDIR=$OUT_DIR -C $ROOT_DIR/wpa_supplicant/ COMPILER_TYPE=$2 -j
make -C $ROOT_DIR/hostapd/ clean
make DEPDIR=$OUT_DIR -C $ROOT_DIR/hostapd/ COMPILER_TYPE=$2 -j

make -C $ROOT_DIR/build/ clean
make DEPDIR=$OUT_DIR -C $ROOT_DIR/build/ COMPILER_TYPE=$2

if [ "$2" == "clang" ];
then
	$ROOT_DIR/../../../prebuilts/clang/harmonyos/linux-x86_64/llvm/bin/llvm-strip $ROOT_DIR/build/libwpa.so
else
    $ROOT_DIR/../../../prebuilts/gcc/linux-x86/arm/arm-linux-harmonyeabi-gcc/bin/arm-linux-harmonyeabi-strip $ROOT_DIR/build/libwpa.so
fi
cp $ROOT_DIR/build/libwpa.so $OUT_DIR
rm -rf $ROOT_DIR/build/objs

make DEPDIR=$OUT_DIR -C $ROOT_DIR/wpa_supplicant/ libwpa_client.so COMPILER_TYPE=$2 -j
if [ "$2" == "clang" ];
then
	$ROOT_DIR/../../../prebuilts/clang/harmonyos/linux-x86_64/llvm/bin/llvm-strip $ROOT_DIR/wpa_supplicant/libwpa_client.so
else
    $ROOT_DIR/../../../prebuilts/gcc/linux-x86/arm/arm-linux-harmonyeabi-gcc/bin/arm-linux-harmonyeabi-strip $ROOT_DIR/wpa_supplicant/libwpa_client.so
fi
cp $ROOT_DIR/wpa_supplicant/libwpa_client.so $OUT_DIR

if [ "$3" = true ]; then
cp $ROOT_DIR/wpa_supplicant/libwpa_client.so $OUT_DIR/ndk/sysroot/usr/lib
cp $ROOT_DIR/build/libwpa.so $OUT_DIR/ndk/sysroot/usr/lib
cp $ROOT_DIR/src/common/wpa_ctrl.h $OUT_DIR/ndk/sysroot/usr/include
fi
