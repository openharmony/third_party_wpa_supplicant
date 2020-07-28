#!/bin/bash

set -e
OUT_DIR=$1
ROOT_DIR=$(dirname "$0")
BIN_DIR=$OUT_DIR/bin/usr

if [ -d "$ROOT_DIR/build_so/objs" ]; then
rm -rf $ROOT_DIR/build_so/objs
fi
mkdir -p $ROOT_DIR/build_so/objs

make -C $ROOT_DIR/wpa_supplicant/ clean
make DEPDIR=$OUT_DIR -C $ROOT_DIR/wpa_supplicant/ -j
make -C $ROOT_DIR/hostapd/ clean
make DEPDIR=$OUT_DIR -C $ROOT_DIR/hostapd/ -j

make -C $ROOT_DIR/build_so/ clean
make DEPDIR=$OUT_DIR -C $ROOT_DIR/build_so/

$ROOT_DIR/../../../prebuilts/gcc/linux-x86/arm/arm-linux-harmonyeabi-gcc/bin/arm-linux-harmonyeabi-strip $ROOT_DIR/build_so/libwpa.so
cp $ROOT_DIR/build_so/libwpa.so $OUT_DIR
rm -rf $ROOT_DIR/build_so/objs


#$ROOT_DIR/../../../prebuilts/gcc/linux-x86/arm/arm-linux-harmonyeabi-gcc/bin/arm-linux-harmonyeabi-strip $ROOT_DIR/wpa_supplicant/wpa_supplicant
#$ROOT_DIR/../../../prebuilts/gcc/linux-x86/arm/arm-linux-harmonyeabi-gcc/bin/arm-linux-harmonyeabi-strip $ROOT_DIR/hostapd/hostapd
#if [ ! -d $BIN_DIR ]; then
#    mkdir -p $BIN_DIR
#fi

#cp $ROOT_DIR/wpa_supplicant/wpa_supplicant $BIN_DIR
#cp $ROOT_DIR/hostapd/hostapd $BIN_DIR
