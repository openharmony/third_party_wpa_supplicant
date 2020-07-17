#!/bin/bash

set -e
OUT_DIR=$1
ROOT_DIR=$(dirname "$0")
BIN_DIR=$OUT_DIR/bin/usr

make -C $ROOT_DIR/wpa_supplicant/ clean
make DEPDIR=$OUT_DIR -C $ROOT_DIR/wpa_supplicant/ -j
make -C $ROOT_DIR/hostapd/ clean
make DEPDIR=$OUT_DIR -C $ROOT_DIR/hostapd/ -j
$ROOT_DIR/../../../prebuilts/gcc/linux-x86/arm/arm-linux-harmonyeabi-gcc/bin/arm-linux-harmonyeabi-strip $ROOT_DIR/wpa_supplicant/wpa_supplicant
$ROOT_DIR/../../../prebuilts/gcc/linux-x86/arm/arm-linux-harmonyeabi-gcc/bin/arm-linux-harmonyeabi-strip $ROOT_DIR/hostapd/hostapd
if [ ! -d $BIN_DIR ]; then
    mkdir -p $BIN_DIR
fi
cp $ROOT_DIR/wpa_supplicant/wpa_supplicant $BIN_DIR
cp $ROOT_DIR/hostapd/hostapd $BIN_DIR
