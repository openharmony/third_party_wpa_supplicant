#!/bin/bash

set -e
OUT_DIR=$1
ROOT_DIR=$(dirname "$0")
BIN_DIR=$OUT_DIR/../bin/usr

if [ -d $ROOT_DIR/os_dep/lib ];then
    rm -rf $ROOT_DIR/os_dep/lib
fi

mkdir -p $ROOT_DIR/os_dep/lib/
if [ -d $ROOT_DIR/os_dep/include ];then
rm -rf $ROOT_DIR/os_dep/include
fi

cp $OUT_DIR/../libmessage_engine.* $ROOT_DIR/os_dep/lib/
cp $OUT_DIR/../libhdf_osal.* $ROOT_DIR/os_dep/lib/
cp $OUT_DIR/libsec.* $ROOT_DIR/os_dep/lib/

echo "Trying to list $ROOT_DIR/os_dep/lib"
if [ -f $ROOT_DIR/os_dep/lib/libmessage_engine.so ];then
echo "libmessage_engine.so exists."
fi
ls -alh $ROOT_DIR/os_dep/lib/

make -C $ROOT_DIR/wpa_supplicant/ clean
make -C $ROOT_DIR/wpa_supplicant/ -j
make -C $ROOT_DIR/hostapd/ clean
make -C $ROOT_DIR/hostapd/ -j
$ROOT_DIR/../../../prebuilts/gcc/linux-x86/arm/arm-linux-harmonyeabi-gcc/bin/arm-linux-harmonyeabi-strip $ROOT_DIR/wpa_supplicant/wpa_supplicant
$ROOT_DIR/../../../prebuilts/gcc/linux-x86/arm/arm-linux-harmonyeabi-gcc/bin/arm-linux-harmonyeabi-strip $ROOT_DIR/hostapd/hostapd
if [ ! -d $BIN_DIR ]; then
    mkdir -p $BIN_DIR
fi
cp $ROOT_DIR/wpa_supplicant/wpa_supplicant $BIN_DIR
cp $ROOT_DIR/hostapd/hostapd $BIN_DIR

rm -rf $ROOT_DIR/os_dep/lib

