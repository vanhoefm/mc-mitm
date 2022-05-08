#!/bin/bash
set -e

cd ../hostapd
cp defconfig .config
make -j 4
