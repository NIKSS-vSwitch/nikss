#!/bin/bash

set -e

ROOT_PATH=$(pwd)
SRC_DIR=$ROOT_PATH/libbpf/src
BUILD_DIR=$ROOT_PATH/libbpf/build
TARGET_DIR=$ROOT_PATH/install

mkdir -p "$BUILD_DIR" "$TARGET_DIR"

make -C "$SRC_DIR" "-j$(nproc)" install install_uapi_headers BUILD_STATIC_ONLY=y "OBJDIR=$BUILD_DIR" "DESTDIR=$TARGET_DIR"
