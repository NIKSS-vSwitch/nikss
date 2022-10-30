#!/bin/bash

set -e  # Exit on error.
set -x  # Make command execution verbose

function build_nikss() {
  git submodule update --init --recursive
  ./build_libbpf.sh
  if [ -e build ]; then /bin/rm -rf build; fi
  mkdir -p build
  cd build
  cmake "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}" ..
  make install
}

function build_bpftool() {
  git clone --recurse-submodules https://github.com/libbpf/bpftool.git /tmp/bpftool
  cd /tmp/bpftool/src
  make install
}

function build_p4c() {
  git clone --recursive https://github.com/p4lang/p4c.git /tmp/p4c
  cd /tmp/p4c
  if [ -e build ]; then /bin/rm -rf build; fi
  mkdir -p build
  cd build
  cmake "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} -DENABLE_EBPF=ON -DENABLE_BMV2=OFF -DENABLE_UBPF=OFF -DENABLE_DPDK=OFF -DENABLE_P4C_GRAPHS=OFF -DENABLE_P4TEST=OFF" ..
  make install

  # install libbpf headers globally
  cd /tmp/p4c/backends/ebpf/runtime/contrib/libbpf/src
  make install_headers

  # install headers required by p4c-ebpf globally
  # we won't need to add includes paths to clang
  cp /tmp/p4c/backends/ebpf/runtime/ebpf_common.h /usr/local/include
  cp /tmp/p4c/backends/ebpf/runtime/ebpf_kernel.h /usr/local/include
  cp /tmp/p4c/backends/ebpf/runtime/psa.h /usr/local/include
}

build_nikss
build_bpftool
build_p4c

# cleanup
rm -rf /tmp/bpftool /tmp/p4c
rm -rf /p4c /var/cache/apt/* /var/lib/apt/lists/*