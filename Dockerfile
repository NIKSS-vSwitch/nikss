FROM p4lang/third-party:latest as builder

ARG CMAKE_BUILD_TYPE=RELEASE
# No questions asked during package installation.
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y --no-install-recommends build-essential ca-certificates python3 flex bison \
     make cmake gcc git libgmp-dev libelf-dev zlib1g-dev libjansson-dev libboost-graph-dev libboost-iostreams1.71-dev \
     libgc-dev libfl-dev pkg-config libcap-dev

COPY . /nikss
WORKDIR /nikss
RUN chmod u+x /nikss/scripts/docker-build.sh && /nikss/scripts/docker-build.sh

FROM ubuntu:20.04 as runtime
LABEL authors="Tomasz Osiński <osinstom@gmail.com>, Jan Palimąka <jan.palimaka95@gmail.com>"

RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates python3 libelf-dev iproute2 clang llvm gcc libboost-iostreams1.71-dev

COPY --from=builder /usr/local/bin/p4c-ebpf /usr/local/bin/p4c-ebpf
COPY --from=builder /usr/local/bin/p4c /usr/local/bin/p4c
COPY --from=builder /usr/local/bin/nikss-ctl /usr/local/bin/nikss-ctl
COPY --from=builder /usr/local/sbin/bpftool /usr/local/sbin/bpftool
COPY --from=builder /usr/local/include/ebpf_kernel.h /usr/local/include/ebpf_kernel.h
COPY --from=builder /usr/local/include/ebpf_common.h /usr/local/include/ebpf_common.h
COPY --from=builder /usr/local/include/psa.h /usr/local/include/psa.h
COPY --from=builder /usr/include/bpf /usr/include/bpf
COPY --from=builder /usr/local/share/p4c /usr/local/share/p4c


WORKDIR /nikss
