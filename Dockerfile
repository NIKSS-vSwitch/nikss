FROM ubuntu:20.04 as builder

ARG CMAKE_BUILD_TYPE=RELEASE
# No questions asked during package installation.
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y --no-install-recommends build-essential ca-certificates python3 flex bison \
     make cmake gcc git libgmp-dev libelf-dev zlib1g-dev libjansson-dev clang-10 llvm-10

COPY . /nikss
WORKDIR /nikss
RUN chmod u+x /nikss/scripts/docker-build.sh && /nikss/scripts/docker-build.sh

FROM ubuntu:20.04 as runtime
LABEL authors="Tomasz Osiński <osinstom@gmail.com>, Jan Palimąka <jan.palimaka95@gmail.com>"

