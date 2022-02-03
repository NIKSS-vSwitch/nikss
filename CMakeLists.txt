# Copyright 2022 Orange
# Copyright 2022 Warsaw University of Technology
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.16)
project(psabpf C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")

set(PSABPFCTL_SRCS
        lib/btf.c
        lib/common.c
        lib/psabpf.c
        lib/psabpf_clone_session.c
        lib/psabpf_pipeline.c
        lib/psabpf_table.c
        lib/psabpf_action_selector.c
        lib/psabpf_meter.c
        CLI/action_selector.c
        CLI/common.c
        CLI/clone_session.c
        CLI/pipeline.c
        CLI/table.c
        CLI/meter.c
        main.c)

add_executable(psabpf-ctl ${PSABPFCTL_SRCS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/install/usr/include)
target_link_libraries(psabpf-ctl ${CMAKE_CURRENT_SOURCE_DIR}/install/usr/lib64/libbpf.a)
target_link_libraries(psabpf-ctl z elf gmp m)
install(TARGETS psabpf-ctl RUNTIME DESTINATION bin)
