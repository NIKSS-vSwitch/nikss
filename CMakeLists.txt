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

OPTION (BUILD_SHARED "Build a shared library which the psabpf-ctl program will link against. Useful for other programs to link against as well." OFF)

set(PSABPFLIB_SRCS
        lib/btf.c
        lib/common.c
        lib/psabpf.c
        lib/psabpf_pre.c
        lib/psabpf_digest.c
        lib/psabpf_pipeline.c
        lib/psabpf_table.c
        lib/psabpf_action_selector.c
        lib/psabpf_meter.c
        lib/psabpf_counter.c
        lib/psabpf_register.c
        lib/psabpf_direct_counter.c
        lib/psabpf_direct_meter.c
        lib/psabpf_value_set.c)

set(PSABPFCTL_SRCS
        CLI/action_selector.c
        CLI/common.c
        CLI/clone_session.c
        CLI/multicast.c
        CLI/digest.c
        CLI/pipeline.c
        CLI/table.c
        CLI/meter.c
        CLI/counter.c
        CLI/register.c
        CLI/value_set.c
        main.c)

if (BUILD_SHARED)
  add_library(psabpf SHARED ${PSABPFLIB_SRCS})
  target_link_libraries(psabpf ${CMAKE_CURRENT_SOURCE_DIR}/install/usr/lib64/libbpf.a z elf)
  install(TARGETS psabpf DESTINATION lib)
  add_executable(psabpf-ctl ${PSABPFCTL_SRCS})
else ()
  add_executable(psabpf-ctl ${PSABPFLIB_SRCS} ${PSABPFCTL_SRCS})
endif ()
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/install/usr/include)
if (BUILD_SHARED)
  link_directories(${CMAKE_CURRENT_BINARY_DIR})
  target_link_libraries(psabpf-ctl psabpf z elf gmp m jansson)
else ()
  target_link_libraries(psabpf-ctl z elf gmp m jansson)
endif ()
target_link_libraries(psabpf-ctl ${CMAKE_CURRENT_SOURCE_DIR}/install/usr/lib64/libbpf.a z elf)
install(TARGETS psabpf-ctl RUNTIME DESTINATION bin)

# linter
set(CPPCHECK_CONFIG
        --quiet
        --language=c
        --std=c11
        --error-exitcode=2
        )
set(CPPCHECK_CHECKS
        --enable=all
        --suppress=readdirCalled
        --suppress=missingIncludeSystem
        --inline-suppr
        --library=std
        --library=posix
        )
set(CLANG_TIDY_CONFIG
        --quiet
        )
set(CLANG_TIDY_CHECKS
        -checks='*,
                 # allow use of memcpy and memset
                 -clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,
                 # recommended to disable, see https://stackoverflow.com/questions/50399090
                 -hicpp-signed-bitwise,
                 # allow hardcoded values (most of them are related to architecture, so can't be changed)
                 -cppcoreguidelines-avoid-magic-numbers,
                 -readability-magic-numbers,
                '
        -warnings-as-errors='*'
        )
add_custom_target(clint
        COMMAND echo Running cppcheck
        COMMAND cppcheck ${CPPCHECK_CONFIG} ${CPPCHECK_CHECKS} -I./include -I./install/usr/include ./CLI ./include ./lib main.c
        COMMAND echo Running clang-tidy
        COMMAND clang-tidy ${CLANG_TIDY_CONFIG} ${CLANG_TIDY_CHECKS} ${PSABPFLIB_SRCS} ${PSABPFCTL_SRCS} -- -I./include -I./install/usr/include
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "C static checks")
