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

cmake_minimum_required(VERSION 3.10)
project(nikss C)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")

OPTION (BUILD_SHARED "Build a shared library which the nikss-ctl program will link against. Useful for other programs to link against as well." OFF)

set(NIKSSLIB_SRCS
        lib/btf.c
        lib/common.c
        lib/nikss.c
        lib/nikss_pre.c
        lib/nikss_digest.c
        lib/nikss_pipeline.c
        lib/nikss_table.c
        lib/nikss_action_selector.c
        lib/nikss_meter.c
        lib/nikss_counter.c
        lib/nikss_register.c
        lib/nikss_direct_counter.c
        lib/nikss_direct_meter.c
        lib/nikss_value_set.c)

set(NIKSSCTL_SRCS
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
        CLI/os_validate.c
        main.c)

# Use newer version of POSIX - 1995
add_definitions(-D_XOPEN_SOURCE=500)
add_definitions(-D_GNU_SOURCE)

# Add include directories on top of the list
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/install/usr/include)

# validate if dependencies are met
find_package(LibGmp REQUIRED)
find_package(LibElf REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Jansson REQUIRED)
find_package(LibBpf REQUIRED)

if (BUILD_SHARED)
  # shared library
  add_library(nikss SHARED ${NIKSSLIB_SRCS})
  target_link_libraries(nikss ${CMAKE_CURRENT_SOURCE_DIR}/install/usr/lib64/libbpf.a z m elf)

  # When cmd tool is built with shared library then it do not contains library code
  add_executable(nikss-ctl ${NIKSSCTL_SRCS})
  target_link_libraries(nikss-ctl nikss gmp jansson)
else ()
  # build one binary with all the code built-in
  add_executable(nikss-ctl ${NIKSSLIB_SRCS} ${NIKSSCTL_SRCS})
  target_link_libraries(nikss-ctl ${CMAKE_CURRENT_SOURCE_DIR}/install/usr/lib64/libbpf.a z elf gmp m jansson)
endif ()

# installation rules
if (BUILD_SHARED)
  install(TARGETS nikss DESTINATION lib)
endif ()
install(TARGETS nikss-ctl RUNTIME DESTINATION bin)

# headers installation
set(HEADERS_INSTALL_PATH ${CMAKE_INSTALL_PREFIX}/include)
add_custom_target(install_headers
        COMMAND ${CMAKE_COMMAND} -E make_directory ${HEADERS_INSTALL_PATH}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/include ${HEADERS_INSTALL_PATH}
        COMMENT "Install C/C++ headers into ${HEADERS_INSTALL_PATH}")

# linter
set(C_LANG_OPTIONS_CHECK
        -I./include
        -I./install/usr/include
        -D_XOPEN_SOURCE=500
        -D_GNU_SOURCE
        )
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
        --extra-arg=-std=c11
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
                 -readability-identifier-length,
                 -readability-suspicious-call-argument,
                 # Disable code maintenance difficulty measurement
                 -readability-function-cognitive-complexity,
                 # Allow libc system headers
                 -llvmlibc-restrict-system-libc-headers,
                 # Allow to ignore return code from calls to standard library
                 -cert-err33-c,
                 # Related to OpenCL programming for FPGA
                 -altera-*,
                 # Do not warn when two or more function arguments has compatible type
                 -bugprone-easily-swappable-parameters,
                 # TODO: enable this check, mostly caused by use of strerror()
                 -concurrency-mt-unsafe,
                '
        -warnings-as-errors='*'
        )
add_custom_target(clint
        COMMAND echo Running cppcheck
        COMMAND cppcheck ${CPPCHECK_CONFIG} ${CPPCHECK_CHECKS} ${C_LANG_OPTIONS_CHECK} ./CLI ./include ./lib main.c
        COMMAND echo Running clang-tidy
        COMMAND clang-tidy ${CLANG_TIDY_CONFIG} ${CLANG_TIDY_CHECKS} ${NIKSSLIB_SRCS} ${NIKSSCTL_SRCS} -- ${C_LANG_OPTIONS_CHECK}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "C static checks")
