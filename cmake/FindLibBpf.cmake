# Copyright 2023 Orange
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

# Try to find libbpf library
#
# The following variables are set:
# LIBBPF_FOUND - libbpf has been found
# LIBBPF_LIBRARIES - The libraries needed to use libbpf
# LIBBPF_INCLUDE_DIR - The libbpf include directory

find_path(LIBBPF_INCLUDE_DIR NAMES bpf/libbpf.h
        PATHS
        ${CMAKE_CURRENT_SOURCE_DIR}/install/usr/include
        NO_DEFAULT_PATH)

find_library(LIBBPF_LIBRARIES NAMES libbpf.a
        PATHS
        ${CMAKE_CURRENT_SOURCE_DIR}/install/usr/lib64
        NO_DEFAULT_PATH)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibBpf "Could NOT find libbpf; did you run the build_libbpf.sh script?"
        LIBBPF_LIBRARIES
        LIBBPF_INCLUDE_DIR)

mark_as_advanced(LIBBPF_INCLUDE_DIR LIBBPF_LIBRARIES)
