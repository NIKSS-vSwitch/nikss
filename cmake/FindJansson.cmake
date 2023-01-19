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

# Try to find Jansson library
#
# The following variables are set:
# JANSSON_FOUND - System has Jansson
# JANSSON_LIBRARIES - The libraries needed to use Jansson
# JANSSON_INCLUDE_DIR - The Jansson include directory

find_path(JANSSON_INCLUDE_DIR jansson.h)

find_library(JANSSON_LIBRARIES NAMES jansson)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Jansson DEFAULT_MSG
        JANSSON_LIBRARIES
        JANSSON_INCLUDE_DIR)

mark_as_advanced(JANSSON_INCLUDE_DIR JANSSON_LIBRARIES)
