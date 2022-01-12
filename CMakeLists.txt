cmake_minimum_required(VERSION 3.16)
project(psabpf C)

set(CMAKE_C_STANDARD 11)

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
