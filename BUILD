
load("@rules_pkg//:pkg.bzl", "pkg_tar")

package(
    default_visibility = ["//visibility:public"],
)

filegroup(
    name = "nikss_hdrs",
    srcs = glob(["include/**/*.h"]),
    visibility = ["//:__subpackages__"],
)

cc_library(
    name = "nikss",
    srcs = [":nikss_hdrs"]
        + glob(["lib/*.c"], exclude=[])
        + glob(["lib/*.h"], exclude=[]),
    hdrs = [],
    includes = ["include", "install/usr/include"],
    #deps = ["@libbpf//:lib"],
    linkopts = [
        "-lelf",
        "-lz",
        "-ljansson",
        "-lgmp",
    ],
)

cc_binary(
    name = "nikss_ctl",
    srcs = ["main.c"]
        + glob(["CLI/*.c"], exclude=[])
        + glob(["CLI/*.h"], exclude=[]),
    deps = ["//:nikss"],
)
