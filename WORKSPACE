workspace(name = "com_github_nikss_vswitch")

new_local_repository(
    name = "libbpf",
    path = "install/usr/lib64",
    build_file = "bazel/libbpf.BUILD"
)

load("//bazel:deps.bzl", "NIKSS_deps")
NIKSS_deps()

load("@rules_pkg//:deps.bzl", "rules_pkg_dependencies")
rules_pkg_dependencies()
