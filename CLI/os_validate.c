/*
 * Copyright 2023 Orange
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "os_validate.h"

#define MAX_STR_LEN 128

enum kernel_build_option_value {
    KBOV_NOT_SET = 0,
    KBOV_YES = 1,
    KBOV_MODULE = 2
};

struct os_configuration {
    char kernel_name[MAX_STR_LEN];
    char kernel_architecture[MAX_STR_LEN];
    char kernel_ver_str[MAX_STR_LEN];
    unsigned kernel_ver_major;
    unsigned kernel_ver_minor;

    char bpf_mount_path[MAX_STR_LEN];
    bool bpf_fs_is_rw;

    unsigned conf_bpf;
    unsigned conf_bpf_syscall;
    unsigned conf_net_act_bpf;
    unsigned conf_bpf_jit;
    unsigned conf_have_ebpf_jit;

    bool has_clang;
    unsigned clang_ver_major;
    unsigned clang_ver_minor;

    bool has_p4c_ebpf;
    unsigned p4c_version[4];
};

static int decode_uname(struct os_configuration *conf)
{
    struct utsname system_info;

    if (uname(&system_info) != 0) {
        int error_code = errno;
        fprintf(stderr, "failed to uname: %s\n", strerror(error_code));
        return error_code;
    }

    strncpy(&conf->kernel_name[0], &system_info.sysname[0], MAX_STR_LEN);
    conf->kernel_name[MAX_STR_LEN - 1] = 0;
    strncpy(&conf->kernel_architecture[0], &system_info.machine[0], MAX_STR_LEN);
    conf->kernel_architecture[MAX_STR_LEN - 1] = 0;
    strncpy(&conf->kernel_ver_str[0], &system_info.release[0], MAX_STR_LEN);
    conf->kernel_ver_str[MAX_STR_LEN - 1] = 0;

    char *ver = NULL;
    char *str = &system_info.release[0];

    /* Decode major kernel version */
    ver = strsep(&str, ".");
    if (ver == NULL) {
        fprintf(stderr, "failed to decode major kernel version\n");
        return EINVAL;
    }
    conf->kernel_ver_major = strtoul(ver, NULL, 0);

    /* Decode minor kernel version */
    ver = strsep(&str, ".");
    if (ver == NULL) {
        fprintf(stderr, "failed to decode minor kernel version\n");
        return EINVAL;
    }
    conf->kernel_ver_minor = strtoul(ver, NULL, 0);

    return 0;
}

static int decode_mounts(struct os_configuration *conf)
{
    /* To avoid introducing new dependency `libmount` read mounted filesystems from /proc/mounts */
    conf->bpf_mount_path[0] = 0;
    FILE *mounts = fopen("/proc/mounts", "re");
    if (mounts != NULL) {
        char buf[BUFSIZ];
        while (fgets(buf, BUFSIZ, mounts) != NULL) {
            char *str = &buf[0];
            char *device = strsep(&str, " ");
            char *mount_point = strsep(&str, " ");
            char *fs_type = strsep(&str, " ");
            char *options = strsep(&str, " ");

            if (strcmp(device, "bpf") == 0 && strcmp(fs_type, "bpf") == 0) {
                strncpy(&conf->bpf_mount_path[0], mount_point, MAX_STR_LEN);
                conf->bpf_mount_path[MAX_STR_LEN - 1] = 0;

                /* Also validate that bpf fs is mounted in read-write mode */
                char *opt = NULL;
                while ((opt = strsep(&options, ",")) != NULL) {
                    if (strcmp(opt, "rw") == 0) {
                        conf->bpf_fs_is_rw = true;
                    } else if (strcmp(opt, "ro") == 0) {
                        conf->bpf_fs_is_rw = false;
                    }
                }
                break;
            }
        }
        fclose(mounts);
    } else {
        int error_code = errno;
        fprintf(stderr, "failed to read mounted filesystems: %s\n", strerror(error_code));
        return error_code;
    }

    return 0;
}

static enum kernel_build_option_value decode_kernel_build_option_value(const char *value)
{
    if (value[0] == 'y') {
        return KBOV_YES;
    }
    if (value[0] == 'm') {
        return KBOV_MODULE;
    }

    return KBOV_NOT_SET;
}

/* require decode_uname to be called before */
static int decode_kernel_build_options(struct os_configuration *conf)
{
    char buf[BUFSIZ];
    snprintf(&buf[0], BUFSIZ, "/boot/config-%s", conf->kernel_ver_str);

    FILE *options = fopen(buf, "re");
    if (options != NULL) {
        while (fgets(buf, BUFSIZ, options) != NULL) {
            if (strlen(buf) < 1 || buf[0] == 0 || buf[0] == '\n' || buf[0] == '#') {
                continue;
            }

            /* Remove trailing new line character */
            if (buf[strlen(buf) - 1] == '\n') {
                buf[strlen(buf) - 1] = 0;
            }

            char *str = &buf[0];
            char *opt = strsep(&str, "=");
            char *value = str;

            if (strcmp(opt, "CONFIG_BPF") == 0) {
                conf->conf_bpf = decode_kernel_build_option_value(value);
            } else if (strcmp(opt, "CONFIG_BPF_SYSCALL") == 0) {
                conf->conf_bpf_syscall = decode_kernel_build_option_value(value);
            } else if (strcmp(opt, "CONFIG_NET_ACT_BPF") == 0) {
                conf->conf_net_act_bpf = decode_kernel_build_option_value(value);
            } else if (strcmp(opt, "CONFIG_BPF_JIT") == 0) {
                conf->conf_bpf_jit = decode_kernel_build_option_value(value);
            } else if (strcmp(opt, "CONFIG_HAVE_EBPF_JIT") == 0) {
                conf->conf_have_ebpf_jit = decode_kernel_build_option_value(value);
            }
        }

        fclose(options);
    } else {
        int error_code = errno;
        fprintf(stderr, "failed to read kernel build options: %s\n", strerror(error_code));
        return error_code;
    }

    return 0;
}

static int exec_cmd(char *output_buf, ssize_t buf_size, char *cmd[])
{
    int error_code = ENOENT;
    int pipe_fds[2];

    if (pipe2(pipe_fds, O_NONBLOCK) != 0) {
        error_code = errno;
        fprintf(stderr, "failed to create pipe: %s\n", strerror(error_code));
        return error_code;
    }
    int write_fd = pipe_fds[1];
    int read_fd = pipe_fds[0];

    int pid = fork();
    if (pid < 0) {
        error_code = errno;
        fprintf(stderr, "failed to create a new process: %s\n", strerror(error_code));
        close(read_fd);
        close(write_fd);
        return error_code;
    }

    if (pid == 0) {
        /* child process */
        dup2(write_fd, 1);
        dup2(write_fd, 2);
        close(read_fd);
        close(write_fd);
        execvp(cmd[0], cmd);
        /* In case of error we can reach this place */
        exit(1);
        /* Never reach this place. NEVER. */
    }

    /* parent process */
    close(write_fd);
    int wstatus;
    waitpid(pid, &wstatus, 0);
    if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0) {
        /* Read the output from the command */
        ssize_t bytes = read(read_fd, output_buf, buf_size);
        if (bytes > 0 && bytes < buf_size) {
            output_buf[bytes] = 0;
            error_code = 0;
        }
    }

    close(read_fd);
    return error_code;
}

static int detect_compilers(struct os_configuration *conf)
{
    char buf[BUFSIZ];
    char *clang[] = {"clang", "--version", NULL};
    char *p4c[] = {"p4c-ebpf", "--version", NULL};

    conf->has_clang = false;
    if (exec_cmd(buf, BUFSIZ, clang) == 0) {
        conf->has_clang = true;

        char *ptr = &buf[0];
        char *line = NULL;
        while ((line = strsep(&ptr, "\n")) != NULL) {
            /* Expected format: "clang version 10.0.0-4ubuntu1" */
            char *token = strsep(&line, " ");
            if (!token || strcmp(token, "clang") != 0) {
                continue;
            }
            token = strsep(&line, " ");
            if (!token || strcmp(token, "version") != 0) {
                continue;
            }

            char *version = strsep(&line, " ");
            char *v = strsep(&version, ".");
            if (v != NULL) {
                conf->clang_ver_major = strtoul(v, NULL, 0);
            }
            v = strsep(&version, ".");
            if (v != NULL) {
                conf->clang_ver_minor = strtoul(v, NULL, 0);
            }
            break;
        }
    }

    conf->has_p4c_ebpf = false;
    if (exec_cmd(buf, BUFSIZ, p4c) == 0) {
        conf->has_p4c_ebpf = true;

        char *ptr = &buf[0];
        char *line = NULL;
        while ((line = strsep(&ptr, "\n")) != NULL) {
            /* Expected format: "Version 1.2.3.5 (SHA: e052f1fbe BUILD: Release)" */
            char *token = strsep(&line, " ");
            if (!token || strcmp(token, "Version") != 0) {
                continue;
            }

            char *version = strsep(&line, " ");
            for (int i = 0; i < 4; ++i) {
                char *v = strsep(&version, ".");
                if (v != NULL) {
                    conf->p4c_version[i] = strtoul(v, NULL, 0);
                }
            }
            break;
        }
    }

    return 0;
}

/* Returns:
 *      -1: v1 < v2
 *       0: v1 == v2
 *       1: v1 > v2
 * */
static int compare_versions(const unsigned v1[4], const unsigned v2[4])
{
    for (unsigned i = 0; i < 4; ++i) {
        if (v1[i] < v2[i]) {
            return -1;
        }
        if (v1[i] > v2[i]) {
            return 1;
        }
    }
    return 0;
}

/* Return codes:
 *      0: Everything OK
 *      1: May work (one or more warning, no errors)
 *      2: Invalid configuration (one or more errors)
 * */
static int validate_config_and_print(struct os_configuration *conf)
{
    bool error = false;
    bool warning = false;

#define CHECK_CONDITION(condition, msg_type, msg, var) \
    if (condition) {                                   \
        printf(" ... OK\n");                           \
    } else {                                           \
        printf(" ... %s (%s)\n", msg_type, msg);       \
        (var) = true;                                  \
    }
#define CHECK_ERROR(condition, err_msg) CHECK_CONDITION(condition, "ERROR", err_msg, error)
#define CHECK_WARNING(condition, warn_msg) CHECK_CONDITION(condition, "WARNING", warn_msg, warning)

    /* Kernel family and release */
    printf("Kernel family: %s", conf->kernel_name);
    CHECK_ERROR(strcmp(conf->kernel_name, "Linux") == 0, "expected a Linux kernel");

    printf("Kernel version: %u.%u", conf->kernel_ver_major, conf->kernel_ver_minor);
    unsigned kernel_min_ver[4] = {5, 8, 0, 0};
    unsigned current_kernel_ver[4] = {conf->kernel_ver_major, conf->kernel_ver_minor, 0, 0};
    CHECK_ERROR(compare_versions(current_kernel_ver, kernel_min_ver) >= 0, "expected kernel version >= 5.8");

    /* Machine architectures */
    const char *tested_archs[] = {"x86_64", NULL};
    const char *tested_archs_err_msg = "unsupported, tested architecture(s): x86_64";
    printf("Machine architecture: %s", conf->kernel_architecture);
    bool arch_is_supported = false;
    for (unsigned i = 0; tested_archs[i] != NULL; ++i) {
        if (strcmp(conf->kernel_architecture, tested_archs[i]) == 0) {
            arch_is_supported = true;
            break;
        }
    }
    CHECK_WARNING(arch_is_supported, tested_archs_err_msg);

    /* BPF filesystem */
    bool bpf_fs_is_mounted = strlen(conf->bpf_mount_path) > 0;
    printf("BPF filesystem is mounted: %s", bpf_fs_is_mounted ? "true" : "false");
    CHECK_ERROR(bpf_fs_is_mounted, "BPF filesystem is not mounted");

    printf("BPF filesystem mount point: %s", conf->bpf_mount_path);
    CHECK_ERROR(strcmp(conf->bpf_mount_path, "/sys/fs/bpf") == 0, "expected BPF filesystem to be mounted on /sys/fs/bpf");

    printf("BPF filesystem in read-write mode: %s", conf->bpf_fs_is_rw ? "true" : "false");
    CHECK_ERROR(conf->bpf_fs_is_rw, "BPF filesystem is not mounted in read-write mode");

    /* Kernel build options */
    const char *build_option_value[] = {"no", "yes", "module"};
    printf("Kernel build option CONFIG_BPF: %s", build_option_value[conf->conf_bpf]);
    CHECK_ERROR(conf->conf_bpf == KBOV_YES, "expected option CONFIG_BPF set to \"yes\"");

    printf("Kernel build option CONFIG_BPF_SYSCALL: %s", build_option_value[conf->conf_bpf_syscall]);
    CHECK_ERROR(conf->conf_bpf_syscall == KBOV_YES, "expected option CONFIG_BPF_SYSCALL set to \"yes\"");

    printf("Kernel build option CONFIG_BPF_JIT: %s", build_option_value[conf->conf_bpf_jit]);
    CHECK_ERROR(conf->conf_bpf_jit == KBOV_YES, "expected option CONFIG_BPF_JIT set to \"yes\"");

    printf("Kernel build option CONFIG_HAVE_EBPF_JIT: %s", build_option_value[conf->conf_have_ebpf_jit]);
    CHECK_ERROR(conf->conf_have_ebpf_jit == KBOV_YES, "expected option CONFIG_HAVE_EBPF_JIT set to \"yes\"");

    printf("Kernel build option CONFIG_NET_ACT_BPF: %s", build_option_value[conf->conf_net_act_bpf]);
    CHECK_ERROR(conf->conf_net_act_bpf == KBOV_YES || conf->conf_net_act_bpf == KBOV_MODULE,
                "expected option CONFIG_NET_ACT_BPF set to \"yes\" or \"module\"");

    /* Clang */
    printf("clang detected: %s", conf->has_clang ? "true" : "false");
    CHECK_WARNING(conf->has_clang, "no clang compiler detected");

    if (conf->has_clang) {
        printf("clang version: %u.%u", conf->clang_ver_major, conf->clang_ver_minor);
        unsigned clang_ver[4] = {conf->clang_ver_major, conf->clang_ver_minor, 0, 0};
        unsigned min_clang_ver[4] = {10, 0, 0, 0};
        CHECK_WARNING(compare_versions(clang_ver, min_clang_ver) >= 0, "expected clang version >= 10.0");
    }

    /* p4c-ebpf */
    printf("p4c-ebpf detected: %s", conf->has_p4c_ebpf ? "true" : "false");
    CHECK_WARNING(conf->has_p4c_ebpf, "no p4c-ebpf compiler detected");

    if (conf->has_p4c_ebpf) {
        printf("p4c-ebpf version: %u.%u.%u.%u", conf->p4c_version[0], conf->p4c_version[1], conf->p4c_version[2], conf->p4c_version[3]);
        unsigned min_p4c_ver[4] = {1, 2, 2, 2};
        CHECK_WARNING(compare_versions(conf->p4c_version, min_p4c_ver) >= 0, "expected p4c-ebpf version >= 1.2.2.2");
    }

#undef CHECK_CONDITION
#undef CHECK_ERROR
#undef CHECK_WARNING

    /*
     * Final verdict
     */

    if (error) {
        printf("\nInvalid system configuration, NIKSS will not work.\n\n");
        return 2;
    }
    if (warning) {
        printf("\nValid system configuration, but some NIKSS features may not work.\n\n");
        return 1;
    }

    printf("\nValid system configuration, NIKSS should work correctly.\n\n");
    return 0;
}

int do_os_validate(int argc, char **argv)
{
    if (argc > 0) {
        fprintf(stderr, "%s: unused argument\n", argv[0]);
    }

    struct os_configuration conf;
    memset(&conf, 0, sizeof(struct os_configuration));

    int (*get_conf_func[])(struct os_configuration *) = {
            decode_uname,
            decode_mounts,
            decode_kernel_build_options,
            detect_compilers,
            NULL
    };

    bool get_conf_failed = false;
    for (unsigned i = 0; get_conf_func[i] != NULL; ++i) {
        if (get_conf_func[i](&conf) != 0) {
            get_conf_failed = true;
        }
    }

    if (get_conf_failed) {
        fprintf(stderr, "failed to obtain system configuration\n");
        return EPERM;
    }

    return validate_config_and_print(&conf);
}
