#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/if_link.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include <string.h>

#include "../include/psabpf_pipeline.h"
#include "../include/bpf_defs.h"
#include "common.h"
#include "btf.h"

static char *program_pin_name(struct bpf_program *prog)
{
    char *name, *p;

    name = p = strdup(bpf_program__section_name(prog));
    while ((p = strchr(p, '/')))
        *p = '_';

    return name;
}

static int do_initialize_maps(int prog_fd)
{
    char in[128], out[128];
    return bpf_prog_test_run(prog_fd, 1, &in[0], 128,
                             out, NULL, NULL, NULL);
}

static int open_prog_by_name(psabpf_context_t *ctx, const char *prog)
{
    char pinned_file[256];
    build_ebpf_prog_filename(pinned_file, sizeof(pinned_file), ctx, prog);

    return bpf_obj_get(pinned_file);  // error in errno
}

static int xdp_attach_prog_to_port(int *fd, psabpf_context_t *ctx, int ifindex, const char *prog)
{
    __u32 flags;
    int ret;

    *fd = open_prog_by_name(ctx, prog);
    if (*fd < 0)
        return errno;  // from sys_call

    /* TODO: add support for hardware offload mode (XDP_FLAGS_HW_MODE) */

    flags = XDP_FLAGS_DRV_MODE;
    ret = bpf_set_link_xdp_fd(ifindex, *fd, flags);
    if (ret != -EOPNOTSUPP) {
        if (ret < 0) {
            close_object_fd(fd);
            return -ret;
        }
        return NO_ERROR;
    }

    fprintf(stderr, "XDP native mode not supported by driver, retrying with generic SKB mode\n");
    flags = XDP_FLAGS_SKB_MODE;
    ret = bpf_set_link_xdp_fd(ifindex, *fd, flags);
    if (ret < 0) {
        close_object_fd(fd);
        return -ret;
    }

    return NO_ERROR;
}

static int update_prog_devmap(psabpf_bpf_map_descriptor_t *devmap, int ifindex, const char *intf, int egress_prog_fd)
{
    struct bpf_devmap_val devmap_val;

    devmap_val.ifindex = ifindex;
    devmap_val.bpf_prog.fd = -1;

    /* install egress program only if it's found */
    if (egress_prog_fd >= 0) {
        devmap_val.bpf_prog.fd = egress_prog_fd;
    }
    if (ifindex > (int) devmap->max_entries) {
        fprintf(stderr,
                "Warning: the index(=%d) of the interface %s is higher than the DEVMAP size (=%d)\n"
                "Applying modulo ... \n", ifindex, intf, devmap->max_entries);
    }
    int index = ifindex % ((int) devmap->max_entries);
    int ret = bpf_map_update_elem(devmap->fd, &index, &devmap_val, 0);
    if (ret)
        return errno;

    return NO_ERROR;
}

static int xdp_port_add(psabpf_context_t *ctx, const char *intf)
{
    int ret;
    int ig_prog_fd, eg_prog_fd;

    int ifindex = (int) if_nametoindex(intf);
    if (!ifindex) {
        return EINVAL;
    }

    /* TODO: Should we attach ingress pipeline at the end of whole procedure?
     *  For short time packets will be served only in ingress but not in egress pipeline. */
    ret = xdp_attach_prog_to_port(&ig_prog_fd, ctx, ifindex, XDP_INGRESS_PROG);
    if (ret != NO_ERROR)
        return ret;
    close_object_fd(&ig_prog_fd);

    /* may not exist, ignore errors */
    eg_prog_fd = open_prog_by_name(ctx, XDP_EGRESS_PROG);

    psabpf_bpf_map_descriptor_t devmap;
    ret = open_bpf_map(ctx, XDP_DEVMAP, NULL, &devmap);
    if (ret != NO_ERROR) {
        close_object_fd(&eg_prog_fd);
        return ret;
    }

    ret = update_prog_devmap(&devmap, ifindex, intf, eg_prog_fd);
    close_object_fd(&eg_prog_fd);
    close_object_fd(&devmap.fd);
    if (ret != NO_ERROR) {
        return ret;
    }

    eg_prog_fd = open_prog_by_name(ctx, XDP_EGRESS_PROG_OPTIMIZED);
    if (eg_prog_fd >= 0) {
        psabpf_bpf_map_descriptor_t jmpmap;
        ret = open_bpf_map(ctx, XDP_JUMP_TBL, NULL, &jmpmap);
        if (ret != NO_ERROR) {
            close_object_fd(&eg_prog_fd);
            return ENOENT;
        }

        int index = 0;
        ret = bpf_map_update_elem(jmpmap.fd, &index, &eg_prog_fd, 0);
        int errno_val = errno;
        close_object_fd(&eg_prog_fd);
        close_object_fd(&jmpmap.fd);
        if (ret) {
            return errno_val;
        }
    }

    /* FIXME: using bash command only for the PoC purpose */
    char cmd[256];
    sprintf(cmd, "tc qdisc add dev %s clsact", intf);
    system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "tc filter add dev %s ingress bpf da fd %s/%s%u/%s",
            intf, BPF_FS, PIPELINE_PREFIX, ctx->pipeline_id, TC_INGRESS_PROG);
    system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "tc filter add dev %s egress bpf da fd %s/%s%u/%s",
            intf, BPF_FS, PIPELINE_PREFIX, ctx->pipeline_id, TC_EGRESS_PROG);
    system(cmd);

    return 0;
}

static int tc_port_add(psabpf_context_t *ctx, const char *intf)
{
    int xdp_helper_fd;

    int ifindex = (int) if_nametoindex(intf);
    if (!ifindex) {
        return EINVAL;
    }

    int ret = xdp_attach_prog_to_port(&xdp_helper_fd, ctx, ifindex, XDP_HELPER_PROG);
    if (ret != NO_ERROR)
        return ret;
    close_object_fd(&xdp_helper_fd);

    /* FIXME: using bash command only for the PoC purpose */
    char cmd[256];
    sprintf(cmd, "tc qdisc add dev %s clsact", intf);
    system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "tc filter add dev %s ingress bpf da fd %s/%s%u/%s",
            intf, BPF_FS, PIPELINE_PREFIX, ctx->pipeline_id, TC_INGRESS_PROG);
    system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "tc filter add dev %s egress bpf da fd %s/%s%u/%s",
            intf, BPF_FS, PIPELINE_PREFIX, ctx->pipeline_id, TC_EGRESS_PROG);
    system(cmd);
    return 0;
}

bool psabpf_pipeline_exists(psabpf_context_t *ctx)
{
    char mounted_path[256];
    build_ebpf_pipeline_path(mounted_path, sizeof(mounted_path), ctx);

    return access(mounted_path, F_OK) == 0;
}

int psabpf_pipeline_load(psabpf_context_t *ctx, const char *file)
{
    struct bpf_object *obj;
    int ret, fd;
    char pinned_file[256];
    struct bpf_program *pos;

    ret = bpf_prog_load(file, BPF_PROG_TYPE_UNSPEC, &obj, &fd);
    /* Do not close fd obtained from above call, it is maintained by obj */
    if (ret < 0 || obj == NULL) {
        fprintf(stderr, "cannot load the BPF program, code = %d\n", ret);
        return -1;
    }

    bpf_object__for_each_program(pos, obj) {
        const char *sec_name = bpf_program__section_name(pos);
        fd = bpf_program__fd(pos);
        if (!strcmp(sec_name, TC_INIT_PROG) || !strcmp(sec_name, XDP_INIT_PROG)) {
            ret = do_initialize_maps(fd);
            if (ret) {
                goto err_close_obj;
            }
            // do not pin map initializer
            continue;
        }

        build_ebpf_prog_filename(pinned_file, sizeof(pinned_file),
                                 ctx, program_pin_name(pos));

        ret = bpf_program__pin(pos, pinned_file);
        if (ret < 0) {
            goto err_close_obj;
        }
    }

    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        if (bpf_map__is_pinned(map)) {
            if (bpf_map__unpin(map, NULL)) {
                goto err_close_obj;
            }
        }

        build_ebpf_map_filename(pinned_file, sizeof(pinned_file),
                                ctx, bpf_map__name(map));
        if (bpf_map__set_pin_path(map, pinned_file)) {
            goto err_close_obj;
        }

        if (bpf_map__pin(map, pinned_file)) {
            goto err_close_obj;
        }
    }

err_close_obj:
    bpf_object__close(obj);

    return ret;
}

int psabpf_pipeline_unload(psabpf_context_t *ctx)
{
    // FIXME: temporary solution [PoC-only].
    char cmd[256];
    sprintf(cmd, "rm -rf %s/%s%u",
            BPF_FS, PIPELINE_PREFIX, ctx->pipeline_id);
    return system(cmd);
}

int psabpf_pipeline_add_port(psabpf_context_t *ctx, const char *interface)
{
    char pinned_file[256];
    bool isXDP = false;

    /* Determine firstly if we have TC-based or XDP-based pipeline.
     * We can do this by just checking if XDP helper exists under a mount path. */
    build_ebpf_prog_filename(pinned_file, sizeof(pinned_file), ctx, XDP_HELPER_PROG);
    isXDP = access(pinned_file, F_OK) != 0;

    return isXDP ? xdp_port_add(ctx, interface) : tc_port_add(ctx, interface);
}

int psabpf_pipeline_del_port(psabpf_context_t *ctx, const char *interface)
{
    (void) ctx;
    char cmd[256];
    __u32 flags = 0;
    int ifindex;

    ifindex = (int) if_nametoindex(interface);
    if (!ifindex)
        return EINVAL;

    int ret = bpf_set_link_xdp_fd(ifindex, -1, flags);
    if (ret) {
        return ret;
    }

    // FIXME: temporary solution [PoC-only].
    sprintf(cmd, "tc qdisc del dev %s clsact", interface);
    ret = system(cmd);
    if (ret) {
        return ret;
    }

    return 0;
}