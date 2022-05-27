/*
 * Copyright 2022 Orange
 * Copyright 2022 Warsaw University of Technology
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
#include "bpf_defs.h"
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
    /* error in errno (sys call) */
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
    if (*fd < 0) {
        ret = errno;  // from sys_call
        fprintf(stderr, "failed to open program %s: %s\n", prog, strerror(ret));
        return ret;
    }

    /* TODO: add support for hardware offload mode (XDP_FLAGS_HW_MODE) */

    flags = XDP_FLAGS_DRV_MODE;
    ret = bpf_set_link_xdp_fd(ifindex, *fd, flags);
    if (ret != -EOPNOTSUPP) {
        if (ret < 0) {
            fprintf(stderr, "failed to attach XDP program in driver mode: %s\n", strerror(-ret));
            close_object_fd(fd);
            return -ret;
        }
        return NO_ERROR;
    }

    fprintf(stderr, "XDP native mode not supported by driver, retrying with generic SKB mode\n");
    flags = XDP_FLAGS_SKB_MODE;
    ret = bpf_set_link_xdp_fd(ifindex, *fd, flags);
    if (ret < 0) {
        fprintf(stderr, "failed to attach XDP program in SKB mode: %s\n", strerror(-ret));
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
    if (ret) {
        ret = errno;
        fprintf(stderr, "failed to update devmap: %s\n", strerror(ret));
        return ret;
    }

    return NO_ERROR;
}

static int xdp_port_add(psabpf_context_t *ctx, const char *intf, int ifindex)
{
    int ret;
    int ig_prog_fd, eg_prog_fd;

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
        fprintf(stderr, "failed to open DEVMAP: %s\n", strerror(ret));
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
            fprintf(stderr, "failed to open map %s: %s\n", XDP_JUMP_TBL, strerror(errno));
            close_object_fd(&eg_prog_fd);
            return ENOENT;
        }

        int index = 0;
        ret = bpf_map_update_elem(jmpmap.fd, &index, &eg_prog_fd, 0);
        int errno_val = errno;
        close_object_fd(&eg_prog_fd);
        close_object_fd(&jmpmap.fd);
        if (ret) {
            fprintf(stderr, "failed to update map %s: %s\n", XDP_JUMP_TBL, strerror(errno_val));
            return errno_val;
        }
    }

    /* FIXME: using bash command only for the PoC purpose
     *   use libbpf for installing TC programs, instead of 'tc filter' */
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

    return NO_ERROR;
}

static int tc_port_add(psabpf_context_t *ctx, const char *intf, int ifindex)
{
    int xdp_helper_fd;

    int ret = xdp_attach_prog_to_port(&xdp_helper_fd, ctx, ifindex, XDP_HELPER_PROG);
    if (ret != NO_ERROR)
        return ret;
    close_object_fd(&xdp_helper_fd);

    /* FIXME: using bash command only for the PoC purpose
     *   use libbpf for installing TC programs, instead of 'tc filter' */
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
    return NO_ERROR;
}

bool psabpf_pipeline_exists(psabpf_context_t *ctx)
{
    char mounted_path[256];
    build_ebpf_pipeline_path(mounted_path, sizeof(mounted_path), ctx);

    return access(mounted_path, F_OK) == 0;
}

static int extract_tuple_id_from_tuple(const char *tuple_name, uint32_t *tuple_id) {
    char *elem;
    elem = strrchr(tuple_name, '_');
    elem++;
    if (tuple_id != NULL) {
        char *end;
        *tuple_id = (uint32_t)strtol(elem, &end, 10);
        if (elem == end) {
            return ENODATA;
        }
    } else {
        return EINVAL;
    }
    return NO_ERROR;
}

static int join_tuple_to_map_if_tuple(psabpf_context_t *ctx, const char *tuple_name)
{
    // We assume that each tuple has "_tuple_" suffix
    // This name also is reserved in a p4c-ebpf-psa compiler
    const char *suffix = "_tuple_";
    const char *ternary_tbl_name_lst_char_ptr = strstr(tuple_name, suffix);

    if (ternary_tbl_name_lst_char_ptr) {
        char tuples_map_name[268];
        int ternary_map_name_length = (int)(ternary_tbl_name_lst_char_ptr - tuple_name);
        char map_name[256];
        strncpy(map_name, tuple_name, ternary_map_name_length);
        snprintf(tuples_map_name, sizeof(tuples_map_name), "%s_tuples_map", map_name);

        psabpf_bpf_map_descriptor_t tuple_map;
        int ret = open_bpf_map(ctx, tuples_map_name, NULL, &tuple_map);
        if (ret != NO_ERROR) {
            fprintf(stderr, "couldn't open map %s: %s\n", tuples_map_name, strerror(ret));
            return ret;
        }

        // Take tuple_id from a tuple map name
        uint32_t tuple_id = 0;
        ret = extract_tuple_id_from_tuple(tuple_name, &tuple_id);
        if (ret != NO_ERROR) {
            fprintf(stderr, "cannot extract tuple_id from tuple name %s: %s", tuple_name, strerror(ret));
            return ENODATA;
        }

        psabpf_bpf_map_descriptor_t tuple;
        ret = open_bpf_map(ctx, tuple_name, NULL, &tuple);
        if (ret != NO_ERROR) {
            fprintf(stderr, "couldn't open map %s: %s\n", tuple_name, strerror(ret));
            return ret;
        }

        ret = bpf_map_update_elem(tuple_map.fd, &tuple_id, &tuple.fd, 0);
        if (ret != NO_ERROR) {
            fprintf(stderr, "failed to add tuple %u: %s\n", tuple_id, strerror(ret));
        }

        tuple_id++;
    }

    return NO_ERROR;
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
        ret = errno;
        fprintf(stderr, "cannot load the BPF program: %s\n", strerror(ret));
        return ret;
    }

    bpf_object__for_each_program(pos, obj) {
        const char *sec_name = bpf_program__section_name(pos);

        build_ebpf_prog_filename(pinned_file, sizeof(pinned_file),
                                 ctx, program_pin_name(pos));

        ret = bpf_program__pin(pos, pinned_file);
        if (ret < 0) {
            fprintf(stderr, "failed to pin %s at %s: %s\n",
                    sec_name, pinned_file, strerror(-ret));
            goto err_close_obj;
        }
    }

    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        if (bpf_map__is_pinned(map)) {
            ret = bpf_map__unpin(map, NULL);
            if (ret) {
                fprintf(stderr, "failed to remove old map pin file: %s\n", strerror(-ret));
                goto err_close_obj;
            }
        }

        const char *map_name = bpf_map__name(map);

        /* Pinned file name cannot contain a dot */
        if (strstr(map_name, ".") != NULL)
            continue;

        build_ebpf_map_filename(pinned_file, sizeof(pinned_file), ctx, map_name);
        ret = bpf_map__set_pin_path(map, pinned_file);
        if (ret) {
            fprintf(stderr, "failed to pin map at %s: %s\n", pinned_file, strerror(-ret));
            goto err_close_obj;
        }

        ret = bpf_map__pin(map, pinned_file);
        if (ret) {
            fprintf(stderr, "failed to pin map at %s: %s\n", pinned_file, strerror(-ret));
            goto err_close_obj;
        }

        ret = join_tuple_to_map_if_tuple(ctx, map_name);
        if (ret) {
            fprintf(stderr, "failed to add tuple (%s) to tuples map\n", map_name);
            goto err_close_obj;
        }
    }

    bpf_object__for_each_program(pos, obj) {
        const char *sec_name = bpf_program__section_name(pos);
        fd = bpf_program__fd(pos);
        if (!strcmp(sec_name, TC_INIT_PROG) || !strcmp(sec_name, XDP_INIT_PROG)) {
            ret = do_initialize_maps(fd);
            if (ret) {
                ret = -errno;
                fprintf(stderr, "failed to initialize maps: %s\n", strerror(errno));
                goto err_close_obj;
            }
        }
    }

err_close_obj:
    bpf_object__close(obj);

    /* ret is negative value from returned libbpf, but we should return positive ones */
    return -ret;
}

int psabpf_pipeline_unload(psabpf_context_t *ctx)
{
    // FIXME: temporary solution [PoC-only].
    char cmd[256];
    sprintf(cmd, "rm -rf %s/%s%u",
            BPF_FS, PIPELINE_PREFIX, ctx->pipeline_id);
    return system(cmd);
}

int psabpf_pipeline_add_port(psabpf_context_t *ctx, const char *interface, int *port_id)
{
    char pinned_file[256];
    bool isXDP = false;

    /* Determine firstly if we have TC-based or XDP-based pipeline.
     * We can do this by just checking if XDP helper exists under a mount path. */
    build_ebpf_prog_filename(pinned_file, sizeof(pinned_file), ctx, XDP_HELPER_PROG);
    isXDP = access(pinned_file, F_OK) != 0;

    int ifindex = (int) if_nametoindex(interface);
    if (!ifindex) {
        fprintf(stderr, "no such interface: %s\n", interface);
        return ENODEV;
    }

    if (port_id != NULL)
        *port_id = ifindex;

    return isXDP ? xdp_port_add(ctx, interface, ifindex) : tc_port_add(ctx, interface, ifindex);
}

int psabpf_pipeline_del_port(psabpf_context_t *ctx, const char *interface)
{
    (void) ctx;
    char cmd[256];
    __u32 flags = 0;
    int ifindex;

    ifindex = (int) if_nametoindex(interface);
    if (!ifindex) {
        fprintf(stderr, "no such interface: %s\n", interface);
        return ENODEV;
    }

    int ret = bpf_set_link_xdp_fd(ifindex, -1, flags);
    if (ret) {
        fprintf(stderr, "failed to detach XDP program: %s\n", strerror(-ret));
        return -ret;
    }

    // FIXME: temporary solution [PoC-only].
    sprintf(cmd, "tc qdisc del dev %s clsact", interface);
    ret = system(cmd);
    if (ret) {
        fprintf(stderr, "failed to detach TC program: %s\n", strerror(ret));
        return ret;
    }

    return NO_ERROR;
}
