#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include <string.h>

#include "../include/psabpf_pipeline.h"
#include "../include/bpf_defs.h"

#define XDP_FLAGS_DRV_MODE		(1U << 2)

#define bpf_object__for_each_program(pos, obj)		\
	for ((pos) = bpf_program__next(NULL, (obj));	\
	     (pos) != NULL;				\
	     (pos) = bpf_program__next((pos), (obj)))

static char *__bpf_program__pin_name(struct bpf_program *prog)
{
    char *name, *p;

    name = p = strdup(bpf_program__section_name(prog));
    while ((p = strchr(p, '/')))
        *p = '_';

    return name;
}

static int do_initialize_maps(int prog_fd)
{
    __u32 duration, retval, size;
    char in[128], out[128];
    return bpf_prog_test_run(prog_fd, 1, &in[0], 128,
                             out, &size, &retval, &duration);
}

static int xdp_port_add(__u32 pipeline_id, char *intf)
{
    struct bpf_devmap_val devmap_val;
    char pinned_file[256];
    int ret;
    int ig_prog_fd, eg_prog_fd, devmap_fd;

    int ifindex = if_nametoindex(intf);
    if (!ifindex)
        return EINVAL;

    snprintf(pinned_file, sizeof(pinned_file), "%s/%s%d/%s", BPF_FS,
             PIPELINE_PREFIX, pipeline_id, XDP_INGRESS_PROG);
    ig_prog_fd = bpf_obj_get(pinned_file);
    if (ig_prog_fd < 0) {
        return -1;
    }
    memset(pinned_file, 0, sizeof(pinned_file));
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s%d/%s", BPF_FS,
             PIPELINE_PREFIX, pipeline_id, XDP_EGRESS_PROG);
    eg_prog_fd = bpf_obj_get(pinned_file);
    if (eg_prog_fd < 0) {
        return -1;
    }
    __u32 flags = XDP_FLAGS_DRV_MODE;
    ret = bpf_set_link_xdp_fd(ifindex, ig_prog_fd, flags);
    if (ret) {
        return ret;
    }

    memset(pinned_file, 0, sizeof(pinned_file));
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s%d/%s", BPF_FS,
             PIPELINE_PREFIX, pipeline_id, XDP_DEVMAP);
    devmap_fd = bpf_obj_get(pinned_file);
    if (devmap_fd < 0) {
        return -1;
    }
    devmap_val.ifindex = ifindex;
    devmap_val.bpf_prog.fd = eg_prog_fd;
    if (ifindex > DEVMAP_SIZE) {
        fprintf(stderr,
            "Warning: the index(=%d) of the interface %s is higher than the DEVMAP size (=%d)\n"
            "Applying modulo ... \n", ifindex, intf, DEVMAP_SIZE);
    }
    int index = ifindex % DEVMAP_SIZE;
    ret = bpf_map_update_elem(devmap_fd, &index, &devmap_val, 0);
    if (ret) {
        return ret;
    }

    /* FIXME: using bash command only for the PoC purpose */
    char cmd[256];
    sprintf(cmd, "tc qdisc add dev %s clsact", intf);
    system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "tc filter add dev %s ingress bpf da fd %s/%s%d/%s",
            intf, BPF_FS, PIPELINE_PREFIX, pipeline_id, TC_INGRESS_PROG);
    system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "tc filter add dev %s egress bpf da fd %s/%s%d/%s",
            intf, BPF_FS, PIPELINE_PREFIX, pipeline_id, TC_EGRESS_PROG);
    system(cmd);

    return 0;
}

static int tc_port_add(__u32 pipeline_id, char *intf)
{
    /* FIXME: using bash command only for the PoC purpose */
    char cmd[256];
    sprintf(cmd, "bpftool net attach xdp pinned %s/%s%d/%s dev %s overwrite",
            BPF_FS, PIPELINE_PREFIX, pipeline_id, XDP_HELPER_PROG, intf);
    system(cmd);
    sprintf(cmd, "tc qdisc add dev %s clsact", intf);
    system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "tc filter add dev %s ingress bpf da fd %s/%s%d/%s",
            intf, BPF_FS, PIPELINE_PREFIX, pipeline_id, TC_INGRESS_PROG);
    system(cmd);
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "tc filter add dev %s egress bpf da fd %s/%s%d/%s",
            intf, BPF_FS, PIPELINE_PREFIX, pipeline_id, TC_EGRESS_PROG);
    system(cmd);
    return 0;
}

void psabpf_pipeline_init(psabpf_pipeline_t *pipeline)
{
    memset(pipeline, 0, sizeof(psabpf_pipeline_t));
}

void psabpf_pipeline_free(psabpf_pipeline_t *pipeline)
{
    if ( pipeline == NULL )
        return;

    memset(pipeline, 0, sizeof(psabpf_pipeline_t));
}

void psabpf_pipeline_setid(psabpf_pipeline_t *pipeline, int pipeline_id)
{
    pipeline->id = pipeline_id;
}

void psabpf_pipeline_setobj(psabpf_pipeline_t *pipeline, char *obj)
{
    pipeline->obj = obj;
}

bool psabpf_pipeline_exists(psabpf_pipeline_t *pipeline)
{
    char mounted_path[256];
    snprintf(mounted_path, sizeof(mounted_path), "%s/%s%d", BPF_FS,
             PIPELINE_PREFIX, pipeline->id);

    return access(mounted_path, F_OK) == 0;
}

int psabpf_pipeline_load(psabpf_pipeline_t *pipeline)
{
    struct bpf_object *obj;
    int ret, prog_fd;
    char pinned_file[256];
    struct bpf_program *pos;

    const char *file = pipeline->obj;

    ret = bpf_prog_load(file, BPF_PROG_TYPE_UNSPEC, &obj, &prog_fd);
    if (ret < 0 || obj == NULL) {
        fprintf(stderr, "cannot load the BPF program, code = %d\n", ret);
        return -1;
    }

    bpf_object__for_each_program(pos, obj) {
        const char *sec_name = bpf_program__section_name(pos);
        int prog_fd = bpf_program__fd(pos);
        if (!strcmp(sec_name, TC_INIT_PROG) || !strcmp(sec_name, XDP_INIT_PROG)) {
            ret = do_initialize_maps(prog_fd);
            if (ret) {
                goto err_close_obj;
            }
            // do not pin map initializer
            continue;
        }

        snprintf(pinned_file, sizeof(pinned_file), "%s/%s%d/%s", BPF_FS,
                 PIPELINE_PREFIX, pipeline->id, __bpf_program__pin_name(pos));

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

        memset(pinned_file, 0, sizeof(pinned_file));
        snprintf(pinned_file, sizeof(pinned_file), "%s/%s%d/%s/%s", BPF_FS,
                 PIPELINE_PREFIX, pipeline->id, "maps", bpf_map__name(map));
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

int psabpf_pipeline_unload(psabpf_pipeline_t *pipeline)
{
    // FIXME: temporary solution [PoC-only].
    char cmd[256];
    sprintf(cmd, "rm -rf %s/%s%d",
            BPF_FS, PIPELINE_PREFIX, pipeline->id);
    return system(cmd);
}

int psabpf_pipeline_add_port(psabpf_pipeline_t *pipeline, char *intf)
{
    char pinned_file[256];
    bool isXDP = false;

    /* Determine firstly if we have TC-based or XDP-based pipeline.
     * We can do this by just checking if XDP helper exists under a mount path. */
    snprintf(pinned_file, sizeof(pinned_file), "%s/%s%d/%s", BPF_FS,
             PIPELINE_PREFIX, pipeline->id, XDP_HELPER_PROG);
    isXDP = access(pinned_file, F_OK) != 0;

    return isXDP ? xdp_port_add(pipeline->id, intf) : tc_port_add(pipeline->id, intf);
}

int psabpf_pipeline_del_port(psabpf_pipeline_t *pipeline, char *intf)
{
    char cmd[256];
    __u32 flags = 0;
    int ifindex;

    ifindex = if_nametoindex(intf);
    if (!ifindex)
        return EINVAL;

    int ret = bpf_set_link_xdp_fd(ifindex, -1, flags);
    if (ret) {
        return ret;
    }

    // FIXME: temporary solution [PoC-only].
    sprintf(cmd, "tc qdisc del dev %s clsact", intf);
    ret = system(cmd);
    if (ret) {
        return ret;
    }

    return 0;
}