#ifndef P4C_BPF_DEFS_H
#define P4C_BPF_DEFS_H

// TODO: make this file private for library (move to lib/ directory)

/**
 * When PIN_GLOBAL_NS is used, this is default global namespace that is loaded.
 */
static const char *BPF_FS = "/sys/fs/bpf";

/**
 * Prefix of the mount point for PSA-eBPF pipelines.
 */
static const char *PIPELINE_PREFIX = "pipeline";

/**
 * The name of TC map initializer.
 */
static const char *TC_INIT_PROG = "classifier/map-initializer";

/**
 * The name of XDP map initializer.
 */
static const char *XDP_INIT_PROG = "xdp/map-initializer";

/**
 * The name of TC ingress program.
 */
static const char *TC_INGRESS_PROG = "classifier_tc-ingress";

/**
 * The name of TC egress program.
 */
static const char *TC_EGRESS_PROG = "classifier_tc-egress";

/**
 * The name of XDP helper program.
 */
static const char *XDP_HELPER_PROG = "xdp_xdp-ingress";

/**
 * The name of XDP ingress program.
 */
static const char *XDP_INGRESS_PROG = "xdp_ingress_xdp-ingress";

/**
 * The name of standard XDP egress program.
 */
static const char *XDP_EGRESS_PROG = "xdp_devmap_xdp-egress";

/**
 * The name of optimized XDP egress program.
 */
static const char *XDP_EGRESS_PROG_OPTIMIZED = "xdp_xdp-egress";

/**
 * The name of XDP devmap.
 */
static const char *XDP_DEVMAP = "maps/tx_port";

/**
 * The name of BPF map used for tail calls.
 */
static const char *XDP_JUMP_TBL = "maps/egress_progs_table";

#endif  /* P4C_BPF_DEFS_H */
