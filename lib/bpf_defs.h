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

#ifndef P4C_BPF_DEFS_H
#define P4C_BPF_DEFS_H

#define COUNTER_PACKETS_OR_BYTES_STRUCT_ENTRIES  1
#define COUNTER_PACKETS_AND_BYTES_STRUCT_ENTRIES 2

#ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-variable"
#endif

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
static const char *XDP_DEVMAP = "tx_port";

/**
 * The name of BPF map used for tail calls.
 */
static const char *XDP_JUMP_TBL = "egress_progs_table";

/**
 * The name of the BPF MAP storing clone sessions.
 */
static const char *CLONE_SESSION_TABLE = "clone_session_tbl";
static const char *CLONE_SESSION_TABLE_INNER = "clone_session_tbl_inner";

/**
 * The name of the BPF MAP storing multicast groups.
 */
static const char *MULTICAST_GROUP_TABLE = "multicast_grp_tbl";
static const char *MULTICAST_GROUP_TABLE_INNER = "multicast_grp_tbl_inner";

#ifdef __GNUC__
    #pragma GCC diagnostic pop
#endif

#endif  /* P4C_BPF_DEFS_H */
