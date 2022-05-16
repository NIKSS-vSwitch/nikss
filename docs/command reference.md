This file lists currently implemented commands for `psabpf-ctl`. Some features these commands might be still unimplemented.

`psabpf-ctl` supports `help` keyword, which can be used on every object. The same result is when there is no command
for object.

```shell
psabpf-ctl [OPTIONS] OBJECT { COMMAND | help }
psabpf-ctl help

OBJECT := { clone-session |
            multicast-group |
            pipeline |
            add-port |
            del-port |
            table |
            action-selector |
            meter |
            digest |
            counter |
            register }
OPTIONS := {}
```

# Clone sessions

```shell
psabpf-ctl clone-session create pipe ID SESSION
psabpf-ctl clone-session delete pipe ID SESSION
psabpf-ctl clone-session add-member pipe ID SESSION egress-port OUTPUT_PORT instance INSTANCE_ID [cos CLASS_OF_SERVICE] [truncate plen_bytes BYTES]
psabpf-ctl clone-session del-member pipe ID SESSION egress-port OUTPUT_PORT instance INSTANCE_ID

SESSION := id SESSION_ID
```

# Multicast groups

```shell
psabpf-ctl multicast-group create pipe ID MULTICAST_GROUP
psabpf-ctl multicast-group delete pipe ID MULTICAST_GROUP
psabpf-ctl multicast-group add-member pipe ID MULTICAST_GROUP egress-port OUTPUT_PORT instance INSTANCE_ID
psabpf-ctl multicast-group del-member pipe ID MULTICAST_GROUP egress-port OUTPUT_PORT instance INSTANCE_ID

MULTICAST_GROUP := id MULTICAST_GROUP_ID
```

# Pipelines and ports management

```shell
psabpf-ctl pipeline load id ID PATH
psabpf-ctl pipeline unload id ID
psabpf-ctl add-port pipe id ID dev DEV
psabpf-ctl del-port pipe id ID dev DEV
```

# Tables

```shell
psabpf-ctl table add pipe ID TABLE ACTION key MATCH_KEY [data ACTION_PARAMS] [priority PRIORITY]
psabpf-ctl table add pipe ID TABLE ref key MATCH_KEY data ACTION_REFS [priority PRIORITY]
psabpf-ctl table update pipe ID TABLE ACTION key MATCH_KEY [data ACTION_PARAMS] [priority PRIORITY]
psabpf-ctl table delete pipe ID TABLE [key MATCH_KEY]
psabpf-ctl table default set pipe ID TABLE ACTION [data ACTION_PARAMS]
psabpf-ctl table get pipe ID TABLE [ref] [key MATCH_KEY]

TABLE := { id TABLE_ID | name FILE | TABLE_FILE }
ACTION := { id ACTION_ID | ACTION_NAME }
ACTION_REFS := { MEMBER_REF | group GROUP_REF } 
MATCH_KEY := { EXACT_KEY | LPM_KEY | RANGE_KEY | TERNARY_KEY | none }
EXACT_KEY := { DATA }
LPM_KEY := { DATA/PREFIX_LEN }
RANGE_KEY := { DATA_MIN..DATA_MAX }
TERNARY_KEY := { DATA^MASK }
ACTION_PARAMS := { DATA | counter COUNTER_NAME COUNTER_VALUE | meter METER_NAME METER_VALUE }
COUNTER_VALUE := { BYTES | PACKETS | BYTES:PACKETS }
METER_VALUE := { PIR:PBS CIR:CBS }
```

Commands to implement:
```shell
psabpf-ctl table default get pipe ID TABLE
```

`ref` keyword means that table has an implementation, `ActionProfile` or `ActionSelector`, and then behave according to
this situation.

# Action Selectors

```shell
psabpf-ctl action-selector add_member pipe ID ACTION_SELECTOR ACTION [data ACTION_PARAMS]
psabpf-ctl action-selector delete_member pipe ID ACTION_SELECTOR MEMBER_REF
psabpf-ctl action-selector update_member pipe ID ACTION_SELECTOR MEMBER_REF ACTION [data ACTION_PARAMS]
psabpf-ctl action-selector create_group pipe ID ACTION_SELECTOR
psabpf-ctl action-selector delete_group pipe ID ACTION_SELECTOR GROUP_REF
psabpf-ctl action-selector add_to_group pipe ID ACTION_SELECTOR MEMBER_REF to GROUP_REF
psabpf-ctl action-selector delete_from_group pipe ID ACTION_SELECTOR MEMBER_REF from GROUP_REF
psabpf-ctl action-selector default_group_action pipe ID ACTION_SELECTOR ACTION [data ACTION_PARAMS]

ACTION_SELECTOR := { id ACTION_SELECTOR_ID | name FILE | ACTION_SELECTOR_FILE }
ACTION := { id ACTION_ID | ACTION_NAME }
ACTION_PARAMS := { DATA }
```

# Meters

```shell
psabpf-ctl meter get pipe ID METER index INDEX
psabpf-ctl meter update pipe ID METER index INDEX PIR:PBS CIR:CBS
psabpf-ctl meter reset pipe ID METER index INDEX

METER := { id METER_ID | name FILE | METER_FILE }
INDEX := { DATA }
PIR := { DATA }
PBS := { DATA }
CIR := { DATA }
CBS := { DATA }
```

# Digests

```shell
psabpf-ctl digest get pipe ID DIGEST

DIGEST := { id DIGEST_ID | name FILE | DIGEST_FILE }
```

# Counters

```shell
psabpf-ctl counter get pipe ID COUNTER [key DATA]
psabpf-ctl counter set pipe ID COUNTER [key DATA] value COUNTER_VALUE
psabpf-ctl counter reset pipe ID COUNTER [key DATA]

COUNTER := { id COUNTER_ID | name COUNTER | COUNTER_FILE }
COUNTER_VALUE := { BYTES | PACKETS | BYTES:PACKETS }
```

# Registers

```shell
psabpf-ctl register get pipe ID REGISTER [index DATA]

REGISTER := { id REGISTER_ID | name REGISTER | REGISTER_FILE }
REGISTER_VALUE := { DATA }
```

Commands to implement:
```shell
psabpf-ctl register set pipe ID REGISTER index DATA value REGISTER_VALUE
psabpf-ctl register reset pipe ID REGISTER index DATA
```
