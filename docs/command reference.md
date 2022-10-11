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
            action-profile |
            meter |
            digest |
            counter |
            register |
            value-set }
OPTIONS := {}
```

# Clone sessions

```shell
psabpf-ctl clone-session create pipe ID SESSION
psabpf-ctl clone-session delete pipe ID SESSION
psabpf-ctl clone-session add-member pipe ID SESSION egress-port OUTPUT_PORT instance INSTANCE_ID [cos CLASS_OF_SERVICE] [truncate plen_bytes BYTES]
psabpf-ctl clone-session del-member pipe ID SESSION egress-port OUTPUT_PORT instance INSTANCE_ID
psabpf-ctl clone-session get pipe ID [SESSION]

SESSION := id SESSION_ID
```

# Multicast groups

```shell
psabpf-ctl multicast-group create pipe ID MULTICAST_GROUP
psabpf-ctl multicast-group delete pipe ID MULTICAST_GROUP
psabpf-ctl multicast-group add-member pipe ID MULTICAST_GROUP egress-port OUTPUT_PORT instance INSTANCE_ID
psabpf-ctl multicast-group del-member pipe ID MULTICAST_GROUP egress-port OUTPUT_PORT instance INSTANCE_ID
psabpf-ctl multicast-group get pipe ID [MULTICAST_GROUP]

MULTICAST_GROUP := id MULTICAST_GROUP_ID
```

# Pipelines and ports management

```shell
psabpf-ctl pipeline load id ID PATH
psabpf-ctl pipeline unload id ID
psabpf-ctl pipeline show id ID
psabpf-ctl add-port pipe id ID dev DEV
psabpf-ctl del-port pipe id ID dev DEV
```

# Tables

```shell
psabpf-ctl table add pipe ID TABLE_NAME action ACTION key MATCH_KEY [data ACTION_PARAMS] [priority PRIORITY]
psabpf-ctl table add pipe ID TABLE_NAME ref key MATCH_KEY data ACTION_REFS [priority PRIORITY]
psabpf-ctl table update pipe ID TABLE_NAME action ACTION key MATCH_KEY [data ACTION_PARAMS] [priority PRIORITY]
psabpf-ctl table delete pipe ID TABLE_NAME [key MATCH_KEY]
psabpf-ctl table get pipe ID TABLE_NAME [ref] [key MATCH_KEY]
psabpf-ctl table default set pipe ID TABLE_NAME action ACTION [data ACTION_PARAMS]
psabpf-ctl table default get pipe ID TABLE_NAME

ACTION := { id ACTION_ID | name ACTION_NAME }
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

`ref` keyword means that table has an implementation, `ActionProfile` or `ActionSelector`, and then behave according to
this situation.

# Action Selectors

```shell
psabpf-ctl action-selector add-member pipe ID ACTION_SELECTOR_NAME action ACTION [data ACTION_PARAMS]
psabpf-ctl action-selector delete-member pipe ID ACTION_SELECTOR_NAME MEMBER_REF
psabpf-ctl action-selector update-member pipe ID ACTION_SELECTOR_NAME MEMBER_REF action ACTION [data ACTION_PARAMS]
psabpf-ctl action-selector create-group pipe ID ACTION_SELECTOR_NAME
psabpf-ctl action-selector delete-group pipe ID ACTION_SELECTOR_NAME GROUP_REF
psabpf-ctl action-selector add-to-group pipe ID ACTION_SELECTOR_NAME MEMBER_REF to GROUP_REF
psabpf-ctl action-selector delete-from-group pipe ID ACTION_SELECTOR_NAME MEMBER_REF from GROUP_REF
psabpf-ctl action-selector empty-group-action pipe ID ACTION_SELECTOR_NAME action ACTION [data ACTION_PARAMS]
psabpf-ctl action-selector get pipe ID ACTION_SELECTOR_NAME [member MEMBER_REF | group GROUP_REF | empty-group-action]

ACTION := { id ACTION_ID | name ACTION_NAME }
ACTION_PARAMS := { DATA }
```

# Action Profile

```shell
psabpf-ctl action-profile add-member pipe ID ACTION_PROFILE_NAME action ACTION [data ACTION_PARAMS]
psabpf-ctl action-profile delete-member pipe ID ACTION_PROFILE_NAME MEMBER_REF
psabpf-ctl action-profile update-member pipe ID ACTION_PROFILE_NAME MEMBER_REF action ACTION [data ACTION_PARAMS]
psabpf-ctl action-profile get pipe ID ACTION_PROFILE_NAME [member MEMBER_REF]

ACTION := { id ACTION_ID | name ACTION_NAME }
ACTION_PARAMS := { DATA }
```

# Meters

```shell
psabpf-ctl meter get pipe ID METER_NAME [index INDEX]
psabpf-ctl meter update pipe ID METER_NAME index INDEX PIR:PBS CIR:CBS
psabpf-ctl meter reset pipe ID METER_NAME [index INDEX]

INDEX := { DATA }
PIR := { DATA }
PBS := { DATA }
CIR := { DATA }
CBS := { DATA }
```

# Digests

```shell
psabpf-ctl digest get pipe ID DIGEST_NAME
psabpf-ctl digest get-all pipe ID DIGEST_NAME
```

# Counters

```shell
psabpf-ctl counter get pipe ID COUNTER_NAME [key DATA]
psabpf-ctl counter set pipe ID COUNTER_NAME [key DATA] value COUNTER_VALUE
psabpf-ctl counter reset pipe ID COUNTER_NAME [key DATA]

COUNTER_VALUE := { BYTES | PACKETS | BYTES:PACKETS }
```

# Registers

```shell
psabpf-ctl register get pipe ID REGISTER_NAME [index DATA]
psabpf-ctl register set pipe ID REGISTER_NAME index DATA value REGISTER_VALUE

REGISTER_VALUE := { DATA }
```

# Value set

```shell
psabpf-ctl value-set insert pipe ID VALUE_SET_NAME value DATA
psabpf-ctl value-set delete pipe ID VALUE_SET_NAME value DATA
psabpf-ctl value-set get pipe ID VALUE_SET_NAME
```
