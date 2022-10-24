To see how to use C API let's look at source code of [CLI implementation](../CLI).

**Note:** The library needs `root` privileges to work correctly.

# Design principles

The public C API exported by this library has the following properties:
- All the names of structures, enums, functions and data types have common prefix `nikss_`.
- All the names of enum values and macros have common prefix `NIKSS_`.
- All the names are grouped by infix, ignoring the letter case. For example objects (structures, functions, etc.) related
  to tables have infix `table_` and names of them will start with `nikss_table_`.
- The last part of the names (postfix) denotes the purpose of the object (structures, functions, etc.), e.g. functions ended
  with `free` will release all resources allocated for instance of the object.
- All the functions operates on instances of structures or typedefs, called `context` or `ctx` for short. Each context must
  be initialized (`init` postfix) before use and freed when no more needed (`free` postfix).
- The content of structures are not considered as a public API, can change at any time. Always use provided functions to
  operate on instances of objects.
- Instances of objects created by the API (returned as a pointer) also must be freed after used.
- In most cases, functions return `0` (`NO_ERROR` constant) or a valid pointer (not `NULL`) on success. In case of an error,
  an error code (a value from the POSIX standard) or `NULL` pointer is returned and a message might be printed on `stderr`
  (some functions print to `stdout` but it is considered to change). Functions that return special values, like data length,
  member reference, etc. have own error values.
- Passing `NULL` pointer to any functions is safe (but not useful). Arguments are validated and error is returned if they
  are required.
- All instances of objects are movable, but not copyable. Pointers acquired using given instance after move are invalid
  (such functionalities use memory space inside context).
- Data passed to or from functions are considered to be a plain binary in the host byte order.

# Basic usage

## Header files

The table below shows NIKSS functionalities and a corresponding header that have to be included to use API for a given functionality.

| Functionality                                                                                                                        | Header file         |
|--------------------------------------------------------------------------------------------------------------------------------------|---------------------|
| `ActionProfile`,<br/>`ActionSelector`,<br/>`Counter`,<br/>`DirectCounter`,<br/>`DirectMeter`,<br/>`Meter`,<br/>`Register`,<br/>Table | `nikss.h`           |
| Clone session,<br/>Multicast group                                                                                                   | `nikss_pre.h`       |
| `Digest`                                                                                                                             | `nikss_digest.h`    |
| Pipeline and port management                                                                                                         | `nikss_pipeline.h`  |
| `value_set`                                                                                                                          | `nikss_value_set.h` |

## Pipeline

To be able to manage any P4 object, pipeline context `nikss_context_t` is mandatory. Following use is minimal and has no
effect on operating system:
```c
nikss_context_t nikss_ctx;
nikss_context_init(&nikss_ctx);
nikss_context_set_pipeline(&nikss_ctx, /* ID of the pipeline to be used. */);

/* Other calls to the NIKSS library. */

nikss_context_free(&nikss_ctx);
```

## P4 extern context

An appropriate context is also required to use any of P4 externs. The context must be initialized and set up (using name) for an operation. One
context variable can be used for one extern instance during program execution. The below snippet shows a sample  usage of nikss API for P4 tables:
```c
nikss_table_entry_ctx_t table_ctx;
nikss_table_entry_ctx_init(&table_ctx);
nikss_table_entry_ctx_tblname(&nikss_ctx, &table_ctx, /* Table name */);

/* Operate on table using ctx. */

nikss_table_entry_ctx_free(&table_ctx);
```

The table below lists externs and their context:

| Extern                                | Context type                      | Set up function                  | Notes                                                                                                                                                                                   |
|---------------------------------------|-----------------------------------|----------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ActionProfile`,<br/>`ActionSelector` | `nikss_action_selector_context_t` | `nikss_action_selector_ctx_name` | Both externs use the same API, but functions related to groups are not available for `ActionProfile` (this can be checked using function `nikss_action_selector_has_group_capability`). |
| Clone session                         | `nikss_clone_session_ctx_t`       | `nikss_clone_session_id`         |
| `Counter`                             | `nikss_counter_context_t`         | `nikss_counter_ctx_name`         |
| `Digest`                              | `nikss_digest_context_t`          | `nikss_digest_ctx_name`          |
| `DirectCounter`                       | `nikss_direct_counter_context_t`  | `nikss_direct_counter_ctx_name`  | Usable only within Table.                                                                                                                                                               |
| `DirectMeter`                         | `nikss_direct_meter_context_t`    | `nikss_direct_meter_ctx_name`    | Usable only within Table.                                                                                                                                                               |
| `Meter`                               | `nikss_meter_ctx_t`               | `nikss_meter_ctx_name`           |
| Multicast group                       | `nikss_mcast_grp_ctx_t`           | `nikss_mcast_grp_id`             |
| `Register`                            | `nikss_register_context_t`        | `nikss_register_ctx_name`        |
| Table                                 | `nikss_table_entry_ctx_t`         | `nikss_table_entry_ctx_tblname`  |
| `value_set`                           | `nikss_value_set_context_t`       | `nikss_value_set_context_name`   |

## P4 extern entries

A context itself is unable to alter entries in an extern, except for deleting all of entries. For this purpose, `entry`
objects, which operates on a single entry or all entries. Possible operations (not available for all externs) for such
entries are:
- **add** or **insert**: add a new entry which did not exist before for given key/index.
- **update**: modify value of an existing entry or of all entries if key/index is not provided within entry.
- **del**: remove an existing entry or all entries if key/index is not provided within entry.
- **get**: get value of a single entry for provided key/index within entry.
- **get_next**: get value and key/index of a next entry.

Sample usage of a table entry is:
```c
nikss_table_entry_t entry;
nikss_table_entry_init(&entry);

/* Create entry */

nikss_table_entry_add(&table_ctx, &entry);
nikss_table_entry_free(&entry);
```

Table below summarizes externs and type of entries.

| Extern           | Entry type                                                                            | Notes                                                                     |
|------------------|---------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| `ActionProfile`  | `nikss_action_selector_member_context_t`                                              | The same type as for `ActionSelector`.                                    |
| `ActionSelector` | `nikss_action_selector_member_context_t`,<br/>`nikss_action_selector_group_context_t` | Groups and members are different things.                                  |
| Clone session    | `nikss_clone_session_entry_t`                                                         |
| `Counter`        | `nikss_counter_entry_t`                                                               |
| `Digest`         | `nikss_digest_t`                                                                      |
| `DirectCounter`  | `nikss_direct_counter_entry_t`                                                        | 
| `DirectMeter`    | `nikss_direct_meter_entry_t`                                                          | 
| `Meter`          | `nikss_meter_entry_t`                                                                 |
| Multicast group  | `nikss_mcast_grp_member_t`                                                            |
| `Register`       | `nikss_register_entry_t`                                                              |
| Table            | `nikss_table_entry_t`                                                                 |
| `value_set`      | `nikss_table_entry_t`                                                                 | Due to https://github.com/NIKSS-vSwitch/nikss/issues/71 might be changed. |

The best way to find out what can be done with entries is to search headers files for functions that takes an argument with
desired type.
