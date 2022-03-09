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

#ifndef P4C_PSABPF_METER_H
#define P4C_PSABPF_METER_H

#ifndef METER_PERIOD_MIN
#define METER_PERIOD_MIN 100
#endif

#ifndef NS_IN_S
#define NS_IN_S (uint64_t) 1e9
#endif

typedef struct {
    psabpf_meter_value_t pir_period;
    psabpf_meter_value_t pir_unit_per_period;
    psabpf_meter_value_t cir_period;
    psabpf_meter_value_t cir_unit_per_period;
    psabpf_meter_value_t pbs;
    psabpf_meter_value_t cbs;
    psabpf_meter_value_t pbs_left;
    psabpf_meter_value_t cbs_left;
    psabpf_meter_value_t time_p;
    psabpf_meter_value_t time_c;
} psabpf_meter_data_t;

#define DIRECT_METER_SIZE sizeof(psabpf_meter_data_t)

int convert_meter_entry_to_data(psabpf_meter_entry_t *entry, psabpf_meter_data_t *data);

#endif  /* P4C_PSABPF_METER_H */
