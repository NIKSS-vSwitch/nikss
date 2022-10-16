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

#ifndef __NIKSS_METER_H
#define __NIKSS_METER_H

#include <nikss.h>

#ifndef METER_PERIOD_MIN
#define METER_PERIOD_MIN 100
#endif

#ifndef NS_IN_S
#define NS_IN_S (uint64_t) 1e9
#endif

typedef struct {
    nikss_meter_value_t pir_period;
    nikss_meter_value_t pir_unit_per_period;
    nikss_meter_value_t cir_period;
    nikss_meter_value_t cir_unit_per_period;
    nikss_meter_value_t pbs;
    nikss_meter_value_t cbs;
    nikss_meter_value_t pbs_left;
    nikss_meter_value_t cbs_left;
    nikss_meter_value_t time_p;
    nikss_meter_value_t time_c;
} nikss_meter_data_t;

#define DIRECT_METER_SIZE sizeof(nikss_meter_data_t)

int convert_meter_entry_to_data(const nikss_meter_entry_t *entry, nikss_meter_data_t *data);
int convert_meter_data_to_entry(const nikss_meter_data_t *data, nikss_meter_entry_t *entry);

#endif  /* __NIKSS_METER_H */
