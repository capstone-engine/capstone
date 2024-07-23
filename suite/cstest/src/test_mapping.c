// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_mappings.h"
#include "../../../utils.h"

static inline uint32_t cs_enum_get_val(const char *id, bool *found) {
	assert(id);
	size_t map_size = ARR_SIZE(cs_enum_map);
	size_t id_len = strlen(id);
	for (size_t i = 0, ti = (map_size / 2); i < id_len && ti < map_size;) {
		size_t j = i;
		size_t entry_len = strlen(cs_enum_map[ti].id);
		while (j < entry_len && i < id_len && id[i] == cs_enum_map[ti].id[j]) {
			++j, ++i;
		}
		if (i == id_len && j == entry_len) {
			*found = true;
			return cs_enum_map[ti].val;
		}

		ti = (j >= entry_len || id[i] > cs_enum_map[ti].id[j]) ? ti + ((map_size - ti) / 2) + 1 : (ti / 2);
	}
	*found = false;
	return 0;
}

