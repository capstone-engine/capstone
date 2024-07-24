// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_mapping.h"
#include "../../../utils.h"

uint32_t cs_enum_get_val(const char *id, bool *found)
{
	assert(id && found);
	size_t l = 0;
	size_t r = ARR_SIZE(cs_enum_map);
	size_t id_len = strlen(id);

	while (l <= r) {
		size_t m = (l + r) / 2;
		size_t j = 0;
		size_t i = 0;
		size_t entry_len = strlen(cs_enum_map[m].id);

		while (j < entry_len && i < id_len && id[i] == cs_enum_map[m].id[j]) {
			++j, ++i;
		}
		if (i == id_len && j == entry_len) {
			*found = true;
			return cs_enum_map[m].val;
		}

		if (id[i] < cs_enum_map[m].id[j]) {
			r = m - 1;
		} else if (id[i] > cs_enum_map[m].id[j]) {
			l = m + 1;
		}
		if (m == 0 || (l + r) / 2 >= ARR_SIZE(cs_enum_map)) {
			// Break before we go out of bounds.
			break;
		}
	}
	*found = false;
	return 0;
}
