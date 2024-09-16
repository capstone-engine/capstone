# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import capstone as cs

configs = {
    "CS_OPT_DETAIL": {"type": cs.CS_OPT_DETAIL, "val": cs.CS_OPT_ON},
    "CS_OPT_DETAIL_REAL": {
        "type": cs.CS_OPT_DETAIL,
        "val": cs.CS_OPT_DETAIL_REAL | cs.CS_OPT_ON,
    },
    "CS_OPT_SKIPDATA": {"type": cs.CS_OPT_SKIPDATA, "val": cs.CS_OPT_ON},
    "CS_OPT_UNSIGNED": {"type": cs.CS_OPT_UNSIGNED, "val": cs.CS_OPT_ON},
    "CS_OPT_ONLY_OFFSET_BRANCH": {
        "type": cs.CS_OPT_ONLY_OFFSET_BRANCH,
        "val": cs.CS_OPT_ON,
    },
    "CS_OPT_SYNTAX_DEFAULT": {
        "type": cs.CS_OPT_SYNTAX,
        "val": cs.CS_OPT_SYNTAX_DEFAULT,
    },
    "CS_OPT_SYNTAX_INTEL": {"type": cs.CS_OPT_SYNTAX, "val": cs.CS_OPT_SYNTAX_INTEL},
    "CS_OPT_SYNTAX_ATT": {"type": cs.CS_OPT_SYNTAX, "val": cs.CS_OPT_SYNTAX_ATT},
    "CS_OPT_SYNTAX_NOREGNAME": {
        "type": cs.CS_OPT_SYNTAX,
        "val": cs.CS_OPT_SYNTAX_NOREGNAME,
    },
    "CS_OPT_SYNTAX_MASM": {"type": cs.CS_OPT_SYNTAX, "val": cs.CS_OPT_SYNTAX_MASM},
    "CS_OPT_SYNTAX_MOTOROLA": {
        "type": cs.CS_OPT_SYNTAX,
        "val": cs.CS_OPT_SYNTAX_MOTOROLA,
    },
    "CS_OPT_SYNTAX_CS_REG_ALIAS": {
        "type": cs.CS_OPT_SYNTAX,
        "val": cs.CS_OPT_SYNTAX_CS_REG_ALIAS,
    },
    "CS_OPT_SYNTAX_PERCENT": {
        "type": cs.CS_OPT_SYNTAX,
        "val": cs.CS_OPT_SYNTAX_PERCENT,
    },
    "CS_OPT_SYNTAX_NO_DOLLAR": {
        "type": cs.CS_OPT_SYNTAX,
        "val": cs.CS_OPT_SYNTAX_NO_DOLLAR,
    },
}
