# CS_ARCH_AARCH64, 0, None
0x20,0x00,0x02,0x0e = tbl v0.8b, {v1.16b}, v2.8b
0x20,0x20,0x02,0x0e = tbl v0.8b, {v1.16b, v2.16b}, v2.8b
0x20,0x40,0x02,0x0e = tbl v0.8b, {v1.16b, v2.16b, v3.16b}, v2.8b
0x20,0x60,0x02,0x0e = tbl v0.8b, {v1.16b, v2.16b, v3.16b, v4.16b}, v2.8b
0xe0,0x63,0x02,0x0e = tbl v0.8b, {v31.16b, v0.16b, v1.16b, v2.16b}, v2.8b
0x20,0x00,0x02,0x4e = tbl v0.16b, {v1.16b}, v2.16b
0x20,0x20,0x02,0x4e = tbl v0.16b, {v1.16b, v2.16b}, v2.16b
0x20,0x40,0x02,0x4e = tbl v0.16b, {v1.16b, v2.16b, v3.16b}, v2.16b
0x20,0x60,0x02,0x4e = tbl v0.16b, {v1.16b, v2.16b, v3.16b, v4.16b}, v2.16b
0xc0,0x63,0x02,0x4e = tbl v0.16b, {v30.16b, v31.16b, v0.16b, v1.16b}, v2.16b
0x20,0x10,0x02,0x0e = tbx v0.8b, {v1.16b}, v2.8b
0x20,0x30,0x02,0x0e = tbx v0.8b, {v1.16b, v2.16b}, v2.8b
0x20,0x50,0x02,0x0e = tbx v0.8b, {v1.16b, v2.16b, v3.16b}, v2.8b
0x20,0x70,0x02,0x0e = tbx v0.8b, {v1.16b, v2.16b, v3.16b, v4.16b}, v2.8b
0xe0,0x73,0x02,0x0e = tbx v0.8b, {v31.16b, v0.16b, v1.16b, v2.16b}, v2.8b
0x20,0x10,0x02,0x4e = tbx v0.16b, {v1.16b}, v2.16b
0x20,0x30,0x02,0x4e = tbx v0.16b, {v1.16b, v2.16b}, v2.16b
0x20,0x50,0x02,0x4e = tbx v0.16b, {v1.16b, v2.16b, v3.16b}, v2.16b
0x20,0x70,0x02,0x4e = tbx v0.16b, {v1.16b, v2.16b, v3.16b, v4.16b}, v2.16b
0xc0,0x73,0x02,0x4e = tbx v0.16b, {v30.16b, v31.16b, v0.16b, v1.16b}, v2.16b
