/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

static const AT ATsList[] = {
  { "s1e1r",  0x3C0 }, // 0
  { "s1e2r",  0x23C0 }, // 1
  { "s1e3r",  0x33C0 }, // 2
  { "s1e1w",  0x3C1 }, // 3
  { "s1e2w",  0x23C1 }, // 4
  { "s1e3w",  0x33C1 }, // 5
  { "s1e0r",  0x3C2 }, // 6
  { "s1e0w",  0x3C3 }, // 7
  { "s12e1r",  0x23C4 }, // 8
  { "s12e1w",  0x23C5 }, // 9
  { "s12e0r",  0x23C6 }, // 10
  { "s12e0w",  0x23C7 }, // 11
  { "s1e1rp",  0x3C8 }, // 12
  { "s1e1wp",  0x3C9 }, // 13
};

const AT *lookupATByEncoding(uint16_t Encoding)
{
  unsigned int i;
  static const struct IndexType Index[] = {
    { 0x3C0, 0 },
    { 0x3C1, 3 },
    { 0x3C2, 6 },
    { 0x3C3, 7 },
    { 0x3C8, 12 },
    { 0x3C9, 13 },
    { 0x23C0, 1 },
    { 0x23C1, 4 },
    { 0x23C4, 8 },
    { 0x23C5, 9 },
    { 0x23C6, 10 },
    { 0x23C7, 11 },
    { 0x33C0, 2 },
    { 0x33C1, 5 },
  };

  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &ATsList[Index[i].index];
}

static const DB DBsList[] = {
  { "oshld", 0x1 }, // 0
  { "oshst", 0x2 }, // 1
  { "osh", 0x3 }, // 2
  { "nshld", 0x5 }, // 3
  { "nshst", 0x6 }, // 4
  { "nsh", 0x7 }, // 5
  { "ishld", 0x9 }, // 6
  { "ishst", 0xA }, // 7
  { "ish", 0xB }, // 8
  { "ld", 0xD }, // 9
  { "st", 0xE }, // 10
  { "sy", 0xF }, // 11
};

const DB *lookupDBByEncoding(uint16_t Encoding)
{
  unsigned int i;
  static const struct IndexType Index[] = {
    { 0x1, 0 },
    { 0x2, 1 },
    { 0x3, 2 },
    { 0x5, 3 },
    { 0x6, 4 },
    { 0x7, 5 },
    { 0x9, 6 },
    { 0xA, 7 },
    { 0xB, 8 },
    { 0xD, 9 },
    { 0xE, 10 },
    { 0xF, 11 },
  };

  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &DBsList[Index[i].index];
}

static const DC DCsList[] = {
  { "zva",  0x1BA1 }, // 0
  { "ivac",  0x3B1 }, // 1
  { "isw",  0x3B2 }, // 2
  { "cvac",  0x1BD1 }, // 3
  { "csw",  0x3D2 }, // 4
  { "cvau",  0x1BD9 }, // 5
  { "civac",  0x1BF1 }, // 6
  { "cisw",  0x3F2 }, // 7
  { "cvap",  0x1BE1 }, // 8
};

const DC *lookupDCByEncoding(uint16_t Encoding)
{
  unsigned int i;
  static const struct IndexType Index[] = {
    { 0x3B1, 1 },
    { 0x3B2, 2 },
    { 0x3D2, 4 },
    { 0x3F2, 7 },
    { 0x1BA1, 0 },
    { 0x1BD1, 3 },
    { 0x1BD9, 5 },
    { 0x1BE1, 8 },
    { 0x1BF1, 6 },
  };

  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &DCsList[Index[i].index];
}

static const IC ICsList[] = {
  { "ialluis", 0x388, false }, // 0
  { "iallu", 0x3a8, false }, // 1
  { "ivau", 0x1ba9, true }, // 2
};

const IC *lookupICByEncoding(uint16_t Encoding)
{
  unsigned int i;
  static const struct IndexType Index[] = {
    { 0x388, 0 },
    { 0x3A8, 1 },
    { 0x1BA9, 2 },
  };

  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &ICsList[Index[i].index];
}

static const TLBI TLBIsList[] = {
  { "ipas2e1is",  0x2401,  true }, // 0
  { "ipas2le1is",  0x2405,  true }, // 1
  { "vmalle1is",  0x418,  false }, // 2
  { "alle2is",  0x2418,  false }, // 3
  { "alle3is",  0x3418,  false }, // 4
  { "vae1is",  0x419,  true }, // 5
  { "vae2is",  0x2419,  true }, // 6
  { "vae3is",  0x3419,  true }, // 7
  { "aside1is",  0x41A,  true }, // 8
  { "vaae1is",  0x41B,  true }, // 9
  { "alle1is",  0x241C,  false }, // 10
  { "vale1is",  0x41D,  true }, // 11
  { "vale2is",  0x241D,  true }, // 12
  { "vale3is",  0x341D,  true }, // 13
  { "vmalls12e1is",  0x241E,  false }, // 14
  { "vaale1is",  0x41F,  true }, // 15
  { "ipas2e1",  0x2421,  true }, // 16
  { "ipas2le1",  0x2425,  true }, // 17
  { "vmalle1",  0x438,  false }, // 18
  { "alle2",  0x2438,  false }, // 19
  { "alle3",  0x3438,  false }, // 20
  { "vae1",  0x439,  true }, // 21
  { "vae2",  0x2439,  true }, // 22
  { "vae3",  0x3439,  true }, // 23
  { "aside1",  0x43A,  true }, // 24
  { "vaae1",  0x43B,  true }, // 25
  { "alle1",  0x243C,  false }, // 26
  { "vale1",  0x43D,  true }, // 27
  { "vale2",  0x243D,  true }, // 28
  { "vale3",  0x343D,  true }, // 29
  { "vmalls12e1",  0x243E,  false }, // 30
  { "vaale1",  0x43F,  true }, // 31
  { "vmalle1os",  0x408,  false }, // 32
  { "vae1os",  0x409,  true }, // 33
  { "aside1os",  0x40A,  true }, // 34
  { "vaae1os",  0x40B,  true }, // 35
  { "vale1os",  0x40D,  true }, // 36
  { "vaale1os",  0x40F,  true }, // 37
  { "ipas2e1os",  0x2420,  true }, // 38
  { "ipas2le1os",  0x2424,  true }, // 39
  { "vae2os",  0x2409,  true }, // 40
  { "vale2os",  0x240D,  true }, // 41
  { "vmalls12e1os",  0x240E,  false }, // 42
  { "vae3os",  0x3409,  true }, // 43
  { "vale3os",  0x340D,  true }, // 44
  { "alle2os",  0x2408,  false }, // 45
  { "alle1os",  0x240C,  false }, // 46
  { "alle3os",  0x3408,  false }, // 47
  { "rvae1",  0x431,  true }, // 48
  { "rvaae1",  0x433,  true }, // 49
  { "rvale1",  0x435,  true }, // 50
  { "rvaale1",  0x437,  true }, // 51
  { "rvae1is",  0x411,  true }, // 52
  { "rvaae1is",  0x413,  true }, // 53
  { "rvale1is",  0x415,  true }, // 54
  { "rvaale1is",  0x417,  true }, // 55
  { "rvae1os",  0x429,  true }, // 56
  { "rvaae1os",  0x42B,  true }, // 57
  { "rvale1os",  0x42D,  true }, // 58
  { "rvaale1os",  0x42F,  true }, // 59
  { "ripas2e1is",  0x2402,  true }, // 60
  { "ripas2le1is",  0x2406,  true }, // 61
  { "ripas2e1",  0x2422,  true }, // 62
  { "ripas2le1",  0x2426,  true }, // 63
  { "ripas2e1os",  0x2423,  true }, // 64
  { "ripas2le1os",  0x2427,  true }, // 65
  { "rvae2",  0x2431,  true }, // 66
  { "rvale2",  0x2435,  true }, // 67
  { "rvae2is",  0x2411,  true }, // 68
  { "rvale2is",  0x2415,  true }, // 69
  { "rvae2os",  0x2429,  true }, // 70
  { "rvale2os",  0x242D,  true }, // 71
  { "rvae3",  0x3431,  true }, // 72
  { "rvale3",  0x3435,  true }, // 73
  { "rvae3is",  0x3411,  true }, // 74
  { "rvale3is",  0x3415,  true }, // 75
  { "rvae3os",  0x3429,  true }, // 76
  { "rvale3os",  0x342D,  true }, // 77
};

const TLBI *lookupTLBIByEncoding(uint16_t Encoding)
{
  unsigned int i;
  static const struct IndexType Index[] = {
    { 0x408, 32 },
    { 0x409, 33 },
    { 0x40A, 34 },
    { 0x40B, 35 },
    { 0x40D, 36 },
    { 0x40F, 37 },
    { 0x411, 52 },
    { 0x413, 53 },
    { 0x415, 54 },
    { 0x417, 55 },
    { 0x418, 2 },
    { 0x419, 5 },
    { 0x41A, 8 },
    { 0x41B, 9 },
    { 0x41D, 11 },
    { 0x41F, 15 },
    { 0x429, 56 },
    { 0x42B, 57 },
    { 0x42D, 58 },
    { 0x42F, 59 },
    { 0x431, 48 },
    { 0x433, 49 },
    { 0x435, 50 },
    { 0x437, 51 },
    { 0x438, 18 },
    { 0x439, 21 },
    { 0x43A, 24 },
    { 0x43B, 25 },
    { 0x43D, 27 },
    { 0x43F, 31 },
    { 0x2401, 0 },
    { 0x2402, 60 },
    { 0x2405, 1 },
    { 0x2406, 61 },
    { 0x2408, 45 },
    { 0x2409, 40 },
    { 0x240C, 46 },
    { 0x240D, 41 },
    { 0x240E, 42 },
    { 0x2411, 68 },
    { 0x2415, 69 },
    { 0x2418, 3 },
    { 0x2419, 6 },
    { 0x241C, 10 },
    { 0x241D, 12 },
    { 0x241E, 14 },
    { 0x2420, 38 },
    { 0x2421, 16 },
    { 0x2422, 62 },
    { 0x2423, 64 },
    { 0x2424, 39 },
    { 0x2425, 17 },
    { 0x2426, 63 },
    { 0x2427, 65 },
    { 0x2429, 70 },
    { 0x242D, 71 },
    { 0x2431, 66 },
    { 0x2435, 67 },
    { 0x2438, 19 },
    { 0x2439, 22 },
    { 0x243C, 26 },
    { 0x243D, 28 },
    { 0x243E, 30 },
    { 0x3408, 47 },
    { 0x3409, 43 },
    { 0x340D, 44 },
    { 0x3411, 74 },
    { 0x3415, 75 },
    { 0x3418, 4 },
    { 0x3419, 7 },
    { 0x341D, 13 },
    { 0x3429, 76 },
    { 0x342D, 77 },
    { 0x3431, 72 },
    { 0x3435, 73 },
    { 0x3438, 20 },
    { 0x3439, 23 },
    { 0x343D, 29 },
  };

  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &TLBIsList[Index[i].index];
}

static const SVEPRFM SVEPRFMsList[] = {
  { "pldl1keep",  0x0 }, // 0
  { "pldl1strm",  0x1 }, // 1
  { "pldl2keep",  0x2 }, // 2
  { "pldl2strm",  0x3 }, // 3
  { "pldl3keep",  0x4 }, // 4
  { "pldl3strm",  0x5 }, // 5
  { "pstl1keep",  0x8 }, // 6
  { "pstl1strm",  0x9 }, // 7
  { "pstl2keep",  0xA }, // 8
  { "pstl2strm",  0xB }, // 9
  { "pstl3keep",  0xC }, // 10
  { "pstl3strm",  0xD }, // 11
};

const SVEPRFM *lookupSVEPRFMByEncoding(uint16_t Encoding)
{
  unsigned int i;
  static const struct IndexType Index[] = {
    { 0x0, 0 },
    { 0x1, 1 },
    { 0x2, 2 },
    { 0x3, 3 },
    { 0x4, 4 },
    { 0x5, 5 },
    { 0x8, 6 },
    { 0x9, 7 },
    { 0xA, 8 },
    { 0xB, 9 },
    { 0xC, 10 },
    { 0xD, 11 },
  };

  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &SVEPRFMsList[Index[i].index];
}

static const PRFM PRFMsList[] = {
  { "pldl1keep", 0x0 }, // 0
  { "pldl1strm", 0x1 }, // 1
  { "pldl2keep", 0x2 }, // 2
  { "pldl2strm", 0x3 }, // 3
  { "pldl3keep", 0x4 }, // 4
  { "pldl3strm", 0x5 }, // 5
  { "plil1keep", 0x8 }, // 6
  { "plil1strm", 0x9 }, // 7
  { "plil2keep", 0xa }, // 8
  { "plil2strm", 0xb }, // 9
  { "plil3keep", 0xc }, // 10
  { "plil3strm", 0xd }, // 11
  { "pstl1keep", 0x10 }, // 12
  { "pstl1strm", 0x11 }, // 13
  { "pstl2keep", 0x12 }, // 14
  { "pstl2strm", 0x13 }, // 15
  { "pstl3keep", 0x14 }, // 16
  { "pstl3strm", 0x15 }, // 17
};

const PRFM *lookupPRFMByEncoding(uint16_t Encoding)
{
  unsigned int i;
  static const struct IndexType Index[] = {
    { 0x0, 0 },
    { 0x1, 1 },
    { 0x2, 2 },
    { 0x3, 3 },
    { 0x4, 4 },
    { 0x5, 5 },
    { 0x8, 6 },
    { 0x9, 7 },
    { 0xA, 8 },
    { 0xB, 9 },
    { 0xC, 10 },
    { 0xD, 11 },
    { 0x10, 12 },
    { 0x11, 13 },
    { 0x12, 14 },
    { 0x13, 15 },
    { 0x14, 16 },
    { 0x15, 17 },
  };

  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &PRFMsList[Index[i].index];
}

static const PSB PSBsList[] = {
  { "csync", 0x11 }, // 0
};

const PSB *AArch64PSBHint_lookupPSBByEncoding(uint16_t Encoding)
{
  unsigned int i;
  static const struct IndexType Index[] = {
    { 0x11, 0 },
  };

  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &PSBsList[Index[i].index];
}

static const ISB ISBsList[] = {
  { "sy", 0xf }, // 0
};

const ISB *lookupISBByEncoding(uint16_t Encoding)
{
  unsigned int i;
  static const struct IndexType Index[] = {
    { 0xF, 0 },
  };

  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &ISBsList[Index[i].index];
}

static const TSB TSBsList[] = {
  { "csync",  0x0 }, // 0
};

const TSB *lookupTSBByEncoding(uint16_t Encoding)
{
  static const struct IndexType Index[] = {
    { 0x0, 0 },
  };

  if (Encoding >= ARR_SIZE(TSBsList))
    return NULL;
  else
    return &TSBsList[Index[Encoding].index];
}

static const SysReg SysRegsList[] = {
  { "mdccsr_el0",  0x9808,  true,  false }, // 0
  { "dbgdtrrx_el0",  0x9828,  true,  false }, // 1
  { "mdrar_el1",  0x8080,  true,  false }, // 2
  { "oslsr_el1",  0x808C,  true,  false }, // 3
  { "dbgauthstatus_el1",  0x83F6,  true,  false }, // 4
  { "pmceid0_el0",  0xDCE6,  true,  false }, // 5
  { "pmceid1_el0",  0xDCE7,  true,  false }, // 6
  { "midr_el1",  0xC000,  true,  false }, // 7
  { "ccsidr_el1",  0xC800,  true,  false }, // 8
  { "ccsidr2_el1",  0xC802,  true,  false }, // 9
  { "clidr_el1",  0xC801,  true,  false }, // 10
  { "ctr_el0",  0xD801,  true,  false }, // 11
  { "mpidr_el1",  0xC005,  true,  false }, // 12
  { "revidr_el1",  0xC006,  true,  false }, // 13
  { "aidr_el1",  0xC807,  true,  false }, // 14
  { "dczid_el0",  0xD807,  true,  false }, // 15
  { "id_pfr0_el1",  0xC008,  true,  false }, // 16
  { "id_pfr1_el1",  0xC009,  true,  false }, // 17
  { "id_dfr0_el1",  0xC00A,  true,  false }, // 18
  { "id_afr0_el1",  0xC00B,  true,  false }, // 19
  { "id_mmfr0_el1",  0xC00C,  true,  false }, // 20
  { "id_mmfr1_el1",  0xC00D,  true,  false }, // 21
  { "id_mmfr2_el1",  0xC00E,  true,  false }, // 22
  { "id_mmfr3_el1",  0xC00F,  true,  false }, // 23
  { "id_isar0_el1",  0xC010,  true,  false }, // 24
  { "id_isar1_el1",  0xC011,  true,  false }, // 25
  { "id_isar2_el1",  0xC012,  true,  false }, // 26
  { "id_isar3_el1",  0xC013,  true,  false }, // 27
  { "id_isar4_el1",  0xC014,  true,  false }, // 28
  { "id_isar5_el1",  0xC015,  true,  false }, // 29
  { "id_isar6_el1",  0xC017,  true,  false }, // 30
  { "id_aa64pfr0_el1",  0xC020,  true,  false }, // 31
  { "id_aa64pfr1_el1",  0xC021,  true,  false }, // 32
  { "id_aa64dfr0_el1",  0xC028,  true,  false }, // 33
  { "id_aa64dfr1_el1",  0xC029,  true,  false }, // 34
  { "id_aa64afr0_el1",  0xC02C,  true,  false }, // 35
  { "id_aa64afr1_el1",  0xC02D,  true,  false }, // 36
  { "id_aa64isar0_el1",  0xC030,  true,  false }, // 37
  { "id_aa64isar1_el1",  0xC031,  true,  false }, // 38
  { "id_aa64mmfr0_el1",  0xC038,  true,  false }, // 39
  { "id_aa64mmfr1_el1",  0xC039,  true,  false }, // 40
  { "id_aa64mmfr2_el1",  0xC03A,  true,  false }, // 41
  { "mvfr0_el1",  0xC018,  true,  false }, // 42
  { "mvfr1_el1",  0xC019,  true,  false }, // 43
  { "mvfr2_el1",  0xC01A,  true,  false }, // 44
  { "rvbar_el1",  0xC601,  true,  false }, // 45
  { "rvbar_el2",  0xE601,  true,  false }, // 46
  { "rvbar_el3",  0xF601,  true,  false }, // 47
  { "isr_el1",  0xC608,  true,  false }, // 48
  { "cntpct_el0",  0xDF01,  true,  false }, // 49
  { "cntvct_el0",  0xDF02,  true,  false }, // 50
  { "id_mmfr4_el1",  0xC016,  true,  false }, // 51
  { "trcstatr",  0x8818,  true,  false }, // 52
  { "trcidr8",  0x8806,  true,  false }, // 53
  { "trcidr9",  0x880E,  true,  false }, // 54
  { "trcidr10",  0x8816,  true,  false }, // 55
  { "trcidr11",  0x881E,  true,  false }, // 56
  { "trcidr12",  0x8826,  true,  false }, // 57
  { "trcidr13",  0x882E,  true,  false }, // 58
  { "trcidr0",  0x8847,  true,  false }, // 59
  { "trcidr1",  0x884F,  true,  false }, // 60
  { "trcidr2",  0x8857,  true,  false }, // 61
  { "trcidr3",  0x885F,  true,  false }, // 62
  { "trcidr4",  0x8867,  true,  false }, // 63
  { "trcidr5",  0x886F,  true,  false }, // 64
  { "trcidr6",  0x8877,  true,  false }, // 65
  { "trcidr7",  0x887F,  true,  false }, // 66
  { "trcoslsr",  0x888C,  true,  false }, // 67
  { "trcpdsr",  0x88AC,  true,  false }, // 68
  { "trcdevaff0",  0x8BD6,  true,  false }, // 69
  { "trcdevaff1",  0x8BDE,  true,  false }, // 70
  { "trclsr",  0x8BEE,  true,  false }, // 71
  { "trcauthstatus",  0x8BF6,  true,  false }, // 72
  { "trcdevarch",  0x8BFE,  true,  false }, // 73
  { "trcdevid",  0x8B97,  true,  false }, // 74
  { "trcdevtype",  0x8B9F,  true,  false }, // 75
  { "trcpidr4",  0x8BA7,  true,  false }, // 76
  { "trcpidr5",  0x8BAF,  true,  false }, // 77
  { "trcpidr6",  0x8BB7,  true,  false }, // 78
  { "trcpidr7",  0x8BBF,  true,  false }, // 79
  { "trcpidr0",  0x8BC7,  true,  false }, // 80
  { "trcpidr1",  0x8BCF,  true,  false }, // 81
  { "trcpidr2",  0x8BD7,  true,  false }, // 82
  { "trcpidr3",  0x8BDF,  true,  false }, // 83
  { "trccidr0",  0x8BE7,  true,  false }, // 84
  { "trccidr1",  0x8BEF,  true,  false }, // 85
  { "trccidr2",  0x8BF7,  true,  false }, // 86
  { "trccidr3",  0x8BFF,  true,  false }, // 87
  { "icc_iar1_el1",  0xC660,  true,  false }, // 88
  { "icc_iar0_el1",  0xC640,  true,  false }, // 89
  { "icc_hppir1_el1",  0xC662,  true,  false }, // 90
  { "icc_hppir0_el1",  0xC642,  true,  false }, // 91
  { "icc_rpr_el1",  0xC65B,  true,  false }, // 92
  { "ich_vtr_el2",  0xE659,  true,  false }, // 93
  { "ich_eisr_el2",  0xE65B,  true,  false }, // 94
  { "ich_elrsr_el2",  0xE65D,  true,  false }, // 95
  { "id_aa64zfr0_el1",  0xC024,  true,  false }, // 96
  { "lorid_el1",  0xC527,  true,  false }, // 97
  { "erridr_el1",  0xC298,  true,  false }, // 98
  { "erxfr_el1",  0xC2A0,  true,  false }, // 99
  { "dbgdtrtx_el0",  0x9828,  false,  true }, // 100
  { "oslar_el1",  0x8084,  false,  true }, // 101
  { "pmswinc_el0",  0xDCE4,  false,  true }, // 102
  { "trcoslar",  0x8884,  false,  true }, // 103
  { "trclar",  0x8BE6,  false,  true }, // 104
  { "icc_eoir1_el1",  0xC661,  false,  true }, // 105
  { "icc_eoir0_el1",  0xC641,  false,  true }, // 106
  { "icc_dir_el1",  0xC659,  false,  true }, // 107
  { "icc_sgi1r_el1",  0xC65D,  false,  true }, // 108
  { "icc_asgi1r_el1",  0xC65E,  false,  true }, // 109
  { "icc_sgi0r_el1",  0xC65F,  false,  true }, // 110
  { "osdtrrx_el1",  0x8002,  true,  true }, // 111
  { "osdtrtx_el1",  0x801A,  true,  true }, // 112
  { "teecr32_el1",  0x9000,  true,  true }, // 113
  { "mdccint_el1",  0x8010,  true,  true }, // 114
  { "mdscr_el1",  0x8012,  true,  true }, // 115
  { "dbgdtr_el0",  0x9820,  true,  true }, // 116
  { "oseccr_el1",  0x8032,  true,  true }, // 117
  { "dbgvcr32_el2",  0xA038,  true,  true }, // 118
  { "dbgbvr0_el1",  0x8004,  true,  true }, // 119
  { "dbgbvr1_el1",  0x800C,  true,  true }, // 120
  { "dbgbvr2_el1",  0x8014,  true,  true }, // 121
  { "dbgbvr3_el1",  0x801C,  true,  true }, // 122
  { "dbgbvr4_el1",  0x8024,  true,  true }, // 123
  { "dbgbvr5_el1",  0x802C,  true,  true }, // 124
  { "dbgbvr6_el1",  0x8034,  true,  true }, // 125
  { "dbgbvr7_el1",  0x803C,  true,  true }, // 126
  { "dbgbvr8_el1",  0x8044,  true,  true }, // 127
  { "dbgbvr9_el1",  0x804C,  true,  true }, // 128
  { "dbgbvr10_el1",  0x8054,  true,  true }, // 129
  { "dbgbvr11_el1",  0x805C,  true,  true }, // 130
  { "dbgbvr12_el1",  0x8064,  true,  true }, // 131
  { "dbgbvr13_el1",  0x806C,  true,  true }, // 132
  { "dbgbvr14_el1",  0x8074,  true,  true }, // 133
  { "dbgbvr15_el1",  0x807C,  true,  true }, // 134
  { "dbgbcr0_el1",  0x8005,  true,  true }, // 135
  { "dbgbcr1_el1",  0x800D,  true,  true }, // 136
  { "dbgbcr2_el1",  0x8015,  true,  true }, // 137
  { "dbgbcr3_el1",  0x801D,  true,  true }, // 138
  { "dbgbcr4_el1",  0x8025,  true,  true }, // 139
  { "dbgbcr5_el1",  0x802D,  true,  true }, // 140
  { "dbgbcr6_el1",  0x8035,  true,  true }, // 141
  { "dbgbcr7_el1",  0x803D,  true,  true }, // 142
  { "dbgbcr8_el1",  0x8045,  true,  true }, // 143
  { "dbgbcr9_el1",  0x804D,  true,  true }, // 144
  { "dbgbcr10_el1",  0x8055,  true,  true }, // 145
  { "dbgbcr11_el1",  0x805D,  true,  true }, // 146
  { "dbgbcr12_el1",  0x8065,  true,  true }, // 147
  { "dbgbcr13_el1",  0x806D,  true,  true }, // 148
  { "dbgbcr14_el1",  0x8075,  true,  true }, // 149
  { "dbgbcr15_el1",  0x807D,  true,  true }, // 150
  { "dbgwvr0_el1",  0x8006,  true,  true }, // 151
  { "dbgwvr1_el1",  0x800E,  true,  true }, // 152
  { "dbgwvr2_el1",  0x8016,  true,  true }, // 153
  { "dbgwvr3_el1",  0x801E,  true,  true }, // 154
  { "dbgwvr4_el1",  0x8026,  true,  true }, // 155
  { "dbgwvr5_el1",  0x802E,  true,  true }, // 156
  { "dbgwvr6_el1",  0x8036,  true,  true }, // 157
  { "dbgwvr7_el1",  0x803E,  true,  true }, // 158
  { "dbgwvr8_el1",  0x8046,  true,  true }, // 159
  { "dbgwvr9_el1",  0x804E,  true,  true }, // 160
  { "dbgwvr10_el1",  0x8056,  true,  true }, // 161
  { "dbgwvr11_el1",  0x805E,  true,  true }, // 162
  { "dbgwvr12_el1",  0x8066,  true,  true }, // 163
  { "dbgwvr13_el1",  0x806E,  true,  true }, // 164
  { "dbgwvr14_el1",  0x8076,  true,  true }, // 165
  { "dbgwvr15_el1",  0x807E,  true,  true }, // 166
  { "dbgwcr0_el1",  0x8007,  true,  true }, // 167
  { "dbgwcr1_el1",  0x800F,  true,  true }, // 168
  { "dbgwcr2_el1",  0x8017,  true,  true }, // 169
  { "dbgwcr3_el1",  0x801F,  true,  true }, // 170
  { "dbgwcr4_el1",  0x8027,  true,  true }, // 171
  { "dbgwcr5_el1",  0x802F,  true,  true }, // 172
  { "dbgwcr6_el1",  0x8037,  true,  true }, // 173
  { "dbgwcr7_el1",  0x803F,  true,  true }, // 174
  { "dbgwcr8_el1",  0x8047,  true,  true }, // 175
  { "dbgwcr9_el1",  0x804F,  true,  true }, // 176
  { "dbgwcr10_el1",  0x8057,  true,  true }, // 177
  { "dbgwcr11_el1",  0x805F,  true,  true }, // 178
  { "dbgwcr12_el1",  0x8067,  true,  true }, // 179
  { "dbgwcr13_el1",  0x806F,  true,  true }, // 180
  { "dbgwcr14_el1",  0x8077,  true,  true }, // 181
  { "dbgwcr15_el1",  0x807F,  true,  true }, // 182
  { "teehbr32_el1",  0x9080,  true,  true }, // 183
  { "osdlr_el1",  0x809C,  true,  true }, // 184
  { "dbgprcr_el1",  0x80A4,  true,  true }, // 185
  { "dbgclaimset_el1",  0x83C6,  true,  true }, // 186
  { "dbgclaimclr_el1",  0x83CE,  true,  true }, // 187
  { "csselr_el1",  0xD000,  true,  true }, // 188
  { "vpidr_el2",  0xE000,  true,  true }, // 189
  { "vmpidr_el2",  0xE005,  true,  true }, // 190
  { "cpacr_el1",  0xC082,  true,  true }, // 191
  { "sctlr_el1",  0xC080,  true,  true }, // 192
  { "sctlr_el2",  0xE080,  true,  true }, // 193
  { "sctlr_el3",  0xF080,  true,  true }, // 194
  { "actlr_el1",  0xC081,  true,  true }, // 195
  { "actlr_el2",  0xE081,  true,  true }, // 196
  { "actlr_el3",  0xF081,  true,  true }, // 197
  { "hcr_el2",  0xE088,  true,  true }, // 198
  { "scr_el3",  0xF088,  true,  true }, // 199
  { "mdcr_el2",  0xE089,  true,  true }, // 200
  { "sder32_el3",  0xF089,  true,  true }, // 201
  { "cptr_el2",  0xE08A,  true,  true }, // 202
  { "cptr_el3",  0xF08A,  true,  true }, // 203
  { "hstr_el2",  0xE08B,  true,  true }, // 204
  { "hacr_el2",  0xE08F,  true,  true }, // 205
  { "mdcr_el3",  0xF099,  true,  true }, // 206
  { "ttbr0_el1",  0xC100,  true,  true }, // 207
  { "ttbr0_el2",  0xE100,  true,  true }, // 208
  { "ttbr0_el3",  0xF100,  true,  true }, // 209
  { "ttbr1_el1",  0xC101,  true,  true }, // 210
  { "tcr_el1",  0xC102,  true,  true }, // 211
  { "tcr_el2",  0xE102,  true,  true }, // 212
  { "tcr_el3",  0xF102,  true,  true }, // 213
  { "vttbr_el2",  0xE108,  true,  true }, // 214
  { "vtcr_el2",  0xE10A,  true,  true }, // 215
  { "dacr32_el2",  0xE180,  true,  true }, // 216
  { "spsr_el1",  0xC200,  true,  true }, // 217
  { "spsr_el2",  0xE200,  true,  true }, // 218
  { "spsr_el3",  0xF200,  true,  true }, // 219
  { "elr_el1",  0xC201,  true,  true }, // 220
  { "elr_el2",  0xE201,  true,  true }, // 221
  { "elr_el3",  0xF201,  true,  true }, // 222
  { "sp_el0",  0xC208,  true,  true }, // 223
  { "sp_el1",  0xE208,  true,  true }, // 224
  { "sp_el2",  0xF208,  true,  true }, // 225
  { "spsel",  0xC210,  true,  true }, // 226
  { "nzcv",  0xDA10,  true,  true }, // 227
  { "daif",  0xDA11,  true,  true }, // 228
  { "currentel",  0xC212,  true,  true }, // 229
  { "spsr_irq",  0xE218,  true,  true }, // 230
  { "spsr_abt",  0xE219,  true,  true }, // 231
  { "spsr_und",  0xE21A,  true,  true }, // 232
  { "spsr_fiq",  0xE21B,  true,  true }, // 233
  { "fpcr",  0xDA20,  true,  true }, // 234
  { "fpsr",  0xDA21,  true,  true }, // 235
  { "dspsr_el0",  0xDA28,  true,  true }, // 236
  { "dlr_el0",  0xDA29,  true,  true }, // 237
  { "ifsr32_el2",  0xE281,  true,  true }, // 238
  { "afsr0_el1",  0xC288,  true,  true }, // 239
  { "afsr0_el2",  0xE288,  true,  true }, // 240
  { "afsr0_el3",  0xF288,  true,  true }, // 241
  { "afsr1_el1",  0xC289,  true,  true }, // 242
  { "afsr1_el2",  0xE289,  true,  true }, // 243
  { "afsr1_el3",  0xF289,  true,  true }, // 244
  { "esr_el1",  0xC290,  true,  true }, // 245
  { "esr_el2",  0xE290,  true,  true }, // 246
  { "esr_el3",  0xF290,  true,  true }, // 247
  { "fpexc32_el2",  0xE298,  true,  true }, // 248
  { "far_el1",  0xC300,  true,  true }, // 249
  { "far_el2",  0xE300,  true,  true }, // 250
  { "far_el3",  0xF300,  true,  true }, // 251
  { "hpfar_el2",  0xE304,  true,  true }, // 252
  { "par_el1",  0xC3A0,  true,  true }, // 253
  { "pmcr_el0",  0xDCE0,  true,  true }, // 254
  { "pmcntenset_el0",  0xDCE1,  true,  true }, // 255
  { "pmcntenclr_el0",  0xDCE2,  true,  true }, // 256
  { "pmovsclr_el0",  0xDCE3,  true,  true }, // 257
  { "pmselr_el0",  0xDCE5,  true,  true }, // 258
  { "pmccntr_el0",  0xDCE8,  true,  true }, // 259
  { "pmxevtyper_el0",  0xDCE9,  true,  true }, // 260
  { "pmxevcntr_el0",  0xDCEA,  true,  true }, // 261
  { "pmuserenr_el0",  0xDCF0,  true,  true }, // 262
  { "pmintenset_el1",  0xC4F1,  true,  true }, // 263
  { "pmintenclr_el1",  0xC4F2,  true,  true }, // 264
  { "pmovsset_el0",  0xDCF3,  true,  true }, // 265
  { "mair_el1",  0xC510,  true,  true }, // 266
  { "mair_el2",  0xE510,  true,  true }, // 267
  { "mair_el3",  0xF510,  true,  true }, // 268
  { "amair_el1",  0xC518,  true,  true }, // 269
  { "amair_el2",  0xE518,  true,  true }, // 270
  { "amair_el3",  0xF518,  true,  true }, // 271
  { "vbar_el1",  0xC600,  true,  true }, // 272
  { "vbar_el2",  0xE600,  true,  true }, // 273
  { "vbar_el3",  0xF600,  true,  true }, // 274
  { "rmr_el1",  0xC602,  true,  true }, // 275
  { "rmr_el2",  0xE602,  true,  true }, // 276
  { "rmr_el3",  0xF602,  true,  true }, // 277
  { "contextidr_el1",  0xC681,  true,  true }, // 278
  { "tpidr_el0",  0xDE82,  true,  true }, // 279
  { "tpidr_el2",  0xE682,  true,  true }, // 280
  { "tpidr_el3",  0xF682,  true,  true }, // 281
  { "tpidrro_el0",  0xDE83,  true,  true }, // 282
  { "tpidr_el1",  0xC684,  true,  true }, // 283
  { "cntfrq_el0",  0xDF00,  true,  true }, // 284
  { "cntvoff_el2",  0xE703,  true,  true }, // 285
  { "cntkctl_el1",  0xC708,  true,  true }, // 286
  { "cnthctl_el2",  0xE708,  true,  true }, // 287
  { "cntp_tval_el0",  0xDF10,  true,  true }, // 288
  { "cnthp_tval_el2",  0xE710,  true,  true }, // 289
  { "cntps_tval_el1",  0xFF10,  true,  true }, // 290
  { "cntp_ctl_el0",  0xDF11,  true,  true }, // 291
  { "cnthp_ctl_el2",  0xE711,  true,  true }, // 292
  { "cntps_ctl_el1",  0xFF11,  true,  true }, // 293
  { "cntp_cval_el0",  0xDF12,  true,  true }, // 294
  { "cnthp_cval_el2",  0xE712,  true,  true }, // 295
  { "cntps_cval_el1",  0xFF12,  true,  true }, // 296
  { "cntv_tval_el0",  0xDF18,  true,  true }, // 297
  { "cntv_ctl_el0",  0xDF19,  true,  true }, // 298
  { "cntv_cval_el0",  0xDF1A,  true,  true }, // 299
  { "pmevcntr0_el0",  0xDF40,  true,  true }, // 300
  { "pmevcntr1_el0",  0xDF41,  true,  true }, // 301
  { "pmevcntr2_el0",  0xDF42,  true,  true }, // 302
  { "pmevcntr3_el0",  0xDF43,  true,  true }, // 303
  { "pmevcntr4_el0",  0xDF44,  true,  true }, // 304
  { "pmevcntr5_el0",  0xDF45,  true,  true }, // 305
  { "pmevcntr6_el0",  0xDF46,  true,  true }, // 306
  { "pmevcntr7_el0",  0xDF47,  true,  true }, // 307
  { "pmevcntr8_el0",  0xDF48,  true,  true }, // 308
  { "pmevcntr9_el0",  0xDF49,  true,  true }, // 309
  { "pmevcntr10_el0",  0xDF4A,  true,  true }, // 310
  { "pmevcntr11_el0",  0xDF4B,  true,  true }, // 311
  { "pmevcntr12_el0",  0xDF4C,  true,  true }, // 312
  { "pmevcntr13_el0",  0xDF4D,  true,  true }, // 313
  { "pmevcntr14_el0",  0xDF4E,  true,  true }, // 314
  { "pmevcntr15_el0",  0xDF4F,  true,  true }, // 315
  { "pmevcntr16_el0",  0xDF50,  true,  true }, // 316
  { "pmevcntr17_el0",  0xDF51,  true,  true }, // 317
  { "pmevcntr18_el0",  0xDF52,  true,  true }, // 318
  { "pmevcntr19_el0",  0xDF53,  true,  true }, // 319
  { "pmevcntr20_el0",  0xDF54,  true,  true }, // 320
  { "pmevcntr21_el0",  0xDF55,  true,  true }, // 321
  { "pmevcntr22_el0",  0xDF56,  true,  true }, // 322
  { "pmevcntr23_el0",  0xDF57,  true,  true }, // 323
  { "pmevcntr24_el0",  0xDF58,  true,  true }, // 324
  { "pmevcntr25_el0",  0xDF59,  true,  true }, // 325
  { "pmevcntr26_el0",  0xDF5A,  true,  true }, // 326
  { "pmevcntr27_el0",  0xDF5B,  true,  true }, // 327
  { "pmevcntr28_el0",  0xDF5C,  true,  true }, // 328
  { "pmevcntr29_el0",  0xDF5D,  true,  true }, // 329
  { "pmevcntr30_el0",  0xDF5E,  true,  true }, // 330
  { "pmccfiltr_el0",  0xDF7F,  true,  true }, // 331
  { "pmevtyper0_el0",  0xDF60,  true,  true }, // 332
  { "pmevtyper1_el0",  0xDF61,  true,  true }, // 333
  { "pmevtyper2_el0",  0xDF62,  true,  true }, // 334
  { "pmevtyper3_el0",  0xDF63,  true,  true }, // 335
  { "pmevtyper4_el0",  0xDF64,  true,  true }, // 336
  { "pmevtyper5_el0",  0xDF65,  true,  true }, // 337
  { "pmevtyper6_el0",  0xDF66,  true,  true }, // 338
  { "pmevtyper7_el0",  0xDF67,  true,  true }, // 339
  { "pmevtyper8_el0",  0xDF68,  true,  true }, // 340
  { "pmevtyper9_el0",  0xDF69,  true,  true }, // 341
  { "pmevtyper10_el0",  0xDF6A,  true,  true }, // 342
  { "pmevtyper11_el0",  0xDF6B,  true,  true }, // 343
  { "pmevtyper12_el0",  0xDF6C,  true,  true }, // 344
  { "pmevtyper13_el0",  0xDF6D,  true,  true }, // 345
  { "pmevtyper14_el0",  0xDF6E,  true,  true }, // 346
  { "pmevtyper15_el0",  0xDF6F,  true,  true }, // 347
  { "pmevtyper16_el0",  0xDF70,  true,  true }, // 348
  { "pmevtyper17_el0",  0xDF71,  true,  true }, // 349
  { "pmevtyper18_el0",  0xDF72,  true,  true }, // 350
  { "pmevtyper19_el0",  0xDF73,  true,  true }, // 351
  { "pmevtyper20_el0",  0xDF74,  true,  true }, // 352
  { "pmevtyper21_el0",  0xDF75,  true,  true }, // 353
  { "pmevtyper22_el0",  0xDF76,  true,  true }, // 354
  { "pmevtyper23_el0",  0xDF77,  true,  true }, // 355
  { "pmevtyper24_el0",  0xDF78,  true,  true }, // 356
  { "pmevtyper25_el0",  0xDF79,  true,  true }, // 357
  { "pmevtyper26_el0",  0xDF7A,  true,  true }, // 358
  { "pmevtyper27_el0",  0xDF7B,  true,  true }, // 359
  { "pmevtyper28_el0",  0xDF7C,  true,  true }, // 360
  { "pmevtyper29_el0",  0xDF7D,  true,  true }, // 361
  { "pmevtyper30_el0",  0xDF7E,  true,  true }, // 362
  { "trcprgctlr",  0x8808,  true,  true }, // 363
  { "trcprocselr",  0x8810,  true,  true }, // 364
  { "trcconfigr",  0x8820,  true,  true }, // 365
  { "trcauxctlr",  0x8830,  true,  true }, // 366
  { "trceventctl0r",  0x8840,  true,  true }, // 367
  { "trceventctl1r",  0x8848,  true,  true }, // 368
  { "trcstallctlr",  0x8858,  true,  true }, // 369
  { "trctsctlr",  0x8860,  true,  true }, // 370
  { "trcsyncpr",  0x8868,  true,  true }, // 371
  { "trcccctlr",  0x8870,  true,  true }, // 372
  { "trcbbctlr",  0x8878,  true,  true }, // 373
  { "trctraceidr",  0x8801,  true,  true }, // 374
  { "trcqctlr",  0x8809,  true,  true }, // 375
  { "trcvictlr",  0x8802,  true,  true }, // 376
  { "trcviiectlr",  0x880A,  true,  true }, // 377
  { "trcvissctlr",  0x8812,  true,  true }, // 378
  { "trcvipcssctlr",  0x881A,  true,  true }, // 379
  { "trcvdctlr",  0x8842,  true,  true }, // 380
  { "trcvdsacctlr",  0x884A,  true,  true }, // 381
  { "trcvdarcctlr",  0x8852,  true,  true }, // 382
  { "trcseqevr0",  0x8804,  true,  true }, // 383
  { "trcseqevr1",  0x880C,  true,  true }, // 384
  { "trcseqevr2",  0x8814,  true,  true }, // 385
  { "trcseqrstevr",  0x8834,  true,  true }, // 386
  { "trcseqstr",  0x883C,  true,  true }, // 387
  { "trcextinselr",  0x8844,  true,  true }, // 388
  { "trccntrldvr0",  0x8805,  true,  true }, // 389
  { "trccntrldvr1",  0x880D,  true,  true }, // 390
  { "trccntrldvr2",  0x8815,  true,  true }, // 391
  { "trccntrldvr3",  0x881D,  true,  true }, // 392
  { "trccntctlr0",  0x8825,  true,  true }, // 393
  { "trccntctlr1",  0x882D,  true,  true }, // 394
  { "trccntctlr2",  0x8835,  true,  true }, // 395
  { "trccntctlr3",  0x883D,  true,  true }, // 396
  { "trccntvr0",  0x8845,  true,  true }, // 397
  { "trccntvr1",  0x884D,  true,  true }, // 398
  { "trccntvr2",  0x8855,  true,  true }, // 399
  { "trccntvr3",  0x885D,  true,  true }, // 400
  { "trcimspec0",  0x8807,  true,  true }, // 401
  { "trcimspec1",  0x880F,  true,  true }, // 402
  { "trcimspec2",  0x8817,  true,  true }, // 403
  { "trcimspec3",  0x881F,  true,  true }, // 404
  { "trcimspec4",  0x8827,  true,  true }, // 405
  { "trcimspec5",  0x882F,  true,  true }, // 406
  { "trcimspec6",  0x8837,  true,  true }, // 407
  { "trcimspec7",  0x883F,  true,  true }, // 408
  { "trcrsctlr2",  0x8890,  true,  true }, // 409
  { "trcrsctlr3",  0x8898,  true,  true }, // 410
  { "trcrsctlr4",  0x88A0,  true,  true }, // 411
  { "trcrsctlr5",  0x88A8,  true,  true }, // 412
  { "trcrsctlr6",  0x88B0,  true,  true }, // 413
  { "trcrsctlr7",  0x88B8,  true,  true }, // 414
  { "trcrsctlr8",  0x88C0,  true,  true }, // 415
  { "trcrsctlr9",  0x88C8,  true,  true }, // 416
  { "trcrsctlr10",  0x88D0,  true,  true }, // 417
  { "trcrsctlr11",  0x88D8,  true,  true }, // 418
  { "trcrsctlr12",  0x88E0,  true,  true }, // 419
  { "trcrsctlr13",  0x88E8,  true,  true }, // 420
  { "trcrsctlr14",  0x88F0,  true,  true }, // 421
  { "trcrsctlr15",  0x88F8,  true,  true }, // 422
  { "trcrsctlr16",  0x8881,  true,  true }, // 423
  { "trcrsctlr17",  0x8889,  true,  true }, // 424
  { "trcrsctlr18",  0x8891,  true,  true }, // 425
  { "trcrsctlr19",  0x8899,  true,  true }, // 426
  { "trcrsctlr20",  0x88A1,  true,  true }, // 427
  { "trcrsctlr21",  0x88A9,  true,  true }, // 428
  { "trcrsctlr22",  0x88B1,  true,  true }, // 429
  { "trcrsctlr23",  0x88B9,  true,  true }, // 430
  { "trcrsctlr24",  0x88C1,  true,  true }, // 431
  { "trcrsctlr25",  0x88C9,  true,  true }, // 432
  { "trcrsctlr26",  0x88D1,  true,  true }, // 433
  { "trcrsctlr27",  0x88D9,  true,  true }, // 434
  { "trcrsctlr28",  0x88E1,  true,  true }, // 435
  { "trcrsctlr29",  0x88E9,  true,  true }, // 436
  { "trcrsctlr30",  0x88F1,  true,  true }, // 437
  { "trcrsctlr31",  0x88F9,  true,  true }, // 438
  { "trcssccr0",  0x8882,  true,  true }, // 439
  { "trcssccr1",  0x888A,  true,  true }, // 440
  { "trcssccr2",  0x8892,  true,  true }, // 441
  { "trcssccr3",  0x889A,  true,  true }, // 442
  { "trcssccr4",  0x88A2,  true,  true }, // 443
  { "trcssccr5",  0x88AA,  true,  true }, // 444
  { "trcssccr6",  0x88B2,  true,  true }, // 445
  { "trcssccr7",  0x88BA,  true,  true }, // 446
  { "trcsscsr0",  0x88C2,  true,  true }, // 447
  { "trcsscsr1",  0x88CA,  true,  true }, // 448
  { "trcsscsr2",  0x88D2,  true,  true }, // 449
  { "trcsscsr3",  0x88DA,  true,  true }, // 450
  { "trcsscsr4",  0x88E2,  true,  true }, // 451
  { "trcsscsr5",  0x88EA,  true,  true }, // 452
  { "trcsscsr6",  0x88F2,  true,  true }, // 453
  { "trcsscsr7",  0x88FA,  true,  true }, // 454
  { "trcsspcicr0",  0x8883,  true,  true }, // 455
  { "trcsspcicr1",  0x888B,  true,  true }, // 456
  { "trcsspcicr2",  0x8893,  true,  true }, // 457
  { "trcsspcicr3",  0x889B,  true,  true }, // 458
  { "trcsspcicr4",  0x88A3,  true,  true }, // 459
  { "trcsspcicr5",  0x88AB,  true,  true }, // 460
  { "trcsspcicr6",  0x88B3,  true,  true }, // 461
  { "trcsspcicr7",  0x88BB,  true,  true }, // 462
  { "trcpdcr",  0x88A4,  true,  true }, // 463
  { "trcacvr0",  0x8900,  true,  true }, // 464
  { "trcacvr1",  0x8910,  true,  true }, // 465
  { "trcacvr2",  0x8920,  true,  true }, // 466
  { "trcacvr3",  0x8930,  true,  true }, // 467
  { "trcacvr4",  0x8940,  true,  true }, // 468
  { "trcacvr5",  0x8950,  true,  true }, // 469
  { "trcacvr6",  0x8960,  true,  true }, // 470
  { "trcacvr7",  0x8970,  true,  true }, // 471
  { "trcacvr8",  0x8901,  true,  true }, // 472
  { "trcacvr9",  0x8911,  true,  true }, // 473
  { "trcacvr10",  0x8921,  true,  true }, // 474
  { "trcacvr11",  0x8931,  true,  true }, // 475
  { "trcacvr12",  0x8941,  true,  true }, // 476
  { "trcacvr13",  0x8951,  true,  true }, // 477
  { "trcacvr14",  0x8961,  true,  true }, // 478
  { "trcacvr15",  0x8971,  true,  true }, // 479
  { "trcacatr0",  0x8902,  true,  true }, // 480
  { "trcacatr1",  0x8912,  true,  true }, // 481
  { "trcacatr2",  0x8922,  true,  true }, // 482
  { "trcacatr3",  0x8932,  true,  true }, // 483
  { "trcacatr4",  0x8942,  true,  true }, // 484
  { "trcacatr5",  0x8952,  true,  true }, // 485
  { "trcacatr6",  0x8962,  true,  true }, // 486
  { "trcacatr7",  0x8972,  true,  true }, // 487
  { "trcacatr8",  0x8903,  true,  true }, // 488
  { "trcacatr9",  0x8913,  true,  true }, // 489
  { "trcacatr10",  0x8923,  true,  true }, // 490
  { "trcacatr11",  0x8933,  true,  true }, // 491
  { "trcacatr12",  0x8943,  true,  true }, // 492
  { "trcacatr13",  0x8953,  true,  true }, // 493
  { "trcacatr14",  0x8963,  true,  true }, // 494
  { "trcacatr15",  0x8973,  true,  true }, // 495
  { "trcdvcvr0",  0x8904,  true,  true }, // 496
  { "trcdvcvr1",  0x8924,  true,  true }, // 497
  { "trcdvcvr2",  0x8944,  true,  true }, // 498
  { "trcdvcvr3",  0x8964,  true,  true }, // 499
  { "trcdvcvr4",  0x8905,  true,  true }, // 500
  { "trcdvcvr5",  0x8925,  true,  true }, // 501
  { "trcdvcvr6",  0x8945,  true,  true }, // 502
  { "trcdvcvr7",  0x8965,  true,  true }, // 503
  { "trcdvcmr0",  0x8906,  true,  true }, // 504
  { "trcdvcmr1",  0x8926,  true,  true }, // 505
  { "trcdvcmr2",  0x8946,  true,  true }, // 506
  { "trcdvcmr3",  0x8966,  true,  true }, // 507
  { "trcdvcmr4",  0x8907,  true,  true }, // 508
  { "trcdvcmr5",  0x8927,  true,  true }, // 509
  { "trcdvcmr6",  0x8947,  true,  true }, // 510
  { "trcdvcmr7",  0x8967,  true,  true }, // 511
  { "trccidcvr0",  0x8980,  true,  true }, // 512
  { "trccidcvr1",  0x8990,  true,  true }, // 513
  { "trccidcvr2",  0x89A0,  true,  true }, // 514
  { "trccidcvr3",  0x89B0,  true,  true }, // 515
  { "trccidcvr4",  0x89C0,  true,  true }, // 516
  { "trccidcvr5",  0x89D0,  true,  true }, // 517
  { "trccidcvr6",  0x89E0,  true,  true }, // 518
  { "trccidcvr7",  0x89F0,  true,  true }, // 519
  { "trcvmidcvr0",  0x8981,  true,  true }, // 520
  { "trcvmidcvr1",  0x8991,  true,  true }, // 521
  { "trcvmidcvr2",  0x89A1,  true,  true }, // 522
  { "trcvmidcvr3",  0x89B1,  true,  true }, // 523
  { "trcvmidcvr4",  0x89C1,  true,  true }, // 524
  { "trcvmidcvr5",  0x89D1,  true,  true }, // 525
  { "trcvmidcvr6",  0x89E1,  true,  true }, // 526
  { "trcvmidcvr7",  0x89F1,  true,  true }, // 527
  { "trccidcctlr0",  0x8982,  true,  true }, // 528
  { "trccidcctlr1",  0x898A,  true,  true }, // 529
  { "trcvmidcctlr0",  0x8992,  true,  true }, // 530
  { "trcvmidcctlr1",  0x899A,  true,  true }, // 531
  { "trcitctrl",  0x8B84,  true,  true }, // 532
  { "trcclaimset",  0x8BC6,  true,  true }, // 533
  { "trcclaimclr",  0x8BCE,  true,  true }, // 534
  { "icc_bpr1_el1",  0xC663,  true,  true }, // 535
  { "icc_bpr0_el1",  0xC643,  true,  true }, // 536
  { "icc_pmr_el1",  0xC230,  true,  true }, // 537
  { "icc_ctlr_el1",  0xC664,  true,  true }, // 538
  { "icc_ctlr_el3",  0xF664,  true,  true }, // 539
  { "icc_sre_el1",  0xC665,  true,  true }, // 540
  { "icc_sre_el2",  0xE64D,  true,  true }, // 541
  { "icc_sre_el3",  0xF665,  true,  true }, // 542
  { "icc_igrpen0_el1",  0xC666,  true,  true }, // 543
  { "icc_igrpen1_el1",  0xC667,  true,  true }, // 544
  { "icc_igrpen1_el3",  0xF667,  true,  true }, // 545
  { "icc_seien_el1",  0xC668,  true,  true }, // 546
  { "icc_ap0r0_el1",  0xC644,  true,  true }, // 547
  { "icc_ap0r1_el1",  0xC645,  true,  true }, // 548
  { "icc_ap0r2_el1",  0xC646,  true,  true }, // 549
  { "icc_ap0r3_el1",  0xC647,  true,  true }, // 550
  { "icc_ap1r0_el1",  0xC648,  true,  true }, // 551
  { "icc_ap1r1_el1",  0xC649,  true,  true }, // 552
  { "icc_ap1r2_el1",  0xC64A,  true,  true }, // 553
  { "icc_ap1r3_el1",  0xC64B,  true,  true }, // 554
  { "ich_ap0r0_el2",  0xE640,  true,  true }, // 555
  { "ich_ap0r1_el2",  0xE641,  true,  true }, // 556
  { "ich_ap0r2_el2",  0xE642,  true,  true }, // 557
  { "ich_ap0r3_el2",  0xE643,  true,  true }, // 558
  { "ich_ap1r0_el2",  0xE648,  true,  true }, // 559
  { "ich_ap1r1_el2",  0xE649,  true,  true }, // 560
  { "ich_ap1r2_el2",  0xE64A,  true,  true }, // 561
  { "ich_ap1r3_el2",  0xE64B,  true,  true }, // 562
  { "ich_hcr_el2",  0xE658,  true,  true }, // 563
  { "ich_misr_el2",  0xE65A,  true,  true }, // 564
  { "ich_vmcr_el2",  0xE65F,  true,  true }, // 565
  { "ich_vseir_el2",  0xE64C,  true,  true }, // 566
  { "ich_lr0_el2",  0xE660,  true,  true }, // 567
  { "ich_lr1_el2",  0xE661,  true,  true }, // 568
  { "ich_lr2_el2",  0xE662,  true,  true }, // 569
  { "ich_lr3_el2",  0xE663,  true,  true }, // 570
  { "ich_lr4_el2",  0xE664,  true,  true }, // 571
  { "ich_lr5_el2",  0xE665,  true,  true }, // 572
  { "ich_lr6_el2",  0xE666,  true,  true }, // 573
  { "ich_lr7_el2",  0xE667,  true,  true }, // 574
  { "ich_lr8_el2",  0xE668,  true,  true }, // 575
  { "ich_lr9_el2",  0xE669,  true,  true }, // 576
  { "ich_lr10_el2",  0xE66A,  true,  true }, // 577
  { "ich_lr11_el2",  0xE66B,  true,  true }, // 578
  { "ich_lr12_el2",  0xE66C,  true,  true }, // 579
  { "ich_lr13_el2",  0xE66D,  true,  true }, // 580
  { "ich_lr14_el2",  0xE66E,  true,  true }, // 581
  { "ich_lr15_el2",  0xE66F,  true,  true }, // 582
  { "pan",  0xC213,  true,  true }, // 583
  { "lorsa_el1",  0xC520,  true,  true }, // 584
  { "lorea_el1",  0xC521,  true,  true }, // 585
  { "lorn_el1",  0xC522,  true,  true }, // 586
  { "lorc_el1",  0xC523,  true,  true }, // 587
  { "ttbr1_el2",  0xE101,  true,  true }, // 588
  { "contextidr_el2",  0xE681,  true,  true }, // 589
  { "cnthv_tval_el2",  0xE718,  true,  true }, // 590
  { "cnthv_cval_el2",  0xE71A,  true,  true }, // 591
  { "cnthv_ctl_el2",  0xE719,  true,  true }, // 592
  { "sctlr_el12",  0xE880,  true,  true }, // 593
  { "cpacr_el12",  0xE882,  true,  true }, // 594
  { "ttbr0_el12",  0xE900,  true,  true }, // 595
  { "ttbr1_el12",  0xE901,  true,  true }, // 596
  { "tcr_el12",  0xE902,  true,  true }, // 597
  { "afsr0_el12",  0xEA88,  true,  true }, // 598
  { "afsr1_el12",  0xEA89,  true,  true }, // 599
  { "esr_el12",  0xEA90,  true,  true }, // 600
  { "far_el12",  0xEB00,  true,  true }, // 601
  { "mair_el12",  0xED10,  true,  true }, // 602
  { "amair_el12",  0xED18,  true,  true }, // 603
  { "vbar_el12",  0xEE00,  true,  true }, // 604
  { "contextidr_el12",  0xEE81,  true,  true }, // 605
  { "cntkctl_el12",  0xEF08,  true,  true }, // 606
  { "cntp_tval_el02",  0xEF10,  true,  true }, // 607
  { "cntp_ctl_el02",  0xEF11,  true,  true }, // 608
  { "cntp_cval_el02",  0xEF12,  true,  true }, // 609
  { "cntv_tval_el02",  0xEF18,  true,  true }, // 610
  { "cntv_ctl_el02",  0xEF19,  true,  true }, // 611
  { "cntv_cval_el02",  0xEF1A,  true,  true }, // 612
  { "spsr_el12",  0xEA00,  true,  true }, // 613
  { "elr_el12",  0xEA01,  true,  true }, // 614
  { "uao",  0xC214,  true,  true }, // 615
  { "pmblimitr_el1",  0xC4D0,  true,  true }, // 616
  { "pmbptr_el1",  0xC4D1,  true,  true }, // 617
  { "pmbsr_el1",  0xC4D3,  true,  true }, // 618
  { "pmbidr_el1",  0xC4D7,  true,  true }, // 619
  { "pmscr_el2",  0xE4C8,  true,  true }, // 620
  { "pmscr_el12",  0xECC8,  true,  true }, // 621
  { "pmscr_el1",  0xC4C8,  true,  true }, // 622
  { "pmsicr_el1",  0xC4CA,  true,  true }, // 623
  { "pmsirr_el1",  0xC4CB,  true,  true }, // 624
  { "pmsfcr_el1",  0xC4CC,  true,  true }, // 625
  { "pmsevfr_el1",  0xC4CD,  true,  true }, // 626
  { "pmslatfr_el1",  0xC4CE,  true,  true }, // 627
  { "pmsidr_el1",  0xC4CF,  true,  true }, // 628
  { "errselr_el1",  0xC299,  true,  true }, // 629
  { "erxctlr_el1",  0xC2A1,  true,  true }, // 630
  { "erxstatus_el1",  0xC2A2,  true,  true }, // 631
  { "erxaddr_el1",  0xC2A3,  true,  true }, // 632
  { "erxmisc0_el1",  0xC2A8,  true,  true }, // 633
  { "erxmisc1_el1",  0xC2A9,  true,  true }, // 634
  { "disr_el1",  0xC609,  true,  true }, // 635
  { "vdisr_el2",  0xE609,  true,  true }, // 636
  { "vsesr_el2",  0xE293,  true,  true }, // 637
  { "apiakeylo_el1",  0xC108,  true,  true }, // 638
  { "apiakeyhi_el1",  0xC109,  true,  true }, // 639
  { "apibkeylo_el1",  0xC10A,  true,  true }, // 640
  { "apibkeyhi_el1",  0xC10B,  true,  true }, // 641
  { "apdakeylo_el1",  0xC110,  true,  true }, // 642
  { "apdakeyhi_el1",  0xC111,  true,  true }, // 643
  { "apdbkeylo_el1",  0xC112,  true,  true }, // 644
  { "apdbkeyhi_el1",  0xC113,  true,  true }, // 645
  { "apgakeylo_el1",  0xC118,  true,  true }, // 646
  { "apgakeyhi_el1",  0xC119,  true,  true }, // 647
  { "vstcr_el2",  0xE132,  true,  true }, // 648
  { "vsttbr_el2",  0xE130,  true,  true }, // 649
  { "cnthvs_tval_el2",  0xE720,  true,  true }, // 650
  { "cnthvs_cval_el2",  0xE722,  true,  true }, // 651
  { "cnthvs_ctl_el2",  0xE721,  true,  true }, // 652
  { "cnthps_tval_el2",  0xE728,  true,  true }, // 653
  { "cnthps_cval_el2",  0xE72A,  true,  true }, // 654
  { "cnthps_ctl_el2",  0xE729,  true,  true }, // 655
  { "sder32_el2",  0xE099,  true,  true }, // 656
  { "erxpfgctl_el1",  0xC2A5,  true,  true }, // 657
  { "erxpfgcdn_el1",  0xC2A6,  true,  true }, // 658
  { "erxts_el1",  0xC2AF,  true,  true }, // 659
  { "erxmisc2_el1",  0xC2AA,  true,  true }, // 660
  { "erxmisc3_el1",  0xC2AB,  true,  true }, // 661
  { "erxpfgf_el1",  0xC2A4,  true,  false }, // 662
  { "mpam0_el1",  0xC529,  true,  true }, // 663
  { "mpam1_el1",  0xC528,  true,  true }, // 664
  { "mpam2_el2",  0xE528,  true,  true }, // 665
  { "mpam3_el3",  0xF528,  true,  true }, // 666
  { "mpam1_el12",  0xED28,  true,  true }, // 667
  { "mpamhcr_el2",  0xE520,  true,  true }, // 668
  { "mpamvpmv_el2",  0xE521,  true,  true }, // 669
  { "mpamvpm0_el2",  0xE530,  true,  true }, // 670
  { "mpamvpm1_el2",  0xE531,  true,  true }, // 671
  { "mpamvpm2_el2",  0xE532,  true,  true }, // 672
  { "mpamvpm3_el2",  0xE533,  true,  true }, // 673
  { "mpamvpm4_el2",  0xE534,  true,  true }, // 674
  { "mpamvpm5_el2",  0xE535,  true,  true }, // 675
  { "mpamvpm6_el2",  0xE536,  true,  true }, // 676
  { "mpamvpm7_el2",  0xE537,  true,  true }, // 677
  { "mpamidr_el1",  0xC524,  true,  false }, // 678
  { "amcr_el0",  0xDE90,  true,  true }, // 679
  { "amcfgr_el0",  0xDE91,  true,  false }, // 680
  { "amcgcr_el0",  0xDE92,  true,  false }, // 681
  { "amuserenr_el0",  0xDE93,  true,  true }, // 682
  { "amcntenclr0_el0",  0xDE94,  true,  true }, // 683
  { "amcntenset0_el0",  0xDE95,  true,  true }, // 684
  { "amevcntr00_el0",  0xDEA0,  true,  true }, // 685
  { "amevcntr01_el0",  0xDEA1,  true,  true }, // 686
  { "amevcntr02_el0",  0xDEA2,  true,  true }, // 687
  { "amevcntr03_el0",  0xDEA3,  true,  true }, // 688
  { "amevtyper00_el0",  0xDEB0,  true,  false }, // 689
  { "amevtyper01_el0",  0xDEB1,  true,  false }, // 690
  { "amevtyper02_el0",  0xDEB2,  true,  false }, // 691
  { "amevtyper03_el0",  0xDEB3,  true,  false }, // 692
  { "amcntenclr1_el0",  0xDE98,  true,  true }, // 693
  { "amcntenset1_el0",  0xDE99,  true,  true }, // 694
  { "amevcntr10_el0",  0xDEE0,  true,  true }, // 695
  { "amevcntr11_el0",  0xDEE1,  true,  true }, // 696
  { "amevcntr12_el0",  0xDEE2,  true,  true }, // 697
  { "amevcntr13_el0",  0xDEE3,  true,  true }, // 698
  { "amevcntr14_el0",  0xDEE4,  true,  true }, // 699
  { "amevcntr15_el0",  0xDEE5,  true,  true }, // 700
  { "amevcntr16_el0",  0xDEE6,  true,  true }, // 701
  { "amevcntr17_el0",  0xDEE7,  true,  true }, // 702
  { "amevcntr18_el0",  0xDEE8,  true,  true }, // 703
  { "amevcntr19_el0",  0xDEE9,  true,  true }, // 704
  { "amevcntr110_el0",  0xDEEA,  true,  true }, // 705
  { "amevcntr111_el0",  0xDEEB,  true,  true }, // 706
  { "amevcntr112_el0",  0xDEEC,  true,  true }, // 707
  { "amevcntr113_el0",  0xDEED,  true,  true }, // 708
  { "amevcntr114_el0",  0xDEEE,  true,  true }, // 709
  { "amevcntr115_el0",  0xDEEF,  true,  true }, // 710
  { "amevtyper10_el0",  0xDEF0,  true,  true }, // 711
  { "amevtyper11_el0",  0xDEF1,  true,  true }, // 712
  { "amevtyper12_el0",  0xDEF2,  true,  true }, // 713
  { "amevtyper13_el0",  0xDEF3,  true,  true }, // 714
  { "amevtyper14_el0",  0xDEF4,  true,  true }, // 715
  { "amevtyper15_el0",  0xDEF5,  true,  true }, // 716
  { "amevtyper16_el0",  0xDEF6,  true,  true }, // 717
  { "amevtyper17_el0",  0xDEF7,  true,  true }, // 718
  { "amevtyper18_el0",  0xDEF8,  true,  true }, // 719
  { "amevtyper19_el0",  0xDEF9,  true,  true }, // 720
  { "amevtyper110_el0",  0xDEFA,  true,  true }, // 721
  { "amevtyper111_el0",  0xDEFB,  true,  true }, // 722
  { "amevtyper112_el0",  0xDEFC,  true,  true }, // 723
  { "amevtyper113_el0",  0xDEFD,  true,  true }, // 724
  { "amevtyper114_el0",  0xDEFE,  true,  true }, // 725
  { "amevtyper115_el0",  0xDEFF,  true,  true }, // 726
  { "trfcr_el1",  0xC091,  true,  true }, // 727
  { "trfcr_el2",  0xE091,  true,  true }, // 728
  { "trfcr_el12",  0xE891,  true,  true }, // 729
  { "dit",  0xDA15,  true,  true }, // 730
  { "vncr_el2",  0xE110,  true,  true }, // 731
  { "zcr_el1",  0xC090,  true,  true }, // 732
  { "zcr_el2",  0xE090,  true,  true }, // 733
  { "zcr_el3",  0xF090,  true,  true }, // 734
  { "zcr_el12",  0xE890,  true,  true }, // 735
  { "cpm_ioacc_ctl_el3",  0xFF90,  true,  true }, // 736
};

const SysReg *lookupSysRegByEncoding(uint16_t Encoding)
{
  unsigned int i;
  static const struct IndexType Index[] = {
    { 0x8002, 111 },
    { 0x8004, 119 },
    { 0x8005, 135 },
    { 0x8006, 151 },
    { 0x8007, 167 },
    { 0x800C, 120 },
    { 0x800D, 136 },
    { 0x800E, 152 },
    { 0x800F, 168 },
    { 0x8010, 114 },
    { 0x8012, 115 },
    { 0x8014, 121 },
    { 0x8015, 137 },
    { 0x8016, 153 },
    { 0x8017, 169 },
    { 0x801A, 112 },
    { 0x801C, 122 },
    { 0x801D, 138 },
    { 0x801E, 154 },
    { 0x801F, 170 },
    { 0x8024, 123 },
    { 0x8025, 139 },
    { 0x8026, 155 },
    { 0x8027, 171 },
    { 0x802C, 124 },
    { 0x802D, 140 },
    { 0x802E, 156 },
    { 0x802F, 172 },
    { 0x8032, 117 },
    { 0x8034, 125 },
    { 0x8035, 141 },
    { 0x8036, 157 },
    { 0x8037, 173 },
    { 0x803C, 126 },
    { 0x803D, 142 },
    { 0x803E, 158 },
    { 0x803F, 174 },
    { 0x8044, 127 },
    { 0x8045, 143 },
    { 0x8046, 159 },
    { 0x8047, 175 },
    { 0x804C, 128 },
    { 0x804D, 144 },
    { 0x804E, 160 },
    { 0x804F, 176 },
    { 0x8054, 129 },
    { 0x8055, 145 },
    { 0x8056, 161 },
    { 0x8057, 177 },
    { 0x805C, 130 },
    { 0x805D, 146 },
    { 0x805E, 162 },
    { 0x805F, 178 },
    { 0x8064, 131 },
    { 0x8065, 147 },
    { 0x8066, 163 },
    { 0x8067, 179 },
    { 0x806C, 132 },
    { 0x806D, 148 },
    { 0x806E, 164 },
    { 0x806F, 180 },
    { 0x8074, 133 },
    { 0x8075, 149 },
    { 0x8076, 165 },
    { 0x8077, 181 },
    { 0x807C, 134 },
    { 0x807D, 150 },
    { 0x807E, 166 },
    { 0x807F, 182 },
    { 0x8080, 2 },
    { 0x8084, 101 },
    { 0x808C, 3 },
    { 0x809C, 184 },
    { 0x80A4, 185 },
    { 0x83C6, 186 },
    { 0x83CE, 187 },
    { 0x83F6, 4 },
    { 0x8801, 374 },
    { 0x8802, 376 },
    { 0x8804, 383 },
    { 0x8805, 389 },
    { 0x8806, 53 },
    { 0x8807, 401 },
    { 0x8808, 363 },
    { 0x8809, 375 },
    { 0x880A, 377 },
    { 0x880C, 384 },
    { 0x880D, 390 },
    { 0x880E, 54 },
    { 0x880F, 402 },
    { 0x8810, 364 },
    { 0x8812, 378 },
    { 0x8814, 385 },
    { 0x8815, 391 },
    { 0x8816, 55 },
    { 0x8817, 403 },
    { 0x8818, 52 },
    { 0x881A, 379 },
    { 0x881D, 392 },
    { 0x881E, 56 },
    { 0x881F, 404 },
    { 0x8820, 365 },
    { 0x8825, 393 },
    { 0x8826, 57 },
    { 0x8827, 405 },
    { 0x882D, 394 },
    { 0x882E, 58 },
    { 0x882F, 406 },
    { 0x8830, 366 },
    { 0x8834, 386 },
    { 0x8835, 395 },
    { 0x8837, 407 },
    { 0x883C, 387 },
    { 0x883D, 396 },
    { 0x883F, 408 },
    { 0x8840, 367 },
    { 0x8842, 380 },
    { 0x8844, 388 },
    { 0x8845, 397 },
    { 0x8847, 59 },
    { 0x8848, 368 },
    { 0x884A, 381 },
    { 0x884D, 398 },
    { 0x884F, 60 },
    { 0x8852, 382 },
    { 0x8855, 399 },
    { 0x8857, 61 },
    { 0x8858, 369 },
    { 0x885D, 400 },
    { 0x885F, 62 },
    { 0x8860, 370 },
    { 0x8867, 63 },
    { 0x8868, 371 },
    { 0x886F, 64 },
    { 0x8870, 372 },
    { 0x8877, 65 },
    { 0x8878, 373 },
    { 0x887F, 66 },
    { 0x8881, 423 },
    { 0x8882, 439 },
    { 0x8883, 455 },
    { 0x8884, 103 },
    { 0x8889, 424 },
    { 0x888A, 440 },
    { 0x888B, 456 },
    { 0x888C, 67 },
    { 0x8890, 409 },
    { 0x8891, 425 },
    { 0x8892, 441 },
    { 0x8893, 457 },
    { 0x8898, 410 },
    { 0x8899, 426 },
    { 0x889A, 442 },
    { 0x889B, 458 },
    { 0x88A0, 411 },
    { 0x88A1, 427 },
    { 0x88A2, 443 },
    { 0x88A3, 459 },
    { 0x88A4, 463 },
    { 0x88A8, 412 },
    { 0x88A9, 428 },
    { 0x88AA, 444 },
    { 0x88AB, 460 },
    { 0x88AC, 68 },
    { 0x88B0, 413 },
    { 0x88B1, 429 },
    { 0x88B2, 445 },
    { 0x88B3, 461 },
    { 0x88B8, 414 },
    { 0x88B9, 430 },
    { 0x88BA, 446 },
    { 0x88BB, 462 },
    { 0x88C0, 415 },
    { 0x88C1, 431 },
    { 0x88C2, 447 },
    { 0x88C8, 416 },
    { 0x88C9, 432 },
    { 0x88CA, 448 },
    { 0x88D0, 417 },
    { 0x88D1, 433 },
    { 0x88D2, 449 },
    { 0x88D8, 418 },
    { 0x88D9, 434 },
    { 0x88DA, 450 },
    { 0x88E0, 419 },
    { 0x88E1, 435 },
    { 0x88E2, 451 },
    { 0x88E8, 420 },
    { 0x88E9, 436 },
    { 0x88EA, 452 },
    { 0x88F0, 421 },
    { 0x88F1, 437 },
    { 0x88F2, 453 },
    { 0x88F8, 422 },
    { 0x88F9, 438 },
    { 0x88FA, 454 },
    { 0x8900, 464 },
    { 0x8901, 472 },
    { 0x8902, 480 },
    { 0x8903, 488 },
    { 0x8904, 496 },
    { 0x8905, 500 },
    { 0x8906, 504 },
    { 0x8907, 508 },
    { 0x8910, 465 },
    { 0x8911, 473 },
    { 0x8912, 481 },
    { 0x8913, 489 },
    { 0x8920, 466 },
    { 0x8921, 474 },
    { 0x8922, 482 },
    { 0x8923, 490 },
    { 0x8924, 497 },
    { 0x8925, 501 },
    { 0x8926, 505 },
    { 0x8927, 509 },
    { 0x8930, 467 },
    { 0x8931, 475 },
    { 0x8932, 483 },
    { 0x8933, 491 },
    { 0x8940, 468 },
    { 0x8941, 476 },
    { 0x8942, 484 },
    { 0x8943, 492 },
    { 0x8944, 498 },
    { 0x8945, 502 },
    { 0x8946, 506 },
    { 0x8947, 510 },
    { 0x8950, 469 },
    { 0x8951, 477 },
    { 0x8952, 485 },
    { 0x8953, 493 },
    { 0x8960, 470 },
    { 0x8961, 478 },
    { 0x8962, 486 },
    { 0x8963, 494 },
    { 0x8964, 499 },
    { 0x8965, 503 },
    { 0x8966, 507 },
    { 0x8967, 511 },
    { 0x8970, 471 },
    { 0x8971, 479 },
    { 0x8972, 487 },
    { 0x8973, 495 },
    { 0x8980, 512 },
    { 0x8981, 520 },
    { 0x8982, 528 },
    { 0x898A, 529 },
    { 0x8990, 513 },
    { 0x8991, 521 },
    { 0x8992, 530 },
    { 0x899A, 531 },
    { 0x89A0, 514 },
    { 0x89A1, 522 },
    { 0x89B0, 515 },
    { 0x89B1, 523 },
    { 0x89C0, 516 },
    { 0x89C1, 524 },
    { 0x89D0, 517 },
    { 0x89D1, 525 },
    { 0x89E0, 518 },
    { 0x89E1, 526 },
    { 0x89F0, 519 },
    { 0x89F1, 527 },
    { 0x8B84, 532 },
    { 0x8B97, 74 },
    { 0x8B9F, 75 },
    { 0x8BA7, 76 },
    { 0x8BAF, 77 },
    { 0x8BB7, 78 },
    { 0x8BBF, 79 },
    { 0x8BC6, 533 },
    { 0x8BC7, 80 },
    { 0x8BCE, 534 },
    { 0x8BCF, 81 },
    { 0x8BD6, 69 },
    { 0x8BD7, 82 },
    { 0x8BDE, 70 },
    { 0x8BDF, 83 },
    { 0x8BE6, 104 },
    { 0x8BE7, 84 },
    { 0x8BEE, 71 },
    { 0x8BEF, 85 },
    { 0x8BF6, 72 },
    { 0x8BF7, 86 },
    { 0x8BFE, 73 },
    { 0x8BFF, 87 },
    { 0x9000, 113 },
    { 0x9080, 183 },
    { 0x9808, 0 },
    { 0x9820, 116 },
    { 0x9828, 1 },
    { 0x9828, 100 },
    { 0xA038, 118 },
    { 0xC000, 7 },
    { 0xC005, 12 },
    { 0xC006, 13 },
    { 0xC008, 16 },
    { 0xC009, 17 },
    { 0xC00A, 18 },
    { 0xC00B, 19 },
    { 0xC00C, 20 },
    { 0xC00D, 21 },
    { 0xC00E, 22 },
    { 0xC00F, 23 },
    { 0xC010, 24 },
    { 0xC011, 25 },
    { 0xC012, 26 },
    { 0xC013, 27 },
    { 0xC014, 28 },
    { 0xC015, 29 },
    { 0xC016, 51 },
    { 0xC017, 30 },
    { 0xC018, 42 },
    { 0xC019, 43 },
    { 0xC01A, 44 },
    { 0xC020, 31 },
    { 0xC021, 32 },
    { 0xC024, 96 },
    { 0xC028, 33 },
    { 0xC029, 34 },
    { 0xC02C, 35 },
    { 0xC02D, 36 },
    { 0xC030, 37 },
    { 0xC031, 38 },
    { 0xC038, 39 },
    { 0xC039, 40 },
    { 0xC03A, 41 },
    { 0xC080, 192 },
    { 0xC081, 195 },
    { 0xC082, 191 },
    { 0xC090, 732 },
    { 0xC091, 727 },
    { 0xC100, 207 },
    { 0xC101, 210 },
    { 0xC102, 211 },
    { 0xC108, 638 },
    { 0xC109, 639 },
    { 0xC10A, 640 },
    { 0xC10B, 641 },
    { 0xC110, 642 },
    { 0xC111, 643 },
    { 0xC112, 644 },
    { 0xC113, 645 },
    { 0xC118, 646 },
    { 0xC119, 647 },
    { 0xC200, 217 },
    { 0xC201, 220 },
    { 0xC208, 223 },
    { 0xC210, 226 },
    { 0xC212, 229 },
    { 0xC213, 583 },
    { 0xC214, 615 },
    { 0xC230, 537 },
    { 0xC288, 239 },
    { 0xC289, 242 },
    { 0xC290, 245 },
    { 0xC298, 98 },
    { 0xC299, 629 },
    { 0xC2A0, 99 },
    { 0xC2A1, 630 },
    { 0xC2A2, 631 },
    { 0xC2A3, 632 },
    { 0xC2A4, 662 },
    { 0xC2A5, 657 },
    { 0xC2A6, 658 },
    { 0xC2A8, 633 },
    { 0xC2A9, 634 },
    { 0xC2AA, 660 },
    { 0xC2AB, 661 },
    { 0xC2AF, 659 },
    { 0xC300, 249 },
    { 0xC3A0, 253 },
    { 0xC4C8, 622 },
    { 0xC4CA, 623 },
    { 0xC4CB, 624 },
    { 0xC4CC, 625 },
    { 0xC4CD, 626 },
    { 0xC4CE, 627 },
    { 0xC4CF, 628 },
    { 0xC4D0, 616 },
    { 0xC4D1, 617 },
    { 0xC4D3, 618 },
    { 0xC4D7, 619 },
    { 0xC4F1, 263 },
    { 0xC4F2, 264 },
    { 0xC510, 266 },
    { 0xC518, 269 },
    { 0xC520, 584 },
    { 0xC521, 585 },
    { 0xC522, 586 },
    { 0xC523, 587 },
    { 0xC524, 678 },
    { 0xC527, 97 },
    { 0xC528, 664 },
    { 0xC529, 663 },
    { 0xC600, 272 },
    { 0xC601, 45 },
    { 0xC602, 275 },
    { 0xC608, 48 },
    { 0xC609, 635 },
    { 0xC640, 89 },
    { 0xC641, 106 },
    { 0xC642, 91 },
    { 0xC643, 536 },
    { 0xC644, 547 },
    { 0xC645, 548 },
    { 0xC646, 549 },
    { 0xC647, 550 },
    { 0xC648, 551 },
    { 0xC649, 552 },
    { 0xC64A, 553 },
    { 0xC64B, 554 },
    { 0xC659, 107 },
    { 0xC65B, 92 },
    { 0xC65D, 108 },
    { 0xC65E, 109 },
    { 0xC65F, 110 },
    { 0xC660, 88 },
    { 0xC661, 105 },
    { 0xC662, 90 },
    { 0xC663, 535 },
    { 0xC664, 538 },
    { 0xC665, 540 },
    { 0xC666, 543 },
    { 0xC667, 544 },
    { 0xC668, 546 },
    { 0xC681, 278 },
    { 0xC684, 283 },
    { 0xC708, 286 },
    { 0xC800, 8 },
    { 0xC801, 10 },
    { 0xC802, 9 },
    { 0xC807, 14 },
    { 0xD000, 188 },
    { 0xD801, 11 },
    { 0xD807, 15 },
    { 0xDA10, 227 },
    { 0xDA11, 228 },
    { 0xDA15, 730 },
    { 0xDA20, 234 },
    { 0xDA21, 235 },
    { 0xDA28, 236 },
    { 0xDA29, 237 },
    { 0xDCE0, 254 },
    { 0xDCE1, 255 },
    { 0xDCE2, 256 },
    { 0xDCE3, 257 },
    { 0xDCE4, 102 },
    { 0xDCE5, 258 },
    { 0xDCE6, 5 },
    { 0xDCE7, 6 },
    { 0xDCE8, 259 },
    { 0xDCE9, 260 },
    { 0xDCEA, 261 },
    { 0xDCF0, 262 },
    { 0xDCF3, 265 },
    { 0xDE82, 279 },
    { 0xDE83, 282 },
    { 0xDE90, 679 },
    { 0xDE91, 680 },
    { 0xDE92, 681 },
    { 0xDE93, 682 },
    { 0xDE94, 683 },
    { 0xDE95, 684 },
    { 0xDE98, 693 },
    { 0xDE99, 694 },
    { 0xDEA0, 685 },
    { 0xDEA1, 686 },
    { 0xDEA2, 687 },
    { 0xDEA3, 688 },
    { 0xDEB0, 689 },
    { 0xDEB1, 690 },
    { 0xDEB2, 691 },
    { 0xDEB3, 692 },
    { 0xDEE0, 695 },
    { 0xDEE1, 696 },
    { 0xDEE2, 697 },
    { 0xDEE3, 698 },
    { 0xDEE4, 699 },
    { 0xDEE5, 700 },
    { 0xDEE6, 701 },
    { 0xDEE7, 702 },
    { 0xDEE8, 703 },
    { 0xDEE9, 704 },
    { 0xDEEA, 705 },
    { 0xDEEB, 706 },
    { 0xDEEC, 707 },
    { 0xDEED, 708 },
    { 0xDEEE, 709 },
    { 0xDEEF, 710 },
    { 0xDEF0, 711 },
    { 0xDEF1, 712 },
    { 0xDEF2, 713 },
    { 0xDEF3, 714 },
    { 0xDEF4, 715 },
    { 0xDEF5, 716 },
    { 0xDEF6, 717 },
    { 0xDEF7, 718 },
    { 0xDEF8, 719 },
    { 0xDEF9, 720 },
    { 0xDEFA, 721 },
    { 0xDEFB, 722 },
    { 0xDEFC, 723 },
    { 0xDEFD, 724 },
    { 0xDEFE, 725 },
    { 0xDEFF, 726 },
    { 0xDF00, 284 },
    { 0xDF01, 49 },
    { 0xDF02, 50 },
    { 0xDF10, 288 },
    { 0xDF11, 291 },
    { 0xDF12, 294 },
    { 0xDF18, 297 },
    { 0xDF19, 298 },
    { 0xDF1A, 299 },
    { 0xDF40, 300 },
    { 0xDF41, 301 },
    { 0xDF42, 302 },
    { 0xDF43, 303 },
    { 0xDF44, 304 },
    { 0xDF45, 305 },
    { 0xDF46, 306 },
    { 0xDF47, 307 },
    { 0xDF48, 308 },
    { 0xDF49, 309 },
    { 0xDF4A, 310 },
    { 0xDF4B, 311 },
    { 0xDF4C, 312 },
    { 0xDF4D, 313 },
    { 0xDF4E, 314 },
    { 0xDF4F, 315 },
    { 0xDF50, 316 },
    { 0xDF51, 317 },
    { 0xDF52, 318 },
    { 0xDF53, 319 },
    { 0xDF54, 320 },
    { 0xDF55, 321 },
    { 0xDF56, 322 },
    { 0xDF57, 323 },
    { 0xDF58, 324 },
    { 0xDF59, 325 },
    { 0xDF5A, 326 },
    { 0xDF5B, 327 },
    { 0xDF5C, 328 },
    { 0xDF5D, 329 },
    { 0xDF5E, 330 },
    { 0xDF60, 332 },
    { 0xDF61, 333 },
    { 0xDF62, 334 },
    { 0xDF63, 335 },
    { 0xDF64, 336 },
    { 0xDF65, 337 },
    { 0xDF66, 338 },
    { 0xDF67, 339 },
    { 0xDF68, 340 },
    { 0xDF69, 341 },
    { 0xDF6A, 342 },
    { 0xDF6B, 343 },
    { 0xDF6C, 344 },
    { 0xDF6D, 345 },
    { 0xDF6E, 346 },
    { 0xDF6F, 347 },
    { 0xDF70, 348 },
    { 0xDF71, 349 },
    { 0xDF72, 350 },
    { 0xDF73, 351 },
    { 0xDF74, 352 },
    { 0xDF75, 353 },
    { 0xDF76, 354 },
    { 0xDF77, 355 },
    { 0xDF78, 356 },
    { 0xDF79, 357 },
    { 0xDF7A, 358 },
    { 0xDF7B, 359 },
    { 0xDF7C, 360 },
    { 0xDF7D, 361 },
    { 0xDF7E, 362 },
    { 0xDF7F, 331 },
    { 0xE000, 189 },
    { 0xE005, 190 },
    { 0xE080, 193 },
    { 0xE081, 196 },
    { 0xE088, 198 },
    { 0xE089, 200 },
    { 0xE08A, 202 },
    { 0xE08B, 204 },
    { 0xE08F, 205 },
    { 0xE090, 733 },
    { 0xE091, 728 },
    { 0xE099, 656 },
    { 0xE100, 208 },
    { 0xE101, 588 },
    { 0xE102, 212 },
    { 0xE108, 214 },
    { 0xE10A, 215 },
    { 0xE110, 731 },
    { 0xE130, 649 },
    { 0xE132, 648 },
    { 0xE180, 216 },
    { 0xE200, 218 },
    { 0xE201, 221 },
    { 0xE208, 224 },
    { 0xE218, 230 },
    { 0xE219, 231 },
    { 0xE21A, 232 },
    { 0xE21B, 233 },
    { 0xE281, 238 },
    { 0xE288, 240 },
    { 0xE289, 243 },
    { 0xE290, 246 },
    { 0xE293, 637 },
    { 0xE298, 248 },
    { 0xE300, 250 },
    { 0xE304, 252 },
    { 0xE4C8, 620 },
    { 0xE510, 267 },
    { 0xE518, 270 },
    { 0xE520, 668 },
    { 0xE521, 669 },
    { 0xE528, 665 },
    { 0xE530, 670 },
    { 0xE531, 671 },
    { 0xE532, 672 },
    { 0xE533, 673 },
    { 0xE534, 674 },
    { 0xE535, 675 },
    { 0xE536, 676 },
    { 0xE537, 677 },
    { 0xE600, 273 },
    { 0xE601, 46 },
    { 0xE602, 276 },
    { 0xE609, 636 },
    { 0xE640, 555 },
    { 0xE641, 556 },
    { 0xE642, 557 },
    { 0xE643, 558 },
    { 0xE648, 559 },
    { 0xE649, 560 },
    { 0xE64A, 561 },
    { 0xE64B, 562 },
    { 0xE64C, 566 },
    { 0xE64D, 541 },
    { 0xE658, 563 },
    { 0xE659, 93 },
    { 0xE65A, 564 },
    { 0xE65B, 94 },
    { 0xE65D, 95 },
    { 0xE65F, 565 },
    { 0xE660, 567 },
    { 0xE661, 568 },
    { 0xE662, 569 },
    { 0xE663, 570 },
    { 0xE664, 571 },
    { 0xE665, 572 },
    { 0xE666, 573 },
    { 0xE667, 574 },
    { 0xE668, 575 },
    { 0xE669, 576 },
    { 0xE66A, 577 },
    { 0xE66B, 578 },
    { 0xE66C, 579 },
    { 0xE66D, 580 },
    { 0xE66E, 581 },
    { 0xE66F, 582 },
    { 0xE681, 589 },
    { 0xE682, 280 },
    { 0xE703, 285 },
    { 0xE708, 287 },
    { 0xE710, 289 },
    { 0xE711, 292 },
    { 0xE712, 295 },
    { 0xE718, 590 },
    { 0xE719, 592 },
    { 0xE71A, 591 },
    { 0xE720, 650 },
    { 0xE721, 652 },
    { 0xE722, 651 },
    { 0xE728, 653 },
    { 0xE729, 655 },
    { 0xE72A, 654 },
    { 0xE880, 593 },
    { 0xE882, 594 },
    { 0xE890, 735 },
    { 0xE891, 729 },
    { 0xE900, 595 },
    { 0xE901, 596 },
    { 0xE902, 597 },
    { 0xEA00, 613 },
    { 0xEA01, 614 },
    { 0xEA88, 598 },
    { 0xEA89, 599 },
    { 0xEA90, 600 },
    { 0xEB00, 601 },
    { 0xECC8, 621 },
    { 0xED10, 602 },
    { 0xED18, 603 },
    { 0xED28, 667 },
    { 0xEE00, 604 },
    { 0xEE81, 605 },
    { 0xEF08, 606 },
    { 0xEF10, 607 },
    { 0xEF11, 608 },
    { 0xEF12, 609 },
    { 0xEF18, 610 },
    { 0xEF19, 611 },
    { 0xEF1A, 612 },
    { 0xF080, 194 },
    { 0xF081, 197 },
    { 0xF088, 199 },
    { 0xF089, 201 },
    { 0xF08A, 203 },
    { 0xF090, 734 },
    { 0xF099, 206 },
    { 0xF100, 209 },
    { 0xF102, 213 },
    { 0xF200, 219 },
    { 0xF201, 222 },
    { 0xF208, 225 },
    { 0xF288, 241 },
    { 0xF289, 244 },
    { 0xF290, 247 },
    { 0xF300, 251 },
    { 0xF510, 268 },
    { 0xF518, 271 },
    { 0xF528, 666 },
    { 0xF600, 274 },
    { 0xF601, 47 },
    { 0xF602, 277 },
    { 0xF664, 539 },
    { 0xF665, 542 },
    { 0xF667, 545 },
    { 0xF682, 281 },
    { 0xFF10, 290 },
    { 0xFF11, 293 },
    { 0xFF12, 296 },
    { 0xFF90, 736 },
  };

  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &SysRegsList[Index[i].index];
}

static const PState PStatesList[] = {
  { "spsel",  0x5 }, // 0
  { "daifset",  0x1E }, // 1
  { "daifclr",  0x1F }, // 2
  { "pan",  0x4 }, // 3
  { "uao",  0x3 }, // 4
  { "dit",  0x1A }, // 5
};

const PState *lookupPStateByEncoding(uint16_t Encoding)
{
  unsigned int i;
  static const struct IndexType Index[] = {
    { 0x3, 4 },
    { 0x4, 3 },
    { 0x5, 0 },
    { 0x1A, 5 },
    { 0x1E, 1 },
    { 0x1F, 2 },
  };

  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &PStatesList[Index[i].index];
}

static const SVEPREDPAT SVEPREDPATsList[] = {
  { "pow2", 0x0 }, // 0
  { "vl1", 0x1 }, // 1
  { "vl2", 0x2 }, // 2
  { "vl3", 0x3 }, // 3
  { "vl4", 0x4 }, // 4
  { "vl5", 0x5 }, // 5
  { "vl6", 0x6 }, // 6
  { "vl7", 0x7 }, // 7
  { "vl8", 0x8 }, // 8
  { "vl16", 0x9 }, // 9
  { "vl32", 0xa }, // 10
  { "vl64", 0xb }, // 11
  { "vl128", 0xc }, // 12
  { "vl256", 0xd }, // 13
  { "mul4", 0x1d }, // 14
  { "mul3", 0x1e }, // 15
  { "all", 0x1f }, // 16
};

const SVEPREDPAT *lookupSVEPREDPATByEncoding(uint16_t Encoding)
{
  unsigned int i;
  static const struct IndexType Index[] = {
    { 0x0, 0 },
    { 0x1, 1 },
    { 0x2, 2 },
    { 0x3, 3 },
    { 0x4, 4 },
    { 0x5, 5 },
    { 0x6, 6 },
    { 0x7, 7 },
    { 0x8, 8 },
    { 0x9, 9 },
    { 0xA, 10 },
    { 0xB, 11 },
    { 0xC, 12 },
    { 0xD, 13 },
    { 0x1D, 14 },
    { 0x1E, 15 },
    { 0x1F, 16 },
  };

  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &SVEPREDPATsList[Index[i].index];
}

static const ExactFPImm ExactFPImmsList[] = {
  { "zero", 0x0, "0.0" }, // 0
  { "half", 0x1, "0.5" }, // 1
  { "one", 0x2, "1.0" }, // 2
  { "two", 0x3, "2.0" }, // 3
};

const ExactFPImm *lookupExactFPImmByEnum(uint16_t Encoding)
{
  static const struct IndexType Index[] = {
    { 0x0, 0 },
    { 0x1, 1 },
    { 0x2, 2 },
    { 0x3, 3 },
  };

  if (Encoding >= ARR_SIZE(ExactFPImmsList))
    return NULL;
  else
    return &ExactFPImmsList[Index[Encoding].index];
}

