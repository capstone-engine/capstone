/* Capstone Disassembly Engine, https://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2024 */
/* Automatically generated file by Capstone's LLVM TableGen Disassembler Backend. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Do not edit. */

/* Capstone's LLVM TableGen Backends: */
/* https://github.com/capstone-engine/llvm-capstone */

#ifdef GET_ASITAG_DECL
#endif

#ifdef GET_ASITAG_DECL
const Sparc_ASITag_ASITag *Sparc_ASITag_lookupASITagByName(const char * Name);
const Sparc_ASITag_ASITag *Sparc_ASITag_lookupASITagByAltName(const char * AltName);
const Sparc_ASITag_ASITag *Sparc_ASITag_lookupASITagByEncoding(uint8_t Encoding);
#endif

#ifdef GET_ASITAG_IMPL
static const Sparc_ASITag_ASITag ASITagsList[] = {
  { "ASI_AIUP", { .raw_val = SPARC_ASITAG_ASI_AIUP }, "ASI_AS_IF_USER_PRIMARY", { .raw_val = SPARC_ASITAG_ASI_AS_IF_USER_PRIMARY }, 0x10 }, // 0
  { "ASI_AIUP_L", { .raw_val = SPARC_ASITAG_ASI_AIUP_L }, "ASI_AS_IF_USER_PRIMARY_LITTLE", { .raw_val = SPARC_ASITAG_ASI_AS_IF_USER_PRIMARY_LITTLE }, 0x18 }, // 1
  { "ASI_AIUS", { .raw_val = SPARC_ASITAG_ASI_AIUS }, "ASI_AS_IF_USER_SECONDARY", { .raw_val = SPARC_ASITAG_ASI_AS_IF_USER_SECONDARY }, 0x11 }, // 2
  { "ASI_AIUS_L", { .raw_val = SPARC_ASITAG_ASI_AIUS_L }, "ASI_AS_IF_USER_SECONDARY_LITTLE", { .raw_val = SPARC_ASITAG_ASI_AS_IF_USER_SECONDARY_LITTLE }, 0x19 }, // 3
  { "ASI_N", { .raw_val = SPARC_ASITAG_ASI_N }, "ASI_NUCLEUS", { .raw_val = SPARC_ASITAG_ASI_NUCLEUS }, 0x4 }, // 4
  { "ASI_N_L", { .raw_val = SPARC_ASITAG_ASI_N_L }, "ASI_NUCLEUS_LITTLE", { .raw_val = SPARC_ASITAG_ASI_NUCLEUS_LITTLE }, 0xC }, // 5
  { "ASI_P", { .raw_val = SPARC_ASITAG_ASI_P }, "ASI_PRIMARY", { .raw_val = SPARC_ASITAG_ASI_PRIMARY }, 0x80 }, // 6
  { "ASI_PNF", { .raw_val = SPARC_ASITAG_ASI_PNF }, "ASI_PRIMARY_NOFAULT", { .raw_val = SPARC_ASITAG_ASI_PRIMARY_NOFAULT }, 0x82 }, // 7
  { "ASI_PNF_L", { .raw_val = SPARC_ASITAG_ASI_PNF_L }, "ASI_PRIMARY_NOFAULT_LITTLE", { .raw_val = SPARC_ASITAG_ASI_PRIMARY_NOFAULT_LITTLE }, 0x8A }, // 8
  { "ASI_P_L", { .raw_val = SPARC_ASITAG_ASI_P_L }, "ASI_PRIMARY_LITTLE", { .raw_val = SPARC_ASITAG_ASI_PRIMARY_LITTLE }, 0x88 }, // 9
  { "ASI_S", { .raw_val = SPARC_ASITAG_ASI_S }, "ASI_SECONDARY", { .raw_val = SPARC_ASITAG_ASI_SECONDARY }, 0x81 }, // 10
  { "ASI_SNF", { .raw_val = SPARC_ASITAG_ASI_SNF }, "ASI_SECONDARY_NOFAULT", { .raw_val = SPARC_ASITAG_ASI_SECONDARY_NOFAULT }, 0x83 }, // 11
  { "ASI_SNF_L", { .raw_val = SPARC_ASITAG_ASI_SNF_L }, "ASI_SECONDARY_NOFAULT_LITTLE", { .raw_val = SPARC_ASITAG_ASI_SECONDARY_NOFAULT_LITTLE }, 0x8B }, // 12
  { "ASI_S_L", { .raw_val = SPARC_ASITAG_ASI_S_L }, "ASI_SECONDARY_LITTLE", { .raw_val = SPARC_ASITAG_ASI_SECONDARY_LITTLE }, 0x89 }, // 13
  };

const Sparc_ASITag_ASITag *Sparc_ASITag_lookupASITagByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "ASI_AIUP", 0 },
    { "ASI_AIUP_L", 1 },
    { "ASI_AIUS", 2 },
    { "ASI_AIUS_L", 3 },
    { "ASI_N", 4 },
    { "ASI_N_L", 5 },
    { "ASI_P", 6 },
    { "ASI_PNF", 7 },
    { "ASI_PNF_L", 8 },
    { "ASI_P_L", 9 },
    { "ASI_S", 10 },
    { "ASI_SNF", 11 },
    { "ASI_SNF_L", 12 },
    { "ASI_S_L", 13 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &ASITagsList[Index[i].index];
}

const Sparc_ASITag_ASITag *Sparc_ASITag_lookupASITagByAltName(const char * AltName) {
  static const struct IndexTypeStr Index[] = {
    { "ASI_AS_IF_USER_PRIMARY", 0 },
    { "ASI_AS_IF_USER_PRIMARY_LITTLE", 1 },
    { "ASI_AS_IF_USER_SECONDARY", 2 },
    { "ASI_AS_IF_USER_SECONDARY_LITTLE", 3 },
    { "ASI_NUCLEUS", 4 },
    { "ASI_NUCLEUS_LITTLE", 5 },
    { "ASI_PRIMARY", 6 },
    { "ASI_PRIMARY_LITTLE", 9 },
    { "ASI_PRIMARY_NOFAULT", 7 },
    { "ASI_PRIMARY_NOFAULT_LITTLE", 8 },
    { "ASI_SECONDARY", 10 },
    { "ASI_SECONDARY_LITTLE", 13 },
    { "ASI_SECONDARY_NOFAULT", 11 },
    { "ASI_SECONDARY_NOFAULT_LITTLE", 12 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), AltName);
   if (i == -1)
      return NULL;
   else
      return &ASITagsList[Index[i].index];
}

const Sparc_ASITag_ASITag *Sparc_ASITag_lookupASITagByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x4, 4 },
    { 0xC, 5 },
    { 0x10, 0 },
    { 0x11, 2 },
    { 0x18, 1 },
    { 0x19, 3 },
    { 0x80, 6 },
    { 0x81, 10 },
    { 0x82, 7 },
    { 0x83, 11 },
    { 0x88, 9 },
    { 0x89, 13 },
    { 0x8A, 8 },
    { 0x8B, 12 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &ASITagsList[Index[i].index];
}

#endif

#undef GET_ASITAG_DECL
#undef GET_ASITAG_IMPL
