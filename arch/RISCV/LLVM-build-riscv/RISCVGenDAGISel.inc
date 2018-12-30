/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* DAG Instruction Selector for the RISCV target                              *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

// *** NOTE: This file is #included into the middle of the target
// *** instruction selector class.  These functions are really methods.

// If GET_DAGISEL_DECL is #defined with any value, only function
// declarations will be included when this file is included.
// If GET_DAGISEL_BODY is #defined, its value should be the name of
// the instruction selector class. Function bodies will be emitted
// and each function's name will be qualified with the name of the
// class.
//
// When neither of the GET_DAGISEL* macros is defined, the functions
// are emitted inline.

#if defined(GET_DAGISEL_DECL) && defined(GET_DAGISEL_BODY)
#error GET_DAGISEL_DECL and GET_DAGISEL_BODY cannot be both defined, undef both for inline definitions
#endif

#ifdef GET_DAGISEL_BODY
#define LOCAL_DAGISEL_STRINGIZE(X) LOCAL_DAGISEL_STRINGIZE_(X)
#define LOCAL_DAGISEL_STRINGIZE_(X) #X
static_assert(sizeof(LOCAL_DAGISEL_STRINGIZE(GET_DAGISEL_BODY)) > 1,
   "GET_DAGISEL_BODY is empty: it should be defined with the class name");
#undef LOCAL_DAGISEL_STRINGIZE_
#undef LOCAL_DAGISEL_STRINGIZE
#endif

#if !defined(GET_DAGISEL_DECL) && !defined(GET_DAGISEL_BODY)
#define DAGISEL_INLINE 1
#else
#define DAGISEL_INLINE 0
#endif

#if !DAGISEL_INLINE
#define DAGISEL_CLASS_COLONCOLON GET_DAGISEL_BODY ::
#else
#define DAGISEL_CLASS_COLONCOLON
#endif

#ifdef GET_DAGISEL_DECL
void SelectCode(SDNode *N);
#endif
#if defined(GET_DAGISEL_BODY) || DAGISEL_INLINE
void DAGISEL_CLASS_COLONCOLON SelectCode(SDNode *N)
{
  // Some target values are emitted as 2 bytes, TARGET_VAL handles
  // this.
  #define TARGET_VAL(X) X & 255, unsigned(X) >> 8
  static const unsigned char MatcherTable[] = {
/*     0*/  OPC_SwitchOpcode /*68 cases */, 80|128,30/*3920*/, TARGET_VAL(ISD::LOAD),// ->3925
/*     5*/    OPC_RecordMemRef,
/*     6*/    OPC_RecordNode, // #0 = 'ld' chained node
/*     7*/    OPC_Scope, 48|128,15/*1968*/, /*->1978*/ // 4 children in Scope
/*    10*/      OPC_MoveChild1,
/*    11*/      OPC_SwitchOpcode /*2 cases */, 57|128,5/*697*/, TARGET_VAL(ISD::OR),// ->713
/*    16*/        OPC_RecordChild0, // #1 = $rs1
/*    17*/        OPC_RecordChild1, // #2 = $imm12
/*    18*/        OPC_MoveChild1,
/*    19*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*    22*/        OPC_CheckPredicate, 0, // Predicate_simm12
/*    24*/        OPC_MoveParent,
/*    25*/        OPC_CheckPredicate, 1, // Predicate_IsOrAdd
/*    27*/        OPC_SwitchType /*2 cases */, 59|128,3/*443*/, MVT::i32,// ->474
/*    31*/          OPC_MoveParent,
/*    32*/          OPC_CheckPredicate, 2, // Predicate_unindexedload
/*    34*/          OPC_CheckType, MVT::i32,
/*    36*/          OPC_Scope, 38, /*->76*/ // 10 children in Scope
/*    38*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*    40*/            OPC_CheckPredicate, 4, // Predicate_sextloadi8
/*    42*/            OPC_Scope, 16, /*->60*/ // 2 children in Scope
/*    44*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*    46*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*    49*/              OPC_EmitMergeInputChains1_0,
/*    50*/              OPC_EmitConvertToTarget, 2,
/*    52*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 18
                        // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*    60*/            /*Scope*/ 14, /*->75*/
/*    61*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*    64*/              OPC_EmitMergeInputChains1_0,
/*    65*/              OPC_EmitConvertToTarget, 2,
/*    67*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 18
                        // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*    75*/            0, /*End of Scope*/
/*    76*/          /*Scope*/ 38, /*->115*/
/*    77*/            OPC_CheckPredicate, 5, // Predicate_extload
/*    79*/            OPC_CheckPredicate, 4, // Predicate_extloadi8
/*    81*/            OPC_Scope, 16, /*->99*/ // 2 children in Scope
/*    83*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*    85*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*    88*/              OPC_EmitMergeInputChains1_0,
/*    89*/              OPC_EmitConvertToTarget, 2,
/*    91*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 18
                        // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*    99*/            /*Scope*/ 14, /*->114*/
/*   100*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   103*/              OPC_EmitMergeInputChains1_0,
/*   104*/              OPC_EmitConvertToTarget, 2,
/*   106*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 18
                        // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   114*/            0, /*End of Scope*/
/*   115*/          /*Scope*/ 38, /*->154*/
/*   116*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*   118*/            OPC_CheckPredicate, 6, // Predicate_sextloadi16
/*   120*/            OPC_Scope, 16, /*->138*/ // 2 children in Scope
/*   122*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*   124*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   127*/              OPC_EmitMergeInputChains1_0,
/*   128*/              OPC_EmitConvertToTarget, 2,
/*   130*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 18
                        // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   138*/            /*Scope*/ 14, /*->153*/
/*   139*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   142*/              OPC_EmitMergeInputChains1_0,
/*   143*/              OPC_EmitConvertToTarget, 2,
/*   145*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 18
                        // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   153*/            0, /*End of Scope*/
/*   154*/          /*Scope*/ 38, /*->193*/
/*   155*/            OPC_CheckPredicate, 5, // Predicate_extload
/*   157*/            OPC_CheckPredicate, 6, // Predicate_extloadi16
/*   159*/            OPC_Scope, 16, /*->177*/ // 2 children in Scope
/*   161*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*   163*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   166*/              OPC_EmitMergeInputChains1_0,
/*   167*/              OPC_EmitConvertToTarget, 2,
/*   169*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 18
                        // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   177*/            /*Scope*/ 14, /*->192*/
/*   178*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   181*/              OPC_EmitMergeInputChains1_0,
/*   182*/              OPC_EmitConvertToTarget, 2,
/*   184*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 18
                        // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   192*/            0, /*End of Scope*/
/*   193*/          /*Scope*/ 38, /*->232*/
/*   194*/            OPC_CheckPredicate, 7, // Predicate_load
/*   196*/            OPC_Scope, 16, /*->214*/ // 2 children in Scope
/*   198*/              OPC_CheckPatternPredicate, 1, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*   200*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   203*/              OPC_EmitMergeInputChains1_0,
/*   204*/              OPC_EmitConvertToTarget, 2,
/*   206*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 18
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   214*/            /*Scope*/ 16, /*->231*/
/*   215*/              OPC_CheckPatternPredicate, 2, // (!Subtarget->is64Bit())
/*   217*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   220*/              OPC_EmitMergeInputChains1_0,
/*   221*/              OPC_EmitConvertToTarget, 2,
/*   223*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 18
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   231*/            0, /*End of Scope*/
/*   232*/          /*Scope*/ 78, /*->311*/
/*   233*/            OPC_CheckPredicate, 8, // Predicate_zextload
/*   235*/            OPC_Scope, 36, /*->273*/ // 2 children in Scope
/*   237*/              OPC_CheckPredicate, 4, // Predicate_zextloadi8
/*   239*/              OPC_Scope, 16, /*->257*/ // 2 children in Scope
/*   241*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*   243*/                OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   246*/                OPC_EmitMergeInputChains1_0,
/*   247*/                OPC_EmitConvertToTarget, 2,
/*   249*/                OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                              MVT::i32, 2/*#Ops*/, 3, 4, 
                          // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 18
                          // Dst: (LBU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   257*/              /*Scope*/ 14, /*->272*/
/*   258*/                OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   261*/                OPC_EmitMergeInputChains1_0,
/*   262*/                OPC_EmitConvertToTarget, 2,
/*   264*/                OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                              MVT::i32, 2/*#Ops*/, 3, 4, 
                          // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 18
                          // Dst: (LBU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   272*/              0, /*End of Scope*/
/*   273*/            /*Scope*/ 36, /*->310*/
/*   274*/              OPC_CheckPredicate, 6, // Predicate_zextloadi16
/*   276*/              OPC_Scope, 16, /*->294*/ // 2 children in Scope
/*   278*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*   280*/                OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   283*/                OPC_EmitMergeInputChains1_0,
/*   284*/                OPC_EmitConvertToTarget, 2,
/*   286*/                OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                              MVT::i32, 2/*#Ops*/, 3, 4, 
                          // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 18
                          // Dst: (LHU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   294*/              /*Scope*/ 14, /*->309*/
/*   295*/                OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   298*/                OPC_EmitMergeInputChains1_0,
/*   299*/                OPC_EmitConvertToTarget, 2,
/*   301*/                OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                              MVT::i32, 2/*#Ops*/, 3, 4, 
                          // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 18
                          // Dst: (LHU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   309*/              0, /*End of Scope*/
/*   310*/            0, /*End of Scope*/
/*   311*/          /*Scope*/ 40, /*->352*/
/*   312*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*   314*/            OPC_CheckPredicate, 9, // Predicate_sextloadi32
/*   316*/            OPC_Scope, 16, /*->334*/ // 2 children in Scope
/*   318*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*   320*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   323*/              OPC_EmitMergeInputChains1_0,
/*   324*/              OPC_EmitConvertToTarget, 2,
/*   326*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 18
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   334*/            /*Scope*/ 16, /*->351*/
/*   335*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*   337*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   340*/              OPC_EmitMergeInputChains1_0,
/*   341*/              OPC_EmitConvertToTarget, 2,
/*   343*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 18
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   351*/            0, /*End of Scope*/
/*   352*/          /*Scope*/ 40, /*->393*/
/*   353*/            OPC_CheckPredicate, 5, // Predicate_extload
/*   355*/            OPC_CheckPredicate, 9, // Predicate_extloadi32
/*   357*/            OPC_Scope, 16, /*->375*/ // 2 children in Scope
/*   359*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*   361*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   364*/              OPC_EmitMergeInputChains1_0,
/*   365*/              OPC_EmitConvertToTarget, 2,
/*   367*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 18
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   375*/            /*Scope*/ 16, /*->392*/
/*   376*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*   378*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   381*/              OPC_EmitMergeInputChains1_0,
/*   382*/              OPC_EmitConvertToTarget, 2,
/*   384*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 18
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   392*/            0, /*End of Scope*/
/*   393*/          /*Scope*/ 40, /*->434*/
/*   394*/            OPC_CheckPredicate, 8, // Predicate_zextload
/*   396*/            OPC_CheckPredicate, 9, // Predicate_zextloadi32
/*   398*/            OPC_Scope, 16, /*->416*/ // 2 children in Scope
/*   400*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*   402*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   405*/              OPC_EmitMergeInputChains1_0,
/*   406*/              OPC_EmitConvertToTarget, 2,
/*   408*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 18
                        // Dst: (LWU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   416*/            /*Scope*/ 16, /*->433*/
/*   417*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*   419*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   422*/              OPC_EmitMergeInputChains1_0,
/*   423*/              OPC_EmitConvertToTarget, 2,
/*   425*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 18
                        // Dst: (LWU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   433*/            0, /*End of Scope*/
/*   434*/          /*Scope*/ 38, /*->473*/
/*   435*/            OPC_CheckPredicate, 7, // Predicate_load
/*   437*/            OPC_Scope, 16, /*->455*/ // 2 children in Scope
/*   439*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*   441*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   444*/              OPC_EmitMergeInputChains1_0,
/*   445*/              OPC_EmitConvertToTarget, 2,
/*   447*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 18
                        // Dst: (LD:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   455*/            /*Scope*/ 16, /*->472*/
/*   456*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*   458*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   461*/              OPC_EmitMergeInputChains1_0,
/*   462*/              OPC_EmitConvertToTarget, 2,
/*   464*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 18
                        // Dst: (LD:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   472*/            0, /*End of Scope*/
/*   473*/          0, /*End of Scope*/
/*   474*/        /*SwitchType*/ 107|128,1/*235*/, MVT::i64,// ->712
/*   477*/          OPC_MoveParent,
/*   478*/          OPC_CheckPredicate, 2, // Predicate_unindexedload
/*   480*/          OPC_CheckType, MVT::i64,
/*   482*/          OPC_Scope, 20, /*->504*/ // 10 children in Scope
/*   484*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*   486*/            OPC_CheckPredicate, 4, // Predicate_sextloadi8
/*   488*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*   490*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   493*/            OPC_EmitMergeInputChains1_0,
/*   494*/            OPC_EmitConvertToTarget, 2,
/*   496*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 18
                      // Dst: (LB:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*   504*/          /*Scope*/ 20, /*->525*/
/*   505*/            OPC_CheckPredicate, 5, // Predicate_extload
/*   507*/            OPC_CheckPredicate, 4, // Predicate_extloadi8
/*   509*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*   511*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   514*/            OPC_EmitMergeInputChains1_0,
/*   515*/            OPC_EmitConvertToTarget, 2,
/*   517*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 18
                      // Dst: (LB:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*   525*/          /*Scope*/ 20, /*->546*/
/*   526*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*   528*/            OPC_CheckPredicate, 6, // Predicate_sextloadi16
/*   530*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*   532*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   535*/            OPC_EmitMergeInputChains1_0,
/*   536*/            OPC_EmitConvertToTarget, 2,
/*   538*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 18
                      // Dst: (LH:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*   546*/          /*Scope*/ 20, /*->567*/
/*   547*/            OPC_CheckPredicate, 5, // Predicate_extload
/*   549*/            OPC_CheckPredicate, 6, // Predicate_extloadi16
/*   551*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*   553*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   556*/            OPC_EmitMergeInputChains1_0,
/*   557*/            OPC_EmitConvertToTarget, 2,
/*   559*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 18
                      // Dst: (LH:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*   567*/          /*Scope*/ 18, /*->586*/
/*   568*/            OPC_CheckPredicate, 7, // Predicate_load
/*   570*/            OPC_CheckPatternPredicate, 6, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*   572*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   575*/            OPC_EmitMergeInputChains1_0,
/*   576*/            OPC_EmitConvertToTarget, 2,
/*   578*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 18
                      // Dst: (LW:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*   586*/          /*Scope*/ 42, /*->629*/
/*   587*/            OPC_CheckPredicate, 8, // Predicate_zextload
/*   589*/            OPC_Scope, 18, /*->609*/ // 2 children in Scope
/*   591*/              OPC_CheckPredicate, 4, // Predicate_zextloadi8
/*   593*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*   595*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   598*/              OPC_EmitMergeInputChains1_0,
/*   599*/              OPC_EmitConvertToTarget, 2,
/*   601*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i64, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 18
                        // Dst: (LBU:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*   609*/            /*Scope*/ 18, /*->628*/
/*   610*/              OPC_CheckPredicate, 6, // Predicate_zextloadi16
/*   612*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*   614*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   617*/              OPC_EmitMergeInputChains1_0,
/*   618*/              OPC_EmitConvertToTarget, 2,
/*   620*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i64, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 18
                        // Dst: (LHU:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*   628*/            0, /*End of Scope*/
/*   629*/          /*Scope*/ 20, /*->650*/
/*   630*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*   632*/            OPC_CheckPredicate, 9, // Predicate_sextloadi32
/*   634*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*   636*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   639*/            OPC_EmitMergeInputChains1_0,
/*   640*/            OPC_EmitConvertToTarget, 2,
/*   642*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 18
                      // Dst: (LW:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*   650*/          /*Scope*/ 20, /*->671*/
/*   651*/            OPC_CheckPredicate, 5, // Predicate_extload
/*   653*/            OPC_CheckPredicate, 9, // Predicate_extloadi32
/*   655*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*   657*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   660*/            OPC_EmitMergeInputChains1_0,
/*   661*/            OPC_EmitConvertToTarget, 2,
/*   663*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 18
                      // Dst: (LW:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*   671*/          /*Scope*/ 20, /*->692*/
/*   672*/            OPC_CheckPredicate, 8, // Predicate_zextload
/*   674*/            OPC_CheckPredicate, 9, // Predicate_zextloadi32
/*   676*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*   678*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   681*/            OPC_EmitMergeInputChains1_0,
/*   682*/            OPC_EmitConvertToTarget, 2,
/*   684*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 18
                      // Dst: (LWU:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*   692*/          /*Scope*/ 18, /*->711*/
/*   693*/            OPC_CheckPredicate, 7, // Predicate_load
/*   695*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*   697*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   700*/            OPC_EmitMergeInputChains1_0,
/*   701*/            OPC_EmitConvertToTarget, 2,
/*   703*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 18
                      // Dst: (LD:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*   711*/          0, /*End of Scope*/
/*   712*/        0, // EndSwitchType
/*   713*/      /*SwitchOpcode*/ 108|128,9/*1260*/, TARGET_VAL(ISD::ADD),// ->1977
/*   717*/        OPC_RecordChild0, // #1 = $rs1
/*   718*/        OPC_RecordChild1, // #2 = $imm12
/*   719*/        OPC_MoveChild1,
/*   720*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*   723*/        OPC_CheckPredicate, 0, // Predicate_simm12
/*   725*/        OPC_MoveParent,
/*   726*/        OPC_SwitchType /*2 cases */, 45|128,6/*813*/, MVT::i32,// ->1543
/*   730*/          OPC_MoveParent,
/*   731*/          OPC_CheckPredicate, 2, // Predicate_unindexedload
/*   733*/          OPC_CheckType, MVT::i32,
/*   735*/          OPC_Scope, 38, /*->775*/ // 20 children in Scope
/*   737*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*   739*/            OPC_CheckPredicate, 4, // Predicate_sextloadi8
/*   741*/            OPC_Scope, 16, /*->759*/ // 2 children in Scope
/*   743*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*   745*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   748*/              OPC_EmitMergeInputChains1_0,
/*   749*/              OPC_EmitConvertToTarget, 2,
/*   751*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 17
                        // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   759*/            /*Scope*/ 14, /*->774*/
/*   760*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   763*/              OPC_EmitMergeInputChains1_0,
/*   764*/              OPC_EmitConvertToTarget, 2,
/*   766*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 17
                        // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   774*/            0, /*End of Scope*/
/*   775*/          /*Scope*/ 38, /*->814*/
/*   776*/            OPC_CheckPredicate, 5, // Predicate_extload
/*   778*/            OPC_CheckPredicate, 4, // Predicate_extloadi8
/*   780*/            OPC_Scope, 16, /*->798*/ // 2 children in Scope
/*   782*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*   784*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   787*/              OPC_EmitMergeInputChains1_0,
/*   788*/              OPC_EmitConvertToTarget, 2,
/*   790*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 17
                        // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   798*/            /*Scope*/ 14, /*->813*/
/*   799*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   802*/              OPC_EmitMergeInputChains1_0,
/*   803*/              OPC_EmitConvertToTarget, 2,
/*   805*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 17
                        // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   813*/            0, /*End of Scope*/
/*   814*/          /*Scope*/ 38, /*->853*/
/*   815*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*   817*/            OPC_CheckPredicate, 6, // Predicate_sextloadi16
/*   819*/            OPC_Scope, 16, /*->837*/ // 2 children in Scope
/*   821*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*   823*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   826*/              OPC_EmitMergeInputChains1_0,
/*   827*/              OPC_EmitConvertToTarget, 2,
/*   829*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 17
                        // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   837*/            /*Scope*/ 14, /*->852*/
/*   838*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   841*/              OPC_EmitMergeInputChains1_0,
/*   842*/              OPC_EmitConvertToTarget, 2,
/*   844*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 17
                        // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   852*/            0, /*End of Scope*/
/*   853*/          /*Scope*/ 38, /*->892*/
/*   854*/            OPC_CheckPredicate, 5, // Predicate_extload
/*   856*/            OPC_CheckPredicate, 6, // Predicate_extloadi16
/*   858*/            OPC_Scope, 16, /*->876*/ // 2 children in Scope
/*   860*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*   862*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   865*/              OPC_EmitMergeInputChains1_0,
/*   866*/              OPC_EmitConvertToTarget, 2,
/*   868*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 17
                        // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   876*/            /*Scope*/ 14, /*->891*/
/*   877*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   880*/              OPC_EmitMergeInputChains1_0,
/*   881*/              OPC_EmitConvertToTarget, 2,
/*   883*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 17
                        // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   891*/            0, /*End of Scope*/
/*   892*/          /*Scope*/ 38, /*->931*/
/*   893*/            OPC_CheckPredicate, 7, // Predicate_load
/*   895*/            OPC_Scope, 16, /*->913*/ // 2 children in Scope
/*   897*/              OPC_CheckPatternPredicate, 1, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*   899*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   902*/              OPC_EmitMergeInputChains1_0,
/*   903*/              OPC_EmitConvertToTarget, 2,
/*   905*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 17
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   913*/            /*Scope*/ 16, /*->930*/
/*   914*/              OPC_CheckPatternPredicate, 2, // (!Subtarget->is64Bit())
/*   916*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   919*/              OPC_EmitMergeInputChains1_0,
/*   920*/              OPC_EmitConvertToTarget, 2,
/*   922*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 17
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   930*/            0, /*End of Scope*/
/*   931*/          /*Scope*/ 78, /*->1010*/
/*   932*/            OPC_CheckPredicate, 8, // Predicate_zextload
/*   934*/            OPC_Scope, 36, /*->972*/ // 2 children in Scope
/*   936*/              OPC_CheckPredicate, 4, // Predicate_zextloadi8
/*   938*/              OPC_Scope, 16, /*->956*/ // 2 children in Scope
/*   940*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*   942*/                OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   945*/                OPC_EmitMergeInputChains1_0,
/*   946*/                OPC_EmitConvertToTarget, 2,
/*   948*/                OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                              MVT::i32, 2/*#Ops*/, 3, 4, 
                          // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 17
                          // Dst: (LBU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   956*/              /*Scope*/ 14, /*->971*/
/*   957*/                OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   960*/                OPC_EmitMergeInputChains1_0,
/*   961*/                OPC_EmitConvertToTarget, 2,
/*   963*/                OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                              MVT::i32, 2/*#Ops*/, 3, 4, 
                          // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 17
                          // Dst: (LBU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   971*/              0, /*End of Scope*/
/*   972*/            /*Scope*/ 36, /*->1009*/
/*   973*/              OPC_CheckPredicate, 6, // Predicate_zextloadi16
/*   975*/              OPC_Scope, 16, /*->993*/ // 2 children in Scope
/*   977*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*   979*/                OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   982*/                OPC_EmitMergeInputChains1_0,
/*   983*/                OPC_EmitConvertToTarget, 2,
/*   985*/                OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                              MVT::i32, 2/*#Ops*/, 3, 4, 
                          // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 17
                          // Dst: (LHU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*   993*/              /*Scope*/ 14, /*->1008*/
/*   994*/                OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*   997*/                OPC_EmitMergeInputChains1_0,
/*   998*/                OPC_EmitConvertToTarget, 2,
/*  1000*/                OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                              MVT::i32, 2/*#Ops*/, 3, 4, 
                          // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 17
                          // Dst: (LHU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1008*/              0, /*End of Scope*/
/*  1009*/            0, /*End of Scope*/
/*  1010*/          /*Scope*/ 40, /*->1051*/
/*  1011*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*  1013*/            OPC_CheckPredicate, 9, // Predicate_sextloadi32
/*  1015*/            OPC_Scope, 16, /*->1033*/ // 2 children in Scope
/*  1017*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  1019*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1022*/              OPC_EmitMergeInputChains1_0,
/*  1023*/              OPC_EmitConvertToTarget, 2,
/*  1025*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 17
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1033*/            /*Scope*/ 16, /*->1050*/
/*  1034*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  1036*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1039*/              OPC_EmitMergeInputChains1_0,
/*  1040*/              OPC_EmitConvertToTarget, 2,
/*  1042*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 17
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1050*/            0, /*End of Scope*/
/*  1051*/          /*Scope*/ 40, /*->1092*/
/*  1052*/            OPC_CheckPredicate, 5, // Predicate_extload
/*  1054*/            OPC_CheckPredicate, 9, // Predicate_extloadi32
/*  1056*/            OPC_Scope, 16, /*->1074*/ // 2 children in Scope
/*  1058*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  1060*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1063*/              OPC_EmitMergeInputChains1_0,
/*  1064*/              OPC_EmitConvertToTarget, 2,
/*  1066*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 17
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1074*/            /*Scope*/ 16, /*->1091*/
/*  1075*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  1077*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1080*/              OPC_EmitMergeInputChains1_0,
/*  1081*/              OPC_EmitConvertToTarget, 2,
/*  1083*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 17
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1091*/            0, /*End of Scope*/
/*  1092*/          /*Scope*/ 40, /*->1133*/
/*  1093*/            OPC_CheckPredicate, 8, // Predicate_zextload
/*  1095*/            OPC_CheckPredicate, 9, // Predicate_zextloadi32
/*  1097*/            OPC_Scope, 16, /*->1115*/ // 2 children in Scope
/*  1099*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  1101*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1104*/              OPC_EmitMergeInputChains1_0,
/*  1105*/              OPC_EmitConvertToTarget, 2,
/*  1107*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 17
                        // Dst: (LWU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1115*/            /*Scope*/ 16, /*->1132*/
/*  1116*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  1118*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1121*/              OPC_EmitMergeInputChains1_0,
/*  1122*/              OPC_EmitConvertToTarget, 2,
/*  1124*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 17
                        // Dst: (LWU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1132*/            0, /*End of Scope*/
/*  1133*/          /*Scope*/ 38, /*->1172*/
/*  1134*/            OPC_CheckPredicate, 7, // Predicate_load
/*  1136*/            OPC_Scope, 16, /*->1154*/ // 2 children in Scope
/*  1138*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  1140*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1143*/              OPC_EmitMergeInputChains1_0,
/*  1144*/              OPC_EmitConvertToTarget, 2,
/*  1146*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 17
                        // Dst: (LD:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1154*/            /*Scope*/ 16, /*->1171*/
/*  1155*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  1157*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1160*/              OPC_EmitMergeInputChains1_0,
/*  1161*/              OPC_EmitConvertToTarget, 2,
/*  1163*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 17
                        // Dst: (LD:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1171*/            0, /*End of Scope*/
/*  1172*/          /*Scope*/ 32, /*->1205*/
/*  1173*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*  1175*/            OPC_CheckPredicate, 4, // Predicate_sextloadi8
/*  1177*/            OPC_Scope, 13, /*->1192*/ // 2 children in Scope
/*  1179*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  1181*/              OPC_EmitMergeInputChains1_0,
/*  1182*/              OPC_EmitConvertToTarget, 2,
/*  1184*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 11
                        // Dst: (LB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1192*/            /*Scope*/ 11, /*->1204*/
/*  1193*/              OPC_EmitMergeInputChains1_0,
/*  1194*/              OPC_EmitConvertToTarget, 2,
/*  1196*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 11
                        // Dst: (LB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1204*/            0, /*End of Scope*/
/*  1205*/          /*Scope*/ 32, /*->1238*/
/*  1206*/            OPC_CheckPredicate, 5, // Predicate_extload
/*  1208*/            OPC_CheckPredicate, 4, // Predicate_extloadi8
/*  1210*/            OPC_Scope, 13, /*->1225*/ // 2 children in Scope
/*  1212*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  1214*/              OPC_EmitMergeInputChains1_0,
/*  1215*/              OPC_EmitConvertToTarget, 2,
/*  1217*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 11
                        // Dst: (LB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1225*/            /*Scope*/ 11, /*->1237*/
/*  1226*/              OPC_EmitMergeInputChains1_0,
/*  1227*/              OPC_EmitConvertToTarget, 2,
/*  1229*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 11
                        // Dst: (LB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1237*/            0, /*End of Scope*/
/*  1238*/          /*Scope*/ 32, /*->1271*/
/*  1239*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*  1241*/            OPC_CheckPredicate, 6, // Predicate_sextloadi16
/*  1243*/            OPC_Scope, 13, /*->1258*/ // 2 children in Scope
/*  1245*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  1247*/              OPC_EmitMergeInputChains1_0,
/*  1248*/              OPC_EmitConvertToTarget, 2,
/*  1250*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 11
                        // Dst: (LH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1258*/            /*Scope*/ 11, /*->1270*/
/*  1259*/              OPC_EmitMergeInputChains1_0,
/*  1260*/              OPC_EmitConvertToTarget, 2,
/*  1262*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 11
                        // Dst: (LH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1270*/            0, /*End of Scope*/
/*  1271*/          /*Scope*/ 32, /*->1304*/
/*  1272*/            OPC_CheckPredicate, 5, // Predicate_extload
/*  1274*/            OPC_CheckPredicate, 6, // Predicate_extloadi16
/*  1276*/            OPC_Scope, 13, /*->1291*/ // 2 children in Scope
/*  1278*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  1280*/              OPC_EmitMergeInputChains1_0,
/*  1281*/              OPC_EmitConvertToTarget, 2,
/*  1283*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 11
                        // Dst: (LH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1291*/            /*Scope*/ 11, /*->1303*/
/*  1292*/              OPC_EmitMergeInputChains1_0,
/*  1293*/              OPC_EmitConvertToTarget, 2,
/*  1295*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 11
                        // Dst: (LH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1303*/            0, /*End of Scope*/
/*  1304*/          /*Scope*/ 32, /*->1337*/
/*  1305*/            OPC_CheckPredicate, 7, // Predicate_load
/*  1307*/            OPC_Scope, 13, /*->1322*/ // 2 children in Scope
/*  1309*/              OPC_CheckPatternPredicate, 1, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  1311*/              OPC_EmitMergeInputChains1_0,
/*  1312*/              OPC_EmitConvertToTarget, 2,
/*  1314*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 11
                        // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1322*/            /*Scope*/ 13, /*->1336*/
/*  1323*/              OPC_CheckPatternPredicate, 2, // (!Subtarget->is64Bit())
/*  1325*/              OPC_EmitMergeInputChains1_0,
/*  1326*/              OPC_EmitConvertToTarget, 2,
/*  1328*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 11
                        // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1336*/            0, /*End of Scope*/
/*  1337*/          /*Scope*/ 66, /*->1404*/
/*  1338*/            OPC_CheckPredicate, 8, // Predicate_zextload
/*  1340*/            OPC_Scope, 30, /*->1372*/ // 2 children in Scope
/*  1342*/              OPC_CheckPredicate, 4, // Predicate_zextloadi8
/*  1344*/              OPC_Scope, 13, /*->1359*/ // 2 children in Scope
/*  1346*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  1348*/                OPC_EmitMergeInputChains1_0,
/*  1349*/                OPC_EmitConvertToTarget, 2,
/*  1351*/                OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                              MVT::i32, 2/*#Ops*/, 1, 3, 
                          // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 11
                          // Dst: (LBU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1359*/              /*Scope*/ 11, /*->1371*/
/*  1360*/                OPC_EmitMergeInputChains1_0,
/*  1361*/                OPC_EmitConvertToTarget, 2,
/*  1363*/                OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                              MVT::i32, 2/*#Ops*/, 1, 3, 
                          // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 11
                          // Dst: (LBU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1371*/              0, /*End of Scope*/
/*  1372*/            /*Scope*/ 30, /*->1403*/
/*  1373*/              OPC_CheckPredicate, 6, // Predicate_zextloadi16
/*  1375*/              OPC_Scope, 13, /*->1390*/ // 2 children in Scope
/*  1377*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  1379*/                OPC_EmitMergeInputChains1_0,
/*  1380*/                OPC_EmitConvertToTarget, 2,
/*  1382*/                OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                              MVT::i32, 2/*#Ops*/, 1, 3, 
                          // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 11
                          // Dst: (LHU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1390*/              /*Scope*/ 11, /*->1402*/
/*  1391*/                OPC_EmitMergeInputChains1_0,
/*  1392*/                OPC_EmitConvertToTarget, 2,
/*  1394*/                OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                              MVT::i32, 2/*#Ops*/, 1, 3, 
                          // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 11
                          // Dst: (LHU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1402*/              0, /*End of Scope*/
/*  1403*/            0, /*End of Scope*/
/*  1404*/          /*Scope*/ 34, /*->1439*/
/*  1405*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*  1407*/            OPC_CheckPredicate, 9, // Predicate_sextloadi32
/*  1409*/            OPC_Scope, 13, /*->1424*/ // 2 children in Scope
/*  1411*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  1413*/              OPC_EmitMergeInputChains1_0,
/*  1414*/              OPC_EmitConvertToTarget, 2,
/*  1416*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 11
                        // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1424*/            /*Scope*/ 13, /*->1438*/
/*  1425*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  1427*/              OPC_EmitMergeInputChains1_0,
/*  1428*/              OPC_EmitConvertToTarget, 2,
/*  1430*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 11
                        // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1438*/            0, /*End of Scope*/
/*  1439*/          /*Scope*/ 34, /*->1474*/
/*  1440*/            OPC_CheckPredicate, 5, // Predicate_extload
/*  1442*/            OPC_CheckPredicate, 9, // Predicate_extloadi32
/*  1444*/            OPC_Scope, 13, /*->1459*/ // 2 children in Scope
/*  1446*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  1448*/              OPC_EmitMergeInputChains1_0,
/*  1449*/              OPC_EmitConvertToTarget, 2,
/*  1451*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 11
                        // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1459*/            /*Scope*/ 13, /*->1473*/
/*  1460*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  1462*/              OPC_EmitMergeInputChains1_0,
/*  1463*/              OPC_EmitConvertToTarget, 2,
/*  1465*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 11
                        // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1473*/            0, /*End of Scope*/
/*  1474*/          /*Scope*/ 34, /*->1509*/
/*  1475*/            OPC_CheckPredicate, 8, // Predicate_zextload
/*  1477*/            OPC_CheckPredicate, 9, // Predicate_zextloadi32
/*  1479*/            OPC_Scope, 13, /*->1494*/ // 2 children in Scope
/*  1481*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  1483*/              OPC_EmitMergeInputChains1_0,
/*  1484*/              OPC_EmitConvertToTarget, 2,
/*  1486*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 11
                        // Dst: (LWU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1494*/            /*Scope*/ 13, /*->1508*/
/*  1495*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  1497*/              OPC_EmitMergeInputChains1_0,
/*  1498*/              OPC_EmitConvertToTarget, 2,
/*  1500*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 11
                        // Dst: (LWU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1508*/            0, /*End of Scope*/
/*  1509*/          /*Scope*/ 32, /*->1542*/
/*  1510*/            OPC_CheckPredicate, 7, // Predicate_load
/*  1512*/            OPC_Scope, 13, /*->1527*/ // 2 children in Scope
/*  1514*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  1516*/              OPC_EmitMergeInputChains1_0,
/*  1517*/              OPC_EmitConvertToTarget, 2,
/*  1519*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 11
                        // Dst: (LD:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1527*/            /*Scope*/ 13, /*->1541*/
/*  1528*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  1530*/              OPC_EmitMergeInputChains1_0,
/*  1531*/              OPC_EmitConvertToTarget, 2,
/*  1533*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 11
                        // Dst: (LD:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  1541*/            0, /*End of Scope*/
/*  1542*/          0, /*End of Scope*/
/*  1543*/        /*SwitchType*/ 46|128,3/*430*/, MVT::i64,// ->1976
/*  1546*/          OPC_MoveParent,
/*  1547*/          OPC_CheckPredicate, 2, // Predicate_unindexedload
/*  1549*/          OPC_CheckType, MVT::i64,
/*  1551*/          OPC_Scope, 20, /*->1573*/ // 20 children in Scope
/*  1553*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*  1555*/            OPC_CheckPredicate, 4, // Predicate_sextloadi8
/*  1557*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  1559*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1562*/            OPC_EmitMergeInputChains1_0,
/*  1563*/            OPC_EmitConvertToTarget, 2,
/*  1565*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 17
                      // Dst: (LB:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1573*/          /*Scope*/ 20, /*->1594*/
/*  1574*/            OPC_CheckPredicate, 5, // Predicate_extload
/*  1576*/            OPC_CheckPredicate, 4, // Predicate_extloadi8
/*  1578*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  1580*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1583*/            OPC_EmitMergeInputChains1_0,
/*  1584*/            OPC_EmitConvertToTarget, 2,
/*  1586*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 17
                      // Dst: (LB:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1594*/          /*Scope*/ 20, /*->1615*/
/*  1595*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*  1597*/            OPC_CheckPredicate, 6, // Predicate_sextloadi16
/*  1599*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  1601*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1604*/            OPC_EmitMergeInputChains1_0,
/*  1605*/            OPC_EmitConvertToTarget, 2,
/*  1607*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 17
                      // Dst: (LH:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1615*/          /*Scope*/ 20, /*->1636*/
/*  1616*/            OPC_CheckPredicate, 5, // Predicate_extload
/*  1618*/            OPC_CheckPredicate, 6, // Predicate_extloadi16
/*  1620*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  1622*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1625*/            OPC_EmitMergeInputChains1_0,
/*  1626*/            OPC_EmitConvertToTarget, 2,
/*  1628*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 17
                      // Dst: (LH:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1636*/          /*Scope*/ 18, /*->1655*/
/*  1637*/            OPC_CheckPredicate, 7, // Predicate_load
/*  1639*/            OPC_CheckPatternPredicate, 6, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  1641*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1644*/            OPC_EmitMergeInputChains1_0,
/*  1645*/            OPC_EmitConvertToTarget, 2,
/*  1647*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 17
                      // Dst: (LW:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1655*/          /*Scope*/ 42, /*->1698*/
/*  1656*/            OPC_CheckPredicate, 8, // Predicate_zextload
/*  1658*/            OPC_Scope, 18, /*->1678*/ // 2 children in Scope
/*  1660*/              OPC_CheckPredicate, 4, // Predicate_zextloadi8
/*  1662*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  1664*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1667*/              OPC_EmitMergeInputChains1_0,
/*  1668*/              OPC_EmitConvertToTarget, 2,
/*  1670*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i64, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 17
                        // Dst: (LBU:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1678*/            /*Scope*/ 18, /*->1697*/
/*  1679*/              OPC_CheckPredicate, 6, // Predicate_zextloadi16
/*  1681*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  1683*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1686*/              OPC_EmitMergeInputChains1_0,
/*  1687*/              OPC_EmitConvertToTarget, 2,
/*  1689*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i64, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 17
                        // Dst: (LHU:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1697*/            0, /*End of Scope*/
/*  1698*/          /*Scope*/ 20, /*->1719*/
/*  1699*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*  1701*/            OPC_CheckPredicate, 9, // Predicate_sextloadi32
/*  1703*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  1705*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1708*/            OPC_EmitMergeInputChains1_0,
/*  1709*/            OPC_EmitConvertToTarget, 2,
/*  1711*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 17
                      // Dst: (LW:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1719*/          /*Scope*/ 20, /*->1740*/
/*  1720*/            OPC_CheckPredicate, 5, // Predicate_extload
/*  1722*/            OPC_CheckPredicate, 9, // Predicate_extloadi32
/*  1724*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  1726*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1729*/            OPC_EmitMergeInputChains1_0,
/*  1730*/            OPC_EmitConvertToTarget, 2,
/*  1732*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 17
                      // Dst: (LW:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1740*/          /*Scope*/ 20, /*->1761*/
/*  1741*/            OPC_CheckPredicate, 8, // Predicate_zextload
/*  1743*/            OPC_CheckPredicate, 9, // Predicate_zextloadi32
/*  1745*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  1747*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1750*/            OPC_EmitMergeInputChains1_0,
/*  1751*/            OPC_EmitConvertToTarget, 2,
/*  1753*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 17
                      // Dst: (LWU:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1761*/          /*Scope*/ 18, /*->1780*/
/*  1762*/            OPC_CheckPredicate, 7, // Predicate_load
/*  1764*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  1766*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  1769*/            OPC_EmitMergeInputChains1_0,
/*  1770*/            OPC_EmitConvertToTarget, 2,
/*  1772*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 17
                      // Dst: (LD:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1780*/          /*Scope*/ 17, /*->1798*/
/*  1781*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*  1783*/            OPC_CheckPredicate, 4, // Predicate_sextloadi8
/*  1785*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  1787*/            OPC_EmitMergeInputChains1_0,
/*  1788*/            OPC_EmitConvertToTarget, 2,
/*  1790*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 3, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 11
                      // Dst: (LB:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1798*/          /*Scope*/ 17, /*->1816*/
/*  1799*/            OPC_CheckPredicate, 5, // Predicate_extload
/*  1801*/            OPC_CheckPredicate, 4, // Predicate_extloadi8
/*  1803*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  1805*/            OPC_EmitMergeInputChains1_0,
/*  1806*/            OPC_EmitConvertToTarget, 2,
/*  1808*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 3, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 11
                      // Dst: (LB:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1816*/          /*Scope*/ 17, /*->1834*/
/*  1817*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*  1819*/            OPC_CheckPredicate, 6, // Predicate_sextloadi16
/*  1821*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  1823*/            OPC_EmitMergeInputChains1_0,
/*  1824*/            OPC_EmitConvertToTarget, 2,
/*  1826*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 3, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 11
                      // Dst: (LH:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1834*/          /*Scope*/ 17, /*->1852*/
/*  1835*/            OPC_CheckPredicate, 5, // Predicate_extload
/*  1837*/            OPC_CheckPredicate, 6, // Predicate_extloadi16
/*  1839*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  1841*/            OPC_EmitMergeInputChains1_0,
/*  1842*/            OPC_EmitConvertToTarget, 2,
/*  1844*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 3, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 11
                      // Dst: (LH:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1852*/          /*Scope*/ 15, /*->1868*/
/*  1853*/            OPC_CheckPredicate, 7, // Predicate_load
/*  1855*/            OPC_CheckPatternPredicate, 6, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  1857*/            OPC_EmitMergeInputChains1_0,
/*  1858*/            OPC_EmitConvertToTarget, 2,
/*  1860*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 3, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 11
                      // Dst: (LW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1868*/          /*Scope*/ 36, /*->1905*/
/*  1869*/            OPC_CheckPredicate, 8, // Predicate_zextload
/*  1871*/            OPC_Scope, 15, /*->1888*/ // 2 children in Scope
/*  1873*/              OPC_CheckPredicate, 4, // Predicate_zextloadi8
/*  1875*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  1877*/              OPC_EmitMergeInputChains1_0,
/*  1878*/              OPC_EmitConvertToTarget, 2,
/*  1880*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i64, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 11
                        // Dst: (LBU:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1888*/            /*Scope*/ 15, /*->1904*/
/*  1889*/              OPC_CheckPredicate, 6, // Predicate_zextloadi16
/*  1891*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  1893*/              OPC_EmitMergeInputChains1_0,
/*  1894*/              OPC_EmitConvertToTarget, 2,
/*  1896*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i64, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 11
                        // Dst: (LHU:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1904*/            0, /*End of Scope*/
/*  1905*/          /*Scope*/ 17, /*->1923*/
/*  1906*/            OPC_CheckPredicate, 3, // Predicate_sextload
/*  1908*/            OPC_CheckPredicate, 9, // Predicate_sextloadi32
/*  1910*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  1912*/            OPC_EmitMergeInputChains1_0,
/*  1913*/            OPC_EmitConvertToTarget, 2,
/*  1915*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 3, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 11
                      // Dst: (LW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1923*/          /*Scope*/ 17, /*->1941*/
/*  1924*/            OPC_CheckPredicate, 5, // Predicate_extload
/*  1926*/            OPC_CheckPredicate, 9, // Predicate_extloadi32
/*  1928*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  1930*/            OPC_EmitMergeInputChains1_0,
/*  1931*/            OPC_EmitConvertToTarget, 2,
/*  1933*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 3, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 11
                      // Dst: (LW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1941*/          /*Scope*/ 17, /*->1959*/
/*  1942*/            OPC_CheckPredicate, 8, // Predicate_zextload
/*  1944*/            OPC_CheckPredicate, 9, // Predicate_zextloadi32
/*  1946*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  1948*/            OPC_EmitMergeInputChains1_0,
/*  1949*/            OPC_EmitConvertToTarget, 2,
/*  1951*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 3, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 11
                      // Dst: (LWU:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1959*/          /*Scope*/ 15, /*->1975*/
/*  1960*/            OPC_CheckPredicate, 7, // Predicate_load
/*  1962*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  1964*/            OPC_EmitMergeInputChains1_0,
/*  1965*/            OPC_EmitConvertToTarget, 2,
/*  1967*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 3, 
                      // Src: (ld:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 11
                      // Dst: (LD:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  1975*/          0, /*End of Scope*/
/*  1976*/        0, // EndSwitchType
/*  1977*/      0, // EndSwitchOpcode
/*  1978*/    /*Scope*/ 51|128,10/*1331*/, /*->3311*/
/*  1980*/      OPC_RecordChild1, // #1 = $rs1
/*  1981*/      OPC_CheckPredicate, 2, // Predicate_unindexedload
/*  1983*/      OPC_Scope, 63, /*->2048*/ // 12 children in Scope
/*  1985*/        OPC_CheckPredicate, 3, // Predicate_sextload
/*  1987*/        OPC_CheckPredicate, 4, // Predicate_sextloadi8
/*  1989*/        OPC_SwitchType /*2 cases */, 36, MVT::i32,// ->2028
/*  1992*/          OPC_Scope, 17, /*->2011*/ // 2 children in Scope
/*  1994*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  1996*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  1999*/            OPC_EmitMergeInputChains1_0,
/*  2000*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2003*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 10
                      // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2011*/          /*Scope*/ 15, /*->2027*/
/*  2012*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2015*/            OPC_EmitMergeInputChains1_0,
/*  2016*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2019*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 10
                      // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2027*/          0, /*End of Scope*/
/*  2028*/        /*SwitchType*/ 17, MVT::i64,// ->2047
/*  2030*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  2032*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2035*/          OPC_EmitMergeInputChains1_0,
/*  2036*/          OPC_EmitInteger, MVT::i64, 0, 
/*  2039*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 10
                    // Dst: (LB:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  2047*/        0, // EndSwitchType
/*  2048*/      /*Scope*/ 63, /*->2112*/
/*  2049*/        OPC_CheckPredicate, 5, // Predicate_extload
/*  2051*/        OPC_CheckPredicate, 4, // Predicate_extloadi8
/*  2053*/        OPC_SwitchType /*2 cases */, 36, MVT::i32,// ->2092
/*  2056*/          OPC_Scope, 17, /*->2075*/ // 2 children in Scope
/*  2058*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  2060*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2063*/            OPC_EmitMergeInputChains1_0,
/*  2064*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2067*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 10
                      // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2075*/          /*Scope*/ 15, /*->2091*/
/*  2076*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2079*/            OPC_EmitMergeInputChains1_0,
/*  2080*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2083*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 10
                      // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2091*/          0, /*End of Scope*/
/*  2092*/        /*SwitchType*/ 17, MVT::i64,// ->2111
/*  2094*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  2096*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2099*/          OPC_EmitMergeInputChains1_0,
/*  2100*/          OPC_EmitInteger, MVT::i64, 0, 
/*  2103*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 10
                    // Dst: (LB:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  2111*/        0, // EndSwitchType
/*  2112*/      /*Scope*/ 63, /*->2176*/
/*  2113*/        OPC_CheckPredicate, 3, // Predicate_sextload
/*  2115*/        OPC_CheckPredicate, 6, // Predicate_sextloadi16
/*  2117*/        OPC_SwitchType /*2 cases */, 36, MVT::i32,// ->2156
/*  2120*/          OPC_Scope, 17, /*->2139*/ // 2 children in Scope
/*  2122*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  2124*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2127*/            OPC_EmitMergeInputChains1_0,
/*  2128*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2131*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 10
                      // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2139*/          /*Scope*/ 15, /*->2155*/
/*  2140*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2143*/            OPC_EmitMergeInputChains1_0,
/*  2144*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2147*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 10
                      // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2155*/          0, /*End of Scope*/
/*  2156*/        /*SwitchType*/ 17, MVT::i64,// ->2175
/*  2158*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  2160*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2163*/          OPC_EmitMergeInputChains1_0,
/*  2164*/          OPC_EmitInteger, MVT::i64, 0, 
/*  2167*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 10
                    // Dst: (LH:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  2175*/        0, // EndSwitchType
/*  2176*/      /*Scope*/ 63, /*->2240*/
/*  2177*/        OPC_CheckPredicate, 5, // Predicate_extload
/*  2179*/        OPC_CheckPredicate, 6, // Predicate_extloadi16
/*  2181*/        OPC_SwitchType /*2 cases */, 36, MVT::i32,// ->2220
/*  2184*/          OPC_Scope, 17, /*->2203*/ // 2 children in Scope
/*  2186*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  2188*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2191*/            OPC_EmitMergeInputChains1_0,
/*  2192*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2195*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 10
                      // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2203*/          /*Scope*/ 15, /*->2219*/
/*  2204*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2207*/            OPC_EmitMergeInputChains1_0,
/*  2208*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2211*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 10
                      // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2219*/          0, /*End of Scope*/
/*  2220*/        /*SwitchType*/ 17, MVT::i64,// ->2239
/*  2222*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  2224*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2227*/          OPC_EmitMergeInputChains1_0,
/*  2228*/          OPC_EmitInteger, MVT::i64, 0, 
/*  2231*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 10
                    // Dst: (LH:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  2239*/        0, // EndSwitchType
/*  2240*/      /*Scope*/ 63, /*->2304*/
/*  2241*/        OPC_CheckPredicate, 7, // Predicate_load
/*  2243*/        OPC_SwitchType /*2 cases */, 38, MVT::i32,// ->2284
/*  2246*/          OPC_Scope, 17, /*->2265*/ // 2 children in Scope
/*  2248*/            OPC_CheckPatternPredicate, 1, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  2250*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2253*/            OPC_EmitMergeInputChains1_0,
/*  2254*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2257*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 10
                      // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2265*/          /*Scope*/ 17, /*->2283*/
/*  2266*/            OPC_CheckPatternPredicate, 2, // (!Subtarget->is64Bit())
/*  2268*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2271*/            OPC_EmitMergeInputChains1_0,
/*  2272*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2275*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 10
                      // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2283*/          0, /*End of Scope*/
/*  2284*/        /*SwitchType*/ 17, MVT::i64,// ->2303
/*  2286*/          OPC_CheckPatternPredicate, 6, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  2288*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2291*/          OPC_EmitMergeInputChains1_0,
/*  2292*/          OPC_EmitInteger, MVT::i64, 0, 
/*  2295*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 10
                    // Dst: (LW:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  2303*/        0, // EndSwitchType
/*  2304*/      /*Scope*/ 0|128,1/*128*/, /*->2434*/
/*  2306*/        OPC_CheckPredicate, 8, // Predicate_zextload
/*  2308*/        OPC_Scope, 61, /*->2371*/ // 2 children in Scope
/*  2310*/          OPC_CheckPredicate, 4, // Predicate_zextloadi8
/*  2312*/          OPC_SwitchType /*2 cases */, 36, MVT::i32,// ->2351
/*  2315*/            OPC_Scope, 17, /*->2334*/ // 2 children in Scope
/*  2317*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  2319*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2322*/              OPC_EmitMergeInputChains1_0,
/*  2323*/              OPC_EmitInteger, MVT::i32, 0, 
/*  2326*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 10
                        // Dst: (LBU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2334*/            /*Scope*/ 15, /*->2350*/
/*  2335*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2338*/              OPC_EmitMergeInputChains1_0,
/*  2339*/              OPC_EmitInteger, MVT::i32, 0, 
/*  2342*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 10
                        // Dst: (LBU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2350*/            0, /*End of Scope*/
/*  2351*/          /*SwitchType*/ 17, MVT::i64,// ->2370
/*  2353*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  2355*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2358*/            OPC_EmitMergeInputChains1_0,
/*  2359*/            OPC_EmitInteger, MVT::i64, 0, 
/*  2362*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 10
                      // Dst: (LBU:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  2370*/          0, // EndSwitchType
/*  2371*/        /*Scope*/ 61, /*->2433*/
/*  2372*/          OPC_CheckPredicate, 6, // Predicate_zextloadi16
/*  2374*/          OPC_SwitchType /*2 cases */, 36, MVT::i32,// ->2413
/*  2377*/            OPC_Scope, 17, /*->2396*/ // 2 children in Scope
/*  2379*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  2381*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2384*/              OPC_EmitMergeInputChains1_0,
/*  2385*/              OPC_EmitInteger, MVT::i32, 0, 
/*  2388*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 10
                        // Dst: (LHU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2396*/            /*Scope*/ 15, /*->2412*/
/*  2397*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2400*/              OPC_EmitMergeInputChains1_0,
/*  2401*/              OPC_EmitInteger, MVT::i32, 0, 
/*  2404*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 10
                        // Dst: (LHU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2412*/            0, /*End of Scope*/
/*  2413*/          /*SwitchType*/ 17, MVT::i64,// ->2432
/*  2415*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  2417*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2420*/            OPC_EmitMergeInputChains1_0,
/*  2421*/            OPC_EmitInteger, MVT::i64, 0, 
/*  2424*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 10
                      // Dst: (LHU:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  2432*/          0, // EndSwitchType
/*  2433*/        0, /*End of Scope*/
/*  2434*/      /*Scope*/ 65, /*->2500*/
/*  2435*/        OPC_CheckPredicate, 3, // Predicate_sextload
/*  2437*/        OPC_CheckPredicate, 9, // Predicate_sextloadi32
/*  2439*/        OPC_SwitchType /*2 cases */, 38, MVT::i32,// ->2480
/*  2442*/          OPC_Scope, 17, /*->2461*/ // 2 children in Scope
/*  2444*/            OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  2446*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2449*/            OPC_EmitMergeInputChains1_0,
/*  2450*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2453*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 10
                      // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2461*/          /*Scope*/ 17, /*->2479*/
/*  2462*/            OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  2464*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2467*/            OPC_EmitMergeInputChains1_0,
/*  2468*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2471*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 10
                      // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2479*/          0, /*End of Scope*/
/*  2480*/        /*SwitchType*/ 17, MVT::i64,// ->2499
/*  2482*/          OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  2484*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2487*/          OPC_EmitMergeInputChains1_0,
/*  2488*/          OPC_EmitInteger, MVT::i64, 0, 
/*  2491*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 10
                    // Dst: (LW:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  2499*/        0, // EndSwitchType
/*  2500*/      /*Scope*/ 65, /*->2566*/
/*  2501*/        OPC_CheckPredicate, 5, // Predicate_extload
/*  2503*/        OPC_CheckPredicate, 9, // Predicate_extloadi32
/*  2505*/        OPC_SwitchType /*2 cases */, 38, MVT::i32,// ->2546
/*  2508*/          OPC_Scope, 17, /*->2527*/ // 2 children in Scope
/*  2510*/            OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  2512*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2515*/            OPC_EmitMergeInputChains1_0,
/*  2516*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2519*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 10
                      // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2527*/          /*Scope*/ 17, /*->2545*/
/*  2528*/            OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  2530*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2533*/            OPC_EmitMergeInputChains1_0,
/*  2534*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2537*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 10
                      // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2545*/          0, /*End of Scope*/
/*  2546*/        /*SwitchType*/ 17, MVT::i64,// ->2565
/*  2548*/          OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  2550*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2553*/          OPC_EmitMergeInputChains1_0,
/*  2554*/          OPC_EmitInteger, MVT::i64, 0, 
/*  2557*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 10
                    // Dst: (LW:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  2565*/        0, // EndSwitchType
/*  2566*/      /*Scope*/ 65, /*->2632*/
/*  2567*/        OPC_CheckPredicate, 8, // Predicate_zextload
/*  2569*/        OPC_CheckPredicate, 9, // Predicate_zextloadi32
/*  2571*/        OPC_SwitchType /*2 cases */, 38, MVT::i32,// ->2612
/*  2574*/          OPC_Scope, 17, /*->2593*/ // 2 children in Scope
/*  2576*/            OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  2578*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2581*/            OPC_EmitMergeInputChains1_0,
/*  2582*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2585*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 10
                      // Dst: (LWU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2593*/          /*Scope*/ 17, /*->2611*/
/*  2594*/            OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  2596*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2599*/            OPC_EmitMergeInputChains1_0,
/*  2600*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2603*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 10
                      // Dst: (LWU:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2611*/          0, /*End of Scope*/
/*  2612*/        /*SwitchType*/ 17, MVT::i64,// ->2631
/*  2614*/          OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  2616*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2619*/          OPC_EmitMergeInputChains1_0,
/*  2620*/          OPC_EmitInteger, MVT::i64, 0, 
/*  2623*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 10
                    // Dst: (LWU:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  2631*/        0, // EndSwitchType
/*  2632*/      /*Scope*/ 63, /*->2696*/
/*  2633*/        OPC_CheckPredicate, 7, // Predicate_load
/*  2635*/        OPC_SwitchType /*2 cases */, 38, MVT::i32,// ->2676
/*  2638*/          OPC_Scope, 17, /*->2657*/ // 2 children in Scope
/*  2640*/            OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  2642*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2645*/            OPC_EmitMergeInputChains1_0,
/*  2646*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2649*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 10
                      // Dst: (LD:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2657*/          /*Scope*/ 17, /*->2675*/
/*  2658*/            OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  2660*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2663*/            OPC_EmitMergeInputChains1_0,
/*  2664*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2667*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (ld:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 10
                      // Dst: (LD:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2675*/          0, /*End of Scope*/
/*  2676*/        /*SwitchType*/ 17, MVT::i64,// ->2695
/*  2678*/          OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  2680*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  2683*/          OPC_EmitMergeInputChains1_0,
/*  2684*/          OPC_EmitInteger, MVT::i64, 0, 
/*  2687*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 10
                    // Dst: (LD:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  2695*/        0, // EndSwitchType
/*  2696*/      /*Scope*/ 14|128,3/*398*/, /*->3096*/
/*  2698*/        OPC_CheckChild1Type, MVT::i32,
/*  2700*/        OPC_CheckType, MVT::i32,
/*  2702*/        OPC_Scope, 34, /*->2738*/ // 10 children in Scope
/*  2704*/          OPC_CheckPredicate, 3, // Predicate_sextload
/*  2706*/          OPC_CheckPredicate, 4, // Predicate_sextloadi8
/*  2708*/          OPC_Scope, 14, /*->2724*/ // 2 children in Scope
/*  2710*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  2712*/            OPC_EmitMergeInputChains1_0,
/*  2713*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2716*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 4
                      // Dst: (LB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2724*/          /*Scope*/ 12, /*->2737*/
/*  2725*/            OPC_EmitMergeInputChains1_0,
/*  2726*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2729*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 4
                      // Dst: (LB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2737*/          0, /*End of Scope*/
/*  2738*/        /*Scope*/ 34, /*->2773*/
/*  2739*/          OPC_CheckPredicate, 5, // Predicate_extload
/*  2741*/          OPC_CheckPredicate, 4, // Predicate_extloadi8
/*  2743*/          OPC_Scope, 14, /*->2759*/ // 2 children in Scope
/*  2745*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  2747*/            OPC_EmitMergeInputChains1_0,
/*  2748*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2751*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 4
                      // Dst: (LB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2759*/          /*Scope*/ 12, /*->2772*/
/*  2760*/            OPC_EmitMergeInputChains1_0,
/*  2761*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2764*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 4
                      // Dst: (LB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2772*/          0, /*End of Scope*/
/*  2773*/        /*Scope*/ 34, /*->2808*/
/*  2774*/          OPC_CheckPredicate, 3, // Predicate_sextload
/*  2776*/          OPC_CheckPredicate, 6, // Predicate_sextloadi16
/*  2778*/          OPC_Scope, 14, /*->2794*/ // 2 children in Scope
/*  2780*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  2782*/            OPC_EmitMergeInputChains1_0,
/*  2783*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2786*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 4
                      // Dst: (LH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2794*/          /*Scope*/ 12, /*->2807*/
/*  2795*/            OPC_EmitMergeInputChains1_0,
/*  2796*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2799*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 4
                      // Dst: (LH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2807*/          0, /*End of Scope*/
/*  2808*/        /*Scope*/ 34, /*->2843*/
/*  2809*/          OPC_CheckPredicate, 5, // Predicate_extload
/*  2811*/          OPC_CheckPredicate, 6, // Predicate_extloadi16
/*  2813*/          OPC_Scope, 14, /*->2829*/ // 2 children in Scope
/*  2815*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  2817*/            OPC_EmitMergeInputChains1_0,
/*  2818*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2821*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 4
                      // Dst: (LH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2829*/          /*Scope*/ 12, /*->2842*/
/*  2830*/            OPC_EmitMergeInputChains1_0,
/*  2831*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2834*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 4
                      // Dst: (LH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2842*/          0, /*End of Scope*/
/*  2843*/        /*Scope*/ 34, /*->2878*/
/*  2844*/          OPC_CheckPredicate, 7, // Predicate_load
/*  2846*/          OPC_Scope, 14, /*->2862*/ // 2 children in Scope
/*  2848*/            OPC_CheckPatternPredicate, 1, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  2850*/            OPC_EmitMergeInputChains1_0,
/*  2851*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2854*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 4
                      // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2862*/          /*Scope*/ 14, /*->2877*/
/*  2863*/            OPC_CheckPatternPredicate, 2, // (!Subtarget->is64Bit())
/*  2865*/            OPC_EmitMergeInputChains1_0,
/*  2866*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2869*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 4
                      // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2877*/          0, /*End of Scope*/
/*  2878*/        /*Scope*/ 70, /*->2949*/
/*  2879*/          OPC_CheckPredicate, 8, // Predicate_zextload
/*  2881*/          OPC_Scope, 32, /*->2915*/ // 2 children in Scope
/*  2883*/            OPC_CheckPredicate, 4, // Predicate_zextloadi8
/*  2885*/            OPC_Scope, 14, /*->2901*/ // 2 children in Scope
/*  2887*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  2889*/              OPC_EmitMergeInputChains1_0,
/*  2890*/              OPC_EmitInteger, MVT::i32, 0, 
/*  2893*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 2, 
                        // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 4
                        // Dst: (LBU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2901*/            /*Scope*/ 12, /*->2914*/
/*  2902*/              OPC_EmitMergeInputChains1_0,
/*  2903*/              OPC_EmitInteger, MVT::i32, 0, 
/*  2906*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 2, 
                        // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 4
                        // Dst: (LBU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2914*/            0, /*End of Scope*/
/*  2915*/          /*Scope*/ 32, /*->2948*/
/*  2916*/            OPC_CheckPredicate, 6, // Predicate_zextloadi16
/*  2918*/            OPC_Scope, 14, /*->2934*/ // 2 children in Scope
/*  2920*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  2922*/              OPC_EmitMergeInputChains1_0,
/*  2923*/              OPC_EmitInteger, MVT::i32, 0, 
/*  2926*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 2, 
                        // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 4
                        // Dst: (LHU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2934*/            /*Scope*/ 12, /*->2947*/
/*  2935*/              OPC_EmitMergeInputChains1_0,
/*  2936*/              OPC_EmitInteger, MVT::i32, 0, 
/*  2939*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 2, 
                        // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 4
                        // Dst: (LHU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2947*/            0, /*End of Scope*/
/*  2948*/          0, /*End of Scope*/
/*  2949*/        /*Scope*/ 36, /*->2986*/
/*  2950*/          OPC_CheckPredicate, 3, // Predicate_sextload
/*  2952*/          OPC_CheckPredicate, 9, // Predicate_sextloadi32
/*  2954*/          OPC_Scope, 14, /*->2970*/ // 2 children in Scope
/*  2956*/            OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  2958*/            OPC_EmitMergeInputChains1_0,
/*  2959*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2962*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 4
                      // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2970*/          /*Scope*/ 14, /*->2985*/
/*  2971*/            OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  2973*/            OPC_EmitMergeInputChains1_0,
/*  2974*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2977*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 4
                      // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  2985*/          0, /*End of Scope*/
/*  2986*/        /*Scope*/ 36, /*->3023*/
/*  2987*/          OPC_CheckPredicate, 5, // Predicate_extload
/*  2989*/          OPC_CheckPredicate, 9, // Predicate_extloadi32
/*  2991*/          OPC_Scope, 14, /*->3007*/ // 2 children in Scope
/*  2993*/            OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  2995*/            OPC_EmitMergeInputChains1_0,
/*  2996*/            OPC_EmitInteger, MVT::i32, 0, 
/*  2999*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 4
                      // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3007*/          /*Scope*/ 14, /*->3022*/
/*  3008*/            OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  3010*/            OPC_EmitMergeInputChains1_0,
/*  3011*/            OPC_EmitInteger, MVT::i32, 0, 
/*  3014*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 4
                      // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3022*/          0, /*End of Scope*/
/*  3023*/        /*Scope*/ 36, /*->3060*/
/*  3024*/          OPC_CheckPredicate, 8, // Predicate_zextload
/*  3026*/          OPC_CheckPredicate, 9, // Predicate_zextloadi32
/*  3028*/          OPC_Scope, 14, /*->3044*/ // 2 children in Scope
/*  3030*/            OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  3032*/            OPC_EmitMergeInputChains1_0,
/*  3033*/            OPC_EmitInteger, MVT::i32, 0, 
/*  3036*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 4
                      // Dst: (LWU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3044*/          /*Scope*/ 14, /*->3059*/
/*  3045*/            OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  3047*/            OPC_EmitMergeInputChains1_0,
/*  3048*/            OPC_EmitInteger, MVT::i32, 0, 
/*  3051*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 4
                      // Dst: (LWU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3059*/          0, /*End of Scope*/
/*  3060*/        /*Scope*/ 34, /*->3095*/
/*  3061*/          OPC_CheckPredicate, 7, // Predicate_load
/*  3063*/          OPC_Scope, 14, /*->3079*/ // 2 children in Scope
/*  3065*/            OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  3067*/            OPC_EmitMergeInputChains1_0,
/*  3068*/            OPC_EmitInteger, MVT::i32, 0, 
/*  3071*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 4
                      // Dst: (LD:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3079*/          /*Scope*/ 14, /*->3094*/
/*  3080*/            OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  3082*/            OPC_EmitMergeInputChains1_0,
/*  3083*/            OPC_EmitInteger, MVT::i32, 0, 
/*  3086*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 4
                      // Dst: (LD:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3094*/          0, /*End of Scope*/
/*  3095*/        0, /*End of Scope*/
/*  3096*/      /*Scope*/ 84|128,1/*212*/, /*->3310*/
/*  3098*/        OPC_CheckChild1Type, MVT::i64,
/*  3100*/        OPC_CheckType, MVT::i64,
/*  3102*/        OPC_Scope, 18, /*->3122*/ // 10 children in Scope
/*  3104*/          OPC_CheckPredicate, 3, // Predicate_sextload
/*  3106*/          OPC_CheckPredicate, 4, // Predicate_sextloadi8
/*  3108*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  3110*/          OPC_EmitMergeInputChains1_0,
/*  3111*/          OPC_EmitInteger, MVT::i64, 0, 
/*  3114*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 1, 2, 
                    // Src: (ld:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi8>> - Complexity = 4
                    // Dst: (LB:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3122*/        /*Scope*/ 18, /*->3141*/
/*  3123*/          OPC_CheckPredicate, 5, // Predicate_extload
/*  3125*/          OPC_CheckPredicate, 4, // Predicate_extloadi8
/*  3127*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  3129*/          OPC_EmitMergeInputChains1_0,
/*  3130*/          OPC_EmitInteger, MVT::i64, 0, 
/*  3133*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 1, 2, 
                    // Src: (ld:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi8>> - Complexity = 4
                    // Dst: (LB:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3141*/        /*Scope*/ 18, /*->3160*/
/*  3142*/          OPC_CheckPredicate, 3, // Predicate_sextload
/*  3144*/          OPC_CheckPredicate, 6, // Predicate_sextloadi16
/*  3146*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  3148*/          OPC_EmitMergeInputChains1_0,
/*  3149*/          OPC_EmitInteger, MVT::i64, 0, 
/*  3152*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 1, 2, 
                    // Src: (ld:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi16>> - Complexity = 4
                    // Dst: (LH:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3160*/        /*Scope*/ 18, /*->3179*/
/*  3161*/          OPC_CheckPredicate, 5, // Predicate_extload
/*  3163*/          OPC_CheckPredicate, 6, // Predicate_extloadi16
/*  3165*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  3167*/          OPC_EmitMergeInputChains1_0,
/*  3168*/          OPC_EmitInteger, MVT::i64, 0, 
/*  3171*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 1, 2, 
                    // Src: (ld:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi16>> - Complexity = 4
                    // Dst: (LH:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3179*/        /*Scope*/ 16, /*->3196*/
/*  3180*/          OPC_CheckPredicate, 7, // Predicate_load
/*  3182*/          OPC_CheckPatternPredicate, 6, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  3184*/          OPC_EmitMergeInputChains1_0,
/*  3185*/          OPC_EmitInteger, MVT::i64, 0, 
/*  3188*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 1, 2, 
                    // Src: (ld:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 4
                    // Dst: (LW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3196*/        /*Scope*/ 38, /*->3235*/
/*  3197*/          OPC_CheckPredicate, 8, // Predicate_zextload
/*  3199*/          OPC_Scope, 16, /*->3217*/ // 2 children in Scope
/*  3201*/            OPC_CheckPredicate, 4, // Predicate_zextloadi8
/*  3203*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  3205*/            OPC_EmitMergeInputChains1_0,
/*  3206*/            OPC_EmitInteger, MVT::i64, 0, 
/*  3209*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LBU), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi8>> - Complexity = 4
                      // Dst: (LBU:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3217*/          /*Scope*/ 16, /*->3234*/
/*  3218*/            OPC_CheckPredicate, 6, // Predicate_zextloadi16
/*  3220*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  3222*/            OPC_EmitMergeInputChains1_0,
/*  3223*/            OPC_EmitInteger, MVT::i64, 0, 
/*  3226*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LHU), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi16>> - Complexity = 4
                      // Dst: (LHU:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3234*/          0, /*End of Scope*/
/*  3235*/        /*Scope*/ 18, /*->3254*/
/*  3236*/          OPC_CheckPredicate, 3, // Predicate_sextload
/*  3238*/          OPC_CheckPredicate, 9, // Predicate_sextloadi32
/*  3240*/          OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  3242*/          OPC_EmitMergeInputChains1_0,
/*  3243*/          OPC_EmitInteger, MVT::i64, 0, 
/*  3246*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 1, 2, 
                    // Src: (ld:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_sextload>><<P:Predicate_sextloadi32>> - Complexity = 4
                    // Dst: (LW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3254*/        /*Scope*/ 18, /*->3273*/
/*  3255*/          OPC_CheckPredicate, 5, // Predicate_extload
/*  3257*/          OPC_CheckPredicate, 9, // Predicate_extloadi32
/*  3259*/          OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  3261*/          OPC_EmitMergeInputChains1_0,
/*  3262*/          OPC_EmitInteger, MVT::i64, 0, 
/*  3265*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 1, 2, 
                    // Src: (ld:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_extload>><<P:Predicate_extloadi32>> - Complexity = 4
                    // Dst: (LW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3273*/        /*Scope*/ 18, /*->3292*/
/*  3274*/          OPC_CheckPredicate, 8, // Predicate_zextload
/*  3276*/          OPC_CheckPredicate, 9, // Predicate_zextloadi32
/*  3278*/          OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  3280*/          OPC_EmitMergeInputChains1_0,
/*  3281*/          OPC_EmitInteger, MVT::i64, 0, 
/*  3284*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LWU), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 1, 2, 
                    // Src: (ld:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_zextload>><<P:Predicate_zextloadi32>> - Complexity = 4
                    // Dst: (LWU:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3292*/        /*Scope*/ 16, /*->3309*/
/*  3293*/          OPC_CheckPredicate, 7, // Predicate_load
/*  3295*/          OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  3297*/          OPC_EmitMergeInputChains1_0,
/*  3298*/          OPC_EmitInteger, MVT::i64, 0, 
/*  3301*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LD), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 1, 2, 
                    // Src: (ld:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 4
                    // Dst: (LD:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3309*/        0, /*End of Scope*/
/*  3310*/      0, /*End of Scope*/
/*  3311*/    /*Scope*/ 126|128,2/*382*/, /*->3695*/
/*  3313*/      OPC_MoveChild1,
/*  3314*/      OPC_SwitchOpcode /*2 cases */, 15|128,1/*143*/, TARGET_VAL(ISD::OR),// ->3462
/*  3319*/        OPC_RecordChild0, // #1 = $rs1
/*  3320*/        OPC_RecordChild1, // #2 = $imm12
/*  3321*/        OPC_MoveChild1,
/*  3322*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  3325*/        OPC_CheckPredicate, 0, // Predicate_simm12
/*  3327*/        OPC_MoveParent,
/*  3328*/        OPC_CheckPredicate, 1, // Predicate_IsOrAdd
/*  3330*/        OPC_SwitchType /*2 cases */, 83, MVT::i32,// ->3416
/*  3333*/          OPC_MoveParent,
/*  3334*/          OPC_CheckPredicate, 2, // Predicate_unindexedload
/*  3336*/          OPC_CheckPredicate, 7, // Predicate_load
/*  3338*/          OPC_SwitchType /*2 cases */, 36, MVT::f32,// ->3377
/*  3341*/            OPC_Scope, 16, /*->3359*/ // 2 children in Scope
/*  3343*/              OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  3345*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  3348*/              OPC_EmitMergeInputChains1_0,
/*  3349*/              OPC_EmitConvertToTarget, 2,
/*  3351*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[f32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 18
                        // Dst: (FLW:{ *:[f32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  3359*/            /*Scope*/ 16, /*->3376*/
/*  3360*/              OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/*  3362*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  3365*/              OPC_EmitMergeInputChains1_0,
/*  3366*/              OPC_EmitConvertToTarget, 2,
/*  3368*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[f32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 18
                        // Dst: (FLW:{ *:[f32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  3376*/            0, /*End of Scope*/
/*  3377*/          /*SwitchType*/ 36, MVT::f64,// ->3415
/*  3379*/            OPC_Scope, 16, /*->3397*/ // 2 children in Scope
/*  3381*/              OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  3383*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  3386*/              OPC_EmitMergeInputChains1_0,
/*  3387*/              OPC_EmitConvertToTarget, 2,
/*  3389*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f64, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[f64] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 18
                        // Dst: (FLD:{ *:[f64] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  3397*/            /*Scope*/ 16, /*->3414*/
/*  3398*/              OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/*  3400*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  3403*/              OPC_EmitMergeInputChains1_0,
/*  3404*/              OPC_EmitConvertToTarget, 2,
/*  3406*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f64, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[f64] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 18
                        // Dst: (FLD:{ *:[f64] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  3414*/            0, /*End of Scope*/
/*  3415*/          0, // EndSwitchType
/*  3416*/        /*SwitchType*/ 43, MVT::i64,// ->3461
/*  3418*/          OPC_MoveParent,
/*  3419*/          OPC_CheckPredicate, 2, // Predicate_unindexedload
/*  3421*/          OPC_CheckPredicate, 7, // Predicate_load
/*  3423*/          OPC_SwitchType /*2 cases */, 16, MVT::f32,// ->3442
/*  3426*/            OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  3428*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  3431*/            OPC_EmitMergeInputChains1_0,
/*  3432*/            OPC_EmitConvertToTarget, 2,
/*  3434*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::f32, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[f32] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 18
                      // Dst: (FLW:{ *:[f32] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  3442*/          /*SwitchType*/ 16, MVT::f64,// ->3460
/*  3444*/            OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  3446*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  3449*/            OPC_EmitMergeInputChains1_0,
/*  3450*/            OPC_EmitConvertToTarget, 2,
/*  3452*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::f64, 2/*#Ops*/, 3, 4, 
                      // Src: (ld:{ *:[f64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 18
                      // Dst: (FLD:{ *:[f64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  3460*/          0, // EndSwitchType
/*  3461*/        0, // EndSwitchType
/*  3462*/      /*SwitchOpcode*/ 100|128,1/*228*/, TARGET_VAL(ISD::ADD),// ->3694
/*  3466*/        OPC_RecordChild0, // #1 = $rs1
/*  3467*/        OPC_RecordChild1, // #2 = $imm12
/*  3468*/        OPC_MoveChild1,
/*  3469*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  3472*/        OPC_CheckPredicate, 0, // Predicate_simm12
/*  3474*/        OPC_MoveParent,
/*  3475*/        OPC_SwitchType /*2 cases */, 11|128,1/*139*/, MVT::i32,// ->3618
/*  3479*/          OPC_MoveParent,
/*  3480*/          OPC_CheckPredicate, 2, // Predicate_unindexedload
/*  3482*/          OPC_CheckPredicate, 7, // Predicate_load
/*  3484*/          OPC_SwitchType /*2 cases */, 64, MVT::f32,// ->3551
/*  3487*/            OPC_Scope, 16, /*->3505*/ // 4 children in Scope
/*  3489*/              OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  3491*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  3494*/              OPC_EmitMergeInputChains1_0,
/*  3495*/              OPC_EmitConvertToTarget, 2,
/*  3497*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[f32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 17
                        // Dst: (FLW:{ *:[f32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  3505*/            /*Scope*/ 16, /*->3522*/
/*  3506*/              OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/*  3508*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  3511*/              OPC_EmitMergeInputChains1_0,
/*  3512*/              OPC_EmitConvertToTarget, 2,
/*  3514*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[f32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 17
                        // Dst: (FLW:{ *:[f32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  3522*/            /*Scope*/ 13, /*->3536*/
/*  3523*/              OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  3525*/              OPC_EmitMergeInputChains1_0,
/*  3526*/              OPC_EmitConvertToTarget, 2,
/*  3528*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[f32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 11
                        // Dst: (FLW:{ *:[f32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  3536*/            /*Scope*/ 13, /*->3550*/
/*  3537*/              OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/*  3539*/              OPC_EmitMergeInputChains1_0,
/*  3540*/              OPC_EmitConvertToTarget, 2,
/*  3542*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[f32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 11
                        // Dst: (FLW:{ *:[f32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  3550*/            0, /*End of Scope*/
/*  3551*/          /*SwitchType*/ 64, MVT::f64,// ->3617
/*  3553*/            OPC_Scope, 16, /*->3571*/ // 4 children in Scope
/*  3555*/              OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  3557*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  3560*/              OPC_EmitMergeInputChains1_0,
/*  3561*/              OPC_EmitConvertToTarget, 2,
/*  3563*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f64, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[f64] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 17
                        // Dst: (FLD:{ *:[f64] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  3571*/            /*Scope*/ 16, /*->3588*/
/*  3572*/              OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/*  3574*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  3577*/              OPC_EmitMergeInputChains1_0,
/*  3578*/              OPC_EmitConvertToTarget, 2,
/*  3580*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f64, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[f64] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 17
                        // Dst: (FLD:{ *:[f64] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  3588*/            /*Scope*/ 13, /*->3602*/
/*  3589*/              OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  3591*/              OPC_EmitMergeInputChains1_0,
/*  3592*/              OPC_EmitConvertToTarget, 2,
/*  3594*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f64, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[f64] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 11
                        // Dst: (FLD:{ *:[f64] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  3602*/            /*Scope*/ 13, /*->3616*/
/*  3603*/              OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/*  3605*/              OPC_EmitMergeInputChains1_0,
/*  3606*/              OPC_EmitConvertToTarget, 2,
/*  3608*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f64, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[f64] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 11
                        // Dst: (FLD:{ *:[f64] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  3616*/            0, /*End of Scope*/
/*  3617*/          0, // EndSwitchType
/*  3618*/        /*SwitchType*/ 73, MVT::i64,// ->3693
/*  3620*/          OPC_MoveParent,
/*  3621*/          OPC_CheckPredicate, 2, // Predicate_unindexedload
/*  3623*/          OPC_CheckPredicate, 7, // Predicate_load
/*  3625*/          OPC_SwitchType /*2 cases */, 31, MVT::f32,// ->3659
/*  3628*/            OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  3630*/            OPC_Scope, 14, /*->3646*/ // 2 children in Scope
/*  3632*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  3635*/              OPC_EmitMergeInputChains1_0,
/*  3636*/              OPC_EmitConvertToTarget, 2,
/*  3638*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f32, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[f32] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 17
                        // Dst: (FLW:{ *:[f32] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  3646*/            /*Scope*/ 11, /*->3658*/
/*  3647*/              OPC_EmitMergeInputChains1_0,
/*  3648*/              OPC_EmitConvertToTarget, 2,
/*  3650*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f32, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[f32] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 11
                        // Dst: (FLW:{ *:[f32] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  3658*/            0, /*End of Scope*/
/*  3659*/          /*SwitchType*/ 31, MVT::f64,// ->3692
/*  3661*/            OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  3663*/            OPC_Scope, 14, /*->3679*/ // 2 children in Scope
/*  3665*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  3668*/              OPC_EmitMergeInputChains1_0,
/*  3669*/              OPC_EmitConvertToTarget, 2,
/*  3671*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f64, 2/*#Ops*/, 3, 4, 
                        // Src: (ld:{ *:[f64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 17
                        // Dst: (FLD:{ *:[f64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  3679*/            /*Scope*/ 11, /*->3691*/
/*  3680*/              OPC_EmitMergeInputChains1_0,
/*  3681*/              OPC_EmitConvertToTarget, 2,
/*  3683*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::f64, 2/*#Ops*/, 1, 3, 
                        // Src: (ld:{ *:[f64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 11
                        // Dst: (FLD:{ *:[f64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  3691*/            0, /*End of Scope*/
/*  3692*/          0, // EndSwitchType
/*  3693*/        0, // EndSwitchType
/*  3694*/      0, // EndSwitchOpcode
/*  3695*/    /*Scope*/ 99|128,1/*227*/, /*->3924*/
/*  3697*/      OPC_RecordChild1, // #1 = $rs1
/*  3698*/      OPC_CheckPredicate, 2, // Predicate_unindexedload
/*  3700*/      OPC_CheckPredicate, 7, // Predicate_load
/*  3702*/      OPC_SwitchType /*2 cases */, 108, MVT::f32,// ->3813
/*  3705*/        OPC_Scope, 17, /*->3724*/ // 5 children in Scope
/*  3707*/          OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  3709*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  3712*/          OPC_EmitMergeInputChains1_0,
/*  3713*/          OPC_EmitInteger, MVT::i32, 0, 
/*  3716*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::f32, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[f32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 10
                    // Dst: (FLW:{ *:[f32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3724*/        /*Scope*/ 17, /*->3742*/
/*  3725*/          OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  3727*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  3730*/          OPC_EmitMergeInputChains1_0,
/*  3731*/          OPC_EmitInteger, MVT::i64, 0, 
/*  3734*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::f32, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[f32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 10
                    // Dst: (FLW:{ *:[f32] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3742*/        /*Scope*/ 17, /*->3760*/
/*  3743*/          OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/*  3745*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  3748*/          OPC_EmitMergeInputChains1_0,
/*  3749*/          OPC_EmitInteger, MVT::i32, 0, 
/*  3752*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::f32, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[f32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 10
                    // Dst: (FLW:{ *:[f32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3760*/        /*Scope*/ 34, /*->3795*/
/*  3761*/          OPC_CheckChild1Type, MVT::i32,
/*  3763*/          OPC_Scope, 14, /*->3779*/ // 2 children in Scope
/*  3765*/            OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  3767*/            OPC_EmitMergeInputChains1_0,
/*  3768*/            OPC_EmitInteger, MVT::i32, 0, 
/*  3771*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::f32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[f32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 4
                      // Dst: (FLW:{ *:[f32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3779*/          /*Scope*/ 14, /*->3794*/
/*  3780*/            OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/*  3782*/            OPC_EmitMergeInputChains1_0,
/*  3783*/            OPC_EmitInteger, MVT::i32, 0, 
/*  3786*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::f32, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[f32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 4
                      // Dst: (FLW:{ *:[f32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3794*/          0, /*End of Scope*/
/*  3795*/        /*Scope*/ 16, /*->3812*/
/*  3796*/          OPC_CheckChild1Type, MVT::i64,
/*  3798*/          OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  3800*/          OPC_EmitMergeInputChains1_0,
/*  3801*/          OPC_EmitInteger, MVT::i64, 0, 
/*  3804*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLW), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::f32, 2/*#Ops*/, 1, 2, 
                    // Src: (ld:{ *:[f32] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 4
                    // Dst: (FLW:{ *:[f32] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3812*/        0, /*End of Scope*/
/*  3813*/      /*SwitchType*/ 108, MVT::f64,// ->3923
/*  3815*/        OPC_Scope, 17, /*->3834*/ // 5 children in Scope
/*  3817*/          OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  3819*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  3822*/          OPC_EmitMergeInputChains1_0,
/*  3823*/          OPC_EmitInteger, MVT::i32, 0, 
/*  3826*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::f64, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[f64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 10
                    // Dst: (FLD:{ *:[f64] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3834*/        /*Scope*/ 17, /*->3852*/
/*  3835*/          OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  3837*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  3840*/          OPC_EmitMergeInputChains1_0,
/*  3841*/          OPC_EmitInteger, MVT::i64, 0, 
/*  3844*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::f64, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[f64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 10
                    // Dst: (FLD:{ *:[f64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3852*/        /*Scope*/ 17, /*->3870*/
/*  3853*/          OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/*  3855*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  3858*/          OPC_EmitMergeInputChains1_0,
/*  3859*/          OPC_EmitInteger, MVT::i32, 0, 
/*  3862*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::f64, 2/*#Ops*/, 2, 3, 
                    // Src: (ld:{ *:[f64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 10
                    // Dst: (FLD:{ *:[f64] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3870*/        /*Scope*/ 34, /*->3905*/
/*  3871*/          OPC_CheckChild1Type, MVT::i32,
/*  3873*/          OPC_Scope, 14, /*->3889*/ // 2 children in Scope
/*  3875*/            OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  3877*/            OPC_EmitMergeInputChains1_0,
/*  3878*/            OPC_EmitInteger, MVT::i32, 0, 
/*  3881*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::f64, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[f64] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 4
                      // Dst: (FLD:{ *:[f64] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3889*/          /*Scope*/ 14, /*->3904*/
/*  3890*/            OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/*  3892*/            OPC_EmitMergeInputChains1_0,
/*  3893*/            OPC_EmitInteger, MVT::i32, 0, 
/*  3896*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::f64, 2/*#Ops*/, 1, 2, 
                      // Src: (ld:{ *:[f64] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 4
                      // Dst: (FLD:{ *:[f64] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  3904*/          0, /*End of Scope*/
/*  3905*/        /*Scope*/ 16, /*->3922*/
/*  3906*/          OPC_CheckChild1Type, MVT::i64,
/*  3908*/          OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  3910*/          OPC_EmitMergeInputChains1_0,
/*  3911*/          OPC_EmitInteger, MVT::i64, 0, 
/*  3914*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLD), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::f64, 2/*#Ops*/, 1, 2, 
                    // Src: (ld:{ *:[f64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedload>><<P:Predicate_load>> - Complexity = 4
                    // Dst: (FLD:{ *:[f64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  3922*/        0, /*End of Scope*/
/*  3923*/      0, // EndSwitchType
/*  3924*/    0, /*End of Scope*/
/*  3925*/  /*SwitchOpcode*/ 59|128,17/*2235*/, TARGET_VAL(ISD::STORE),// ->6164
/*  3929*/    OPC_RecordMemRef,
/*  3930*/    OPC_RecordNode, // #0 = 'st' chained node
/*  3931*/    OPC_RecordChild1, // #1 = $rs2
/*  3932*/    OPC_Scope, 118|128,7/*1014*/, /*->4949*/ // 4 children in Scope
/*  3935*/      OPC_CheckChild1Type, MVT::i32,
/*  3937*/      OPC_Scope, 97|128,4/*609*/, /*->4549*/ // 2 children in Scope
/*  3940*/        OPC_MoveChild2,
/*  3941*/        OPC_SwitchOpcode /*2 cases */, 88|128,1/*216*/, TARGET_VAL(ISD::OR),// ->4162
/*  3946*/          OPC_RecordChild0, // #2 = $rs1
/*  3947*/          OPC_RecordChild1, // #3 = $imm12
/*  3948*/          OPC_MoveChild1,
/*  3949*/          OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  3952*/          OPC_CheckPredicate, 0, // Predicate_simm12
/*  3954*/          OPC_MoveParent,
/*  3955*/          OPC_CheckPredicate, 1, // Predicate_IsOrAdd
/*  3957*/          OPC_CheckType, MVT::i32,
/*  3959*/          OPC_MoveParent,
/*  3960*/          OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  3962*/          OPC_Scope, 78, /*->4042*/ // 4 children in Scope
/*  3964*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  3966*/            OPC_Scope, 36, /*->4004*/ // 2 children in Scope
/*  3968*/              OPC_CheckPredicate, 12, // Predicate_truncstorei8
/*  3970*/              OPC_Scope, 16, /*->3988*/ // 2 children in Scope
/*  3972*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  3974*/                OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  3977*/                OPC_EmitMergeInputChains1_0,
/*  3978*/                OPC_EmitConvertToTarget, 3,
/*  3980*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 4, 5, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 18
                          // Dst: (SB GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  3988*/              /*Scope*/ 14, /*->4003*/
/*  3989*/                OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  3992*/                OPC_EmitMergeInputChains1_0,
/*  3993*/                OPC_EmitConvertToTarget, 3,
/*  3995*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 4, 5, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 18
                          // Dst: (SB GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4003*/              0, /*End of Scope*/
/*  4004*/            /*Scope*/ 36, /*->4041*/
/*  4005*/              OPC_CheckPredicate, 13, // Predicate_truncstorei16
/*  4007*/              OPC_Scope, 16, /*->4025*/ // 2 children in Scope
/*  4009*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  4011*/                OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4014*/                OPC_EmitMergeInputChains1_0,
/*  4015*/                OPC_EmitConvertToTarget, 3,
/*  4017*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 4, 5, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 18
                          // Dst: (SH GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4025*/              /*Scope*/ 14, /*->4040*/
/*  4026*/                OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4029*/                OPC_EmitMergeInputChains1_0,
/*  4030*/                OPC_EmitConvertToTarget, 3,
/*  4032*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 4, 5, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 18
                          // Dst: (SH GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4040*/              0, /*End of Scope*/
/*  4041*/            0, /*End of Scope*/
/*  4042*/          /*Scope*/ 38, /*->4081*/
/*  4043*/            OPC_CheckPredicate, 14, // Predicate_store
/*  4045*/            OPC_Scope, 16, /*->4063*/ // 2 children in Scope
/*  4047*/              OPC_CheckPatternPredicate, 1, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4049*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4052*/              OPC_EmitMergeInputChains1_0,
/*  4053*/              OPC_EmitConvertToTarget, 3,
/*  4055*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 18
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4063*/            /*Scope*/ 16, /*->4080*/
/*  4064*/              OPC_CheckPatternPredicate, 2, // (!Subtarget->is64Bit())
/*  4066*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4069*/              OPC_EmitMergeInputChains1_0,
/*  4070*/              OPC_EmitConvertToTarget, 3,
/*  4072*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 18
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4080*/            0, /*End of Scope*/
/*  4081*/          /*Scope*/ 40, /*->4122*/
/*  4082*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  4084*/            OPC_CheckPredicate, 15, // Predicate_truncstorei32
/*  4086*/            OPC_Scope, 16, /*->4104*/ // 2 children in Scope
/*  4088*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4090*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4093*/              OPC_EmitMergeInputChains1_0,
/*  4094*/              OPC_EmitConvertToTarget, 3,
/*  4096*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 18
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4104*/            /*Scope*/ 16, /*->4121*/
/*  4105*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  4107*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4110*/              OPC_EmitMergeInputChains1_0,
/*  4111*/              OPC_EmitConvertToTarget, 3,
/*  4113*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 18
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4121*/            0, /*End of Scope*/
/*  4122*/          /*Scope*/ 38, /*->4161*/
/*  4123*/            OPC_CheckPredicate, 14, // Predicate_store
/*  4125*/            OPC_Scope, 16, /*->4143*/ // 2 children in Scope
/*  4127*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4129*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4132*/              OPC_EmitMergeInputChains1_0,
/*  4133*/              OPC_EmitConvertToTarget, 3,
/*  4135*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 18
                        // Dst: (SD GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4143*/            /*Scope*/ 16, /*->4160*/
/*  4144*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  4146*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4149*/              OPC_EmitMergeInputChains1_0,
/*  4150*/              OPC_EmitConvertToTarget, 3,
/*  4152*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 18
                        // Dst: (SD GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4160*/            0, /*End of Scope*/
/*  4161*/          0, /*End of Scope*/
/*  4162*/        /*SwitchOpcode*/ 126|128,2/*382*/, TARGET_VAL(ISD::ADD),// ->4548
/*  4166*/          OPC_RecordChild0, // #2 = $rs1
/*  4167*/          OPC_RecordChild1, // #3 = $imm12
/*  4168*/          OPC_MoveChild1,
/*  4169*/          OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  4172*/          OPC_CheckPredicate, 0, // Predicate_simm12
/*  4174*/          OPC_MoveParent,
/*  4175*/          OPC_CheckType, MVT::i32,
/*  4177*/          OPC_MoveParent,
/*  4178*/          OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  4180*/          OPC_Scope, 78, /*->4260*/ // 8 children in Scope
/*  4182*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  4184*/            OPC_Scope, 36, /*->4222*/ // 2 children in Scope
/*  4186*/              OPC_CheckPredicate, 12, // Predicate_truncstorei8
/*  4188*/              OPC_Scope, 16, /*->4206*/ // 2 children in Scope
/*  4190*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  4192*/                OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4195*/                OPC_EmitMergeInputChains1_0,
/*  4196*/                OPC_EmitConvertToTarget, 3,
/*  4198*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 4, 5, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 17
                          // Dst: (SB GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4206*/              /*Scope*/ 14, /*->4221*/
/*  4207*/                OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4210*/                OPC_EmitMergeInputChains1_0,
/*  4211*/                OPC_EmitConvertToTarget, 3,
/*  4213*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 4, 5, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 17
                          // Dst: (SB GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4221*/              0, /*End of Scope*/
/*  4222*/            /*Scope*/ 36, /*->4259*/
/*  4223*/              OPC_CheckPredicate, 13, // Predicate_truncstorei16
/*  4225*/              OPC_Scope, 16, /*->4243*/ // 2 children in Scope
/*  4227*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  4229*/                OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4232*/                OPC_EmitMergeInputChains1_0,
/*  4233*/                OPC_EmitConvertToTarget, 3,
/*  4235*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 4, 5, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 17
                          // Dst: (SH GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4243*/              /*Scope*/ 14, /*->4258*/
/*  4244*/                OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4247*/                OPC_EmitMergeInputChains1_0,
/*  4248*/                OPC_EmitConvertToTarget, 3,
/*  4250*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 4, 5, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 17
                          // Dst: (SH GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4258*/              0, /*End of Scope*/
/*  4259*/            0, /*End of Scope*/
/*  4260*/          /*Scope*/ 38, /*->4299*/
/*  4261*/            OPC_CheckPredicate, 14, // Predicate_store
/*  4263*/            OPC_Scope, 16, /*->4281*/ // 2 children in Scope
/*  4265*/              OPC_CheckPatternPredicate, 1, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4267*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4270*/              OPC_EmitMergeInputChains1_0,
/*  4271*/              OPC_EmitConvertToTarget, 3,
/*  4273*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 17
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4281*/            /*Scope*/ 16, /*->4298*/
/*  4282*/              OPC_CheckPatternPredicate, 2, // (!Subtarget->is64Bit())
/*  4284*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4287*/              OPC_EmitMergeInputChains1_0,
/*  4288*/              OPC_EmitConvertToTarget, 3,
/*  4290*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 17
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4298*/            0, /*End of Scope*/
/*  4299*/          /*Scope*/ 40, /*->4340*/
/*  4300*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  4302*/            OPC_CheckPredicate, 15, // Predicate_truncstorei32
/*  4304*/            OPC_Scope, 16, /*->4322*/ // 2 children in Scope
/*  4306*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4308*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4311*/              OPC_EmitMergeInputChains1_0,
/*  4312*/              OPC_EmitConvertToTarget, 3,
/*  4314*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 17
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4322*/            /*Scope*/ 16, /*->4339*/
/*  4323*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  4325*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4328*/              OPC_EmitMergeInputChains1_0,
/*  4329*/              OPC_EmitConvertToTarget, 3,
/*  4331*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 17
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4339*/            0, /*End of Scope*/
/*  4340*/          /*Scope*/ 38, /*->4379*/
/*  4341*/            OPC_CheckPredicate, 14, // Predicate_store
/*  4343*/            OPC_Scope, 16, /*->4361*/ // 2 children in Scope
/*  4345*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4347*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4350*/              OPC_EmitMergeInputChains1_0,
/*  4351*/              OPC_EmitConvertToTarget, 3,
/*  4353*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 17
                        // Dst: (SD GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4361*/            /*Scope*/ 16, /*->4378*/
/*  4362*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  4364*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4367*/              OPC_EmitMergeInputChains1_0,
/*  4368*/              OPC_EmitConvertToTarget, 3,
/*  4370*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 17
                        // Dst: (SD GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4378*/            0, /*End of Scope*/
/*  4379*/          /*Scope*/ 66, /*->4446*/
/*  4380*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  4382*/            OPC_Scope, 30, /*->4414*/ // 2 children in Scope
/*  4384*/              OPC_CheckPredicate, 12, // Predicate_truncstorei8
/*  4386*/              OPC_Scope, 13, /*->4401*/ // 2 children in Scope
/*  4388*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  4390*/                OPC_EmitMergeInputChains1_0,
/*  4391*/                OPC_EmitConvertToTarget, 3,
/*  4393*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 2, 4, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 11
                          // Dst: (SB GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4401*/              /*Scope*/ 11, /*->4413*/
/*  4402*/                OPC_EmitMergeInputChains1_0,
/*  4403*/                OPC_EmitConvertToTarget, 3,
/*  4405*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 2, 4, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 11
                          // Dst: (SB GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4413*/              0, /*End of Scope*/
/*  4414*/            /*Scope*/ 30, /*->4445*/
/*  4415*/              OPC_CheckPredicate, 13, // Predicate_truncstorei16
/*  4417*/              OPC_Scope, 13, /*->4432*/ // 2 children in Scope
/*  4419*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  4421*/                OPC_EmitMergeInputChains1_0,
/*  4422*/                OPC_EmitConvertToTarget, 3,
/*  4424*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 2, 4, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 11
                          // Dst: (SH GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4432*/              /*Scope*/ 11, /*->4444*/
/*  4433*/                OPC_EmitMergeInputChains1_0,
/*  4434*/                OPC_EmitConvertToTarget, 3,
/*  4436*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 2, 4, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 11
                          // Dst: (SH GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4444*/              0, /*End of Scope*/
/*  4445*/            0, /*End of Scope*/
/*  4446*/          /*Scope*/ 32, /*->4479*/
/*  4447*/            OPC_CheckPredicate, 14, // Predicate_store
/*  4449*/            OPC_Scope, 13, /*->4464*/ // 2 children in Scope
/*  4451*/              OPC_CheckPatternPredicate, 1, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4453*/              OPC_EmitMergeInputChains1_0,
/*  4454*/              OPC_EmitConvertToTarget, 3,
/*  4456*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 11
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4464*/            /*Scope*/ 13, /*->4478*/
/*  4465*/              OPC_CheckPatternPredicate, 2, // (!Subtarget->is64Bit())
/*  4467*/              OPC_EmitMergeInputChains1_0,
/*  4468*/              OPC_EmitConvertToTarget, 3,
/*  4470*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 11
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4478*/            0, /*End of Scope*/
/*  4479*/          /*Scope*/ 34, /*->4514*/
/*  4480*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  4482*/            OPC_CheckPredicate, 15, // Predicate_truncstorei32
/*  4484*/            OPC_Scope, 13, /*->4499*/ // 2 children in Scope
/*  4486*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4488*/              OPC_EmitMergeInputChains1_0,
/*  4489*/              OPC_EmitConvertToTarget, 3,
/*  4491*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 11
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4499*/            /*Scope*/ 13, /*->4513*/
/*  4500*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  4502*/              OPC_EmitMergeInputChains1_0,
/*  4503*/              OPC_EmitConvertToTarget, 3,
/*  4505*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 11
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4513*/            0, /*End of Scope*/
/*  4514*/          /*Scope*/ 32, /*->4547*/
/*  4515*/            OPC_CheckPredicate, 14, // Predicate_store
/*  4517*/            OPC_Scope, 13, /*->4532*/ // 2 children in Scope
/*  4519*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4521*/              OPC_EmitMergeInputChains1_0,
/*  4522*/              OPC_EmitConvertToTarget, 3,
/*  4524*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 11
                        // Dst: (SD GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4532*/            /*Scope*/ 13, /*->4546*/
/*  4533*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  4535*/              OPC_EmitMergeInputChains1_0,
/*  4536*/              OPC_EmitConvertToTarget, 3,
/*  4538*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 11
                        // Dst: (SD GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  4546*/            0, /*End of Scope*/
/*  4547*/          0, /*End of Scope*/
/*  4548*/        0, // EndSwitchOpcode
/*  4549*/      /*Scope*/ 13|128,3/*397*/, /*->4948*/
/*  4551*/        OPC_RecordChild2, // #2 = $rs1
/*  4552*/        OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  4554*/        OPC_Scope, 82, /*->4638*/ // 5 children in Scope
/*  4556*/          OPC_CheckPredicate, 11, // Predicate_truncstore
/*  4558*/          OPC_Scope, 38, /*->4598*/ // 2 children in Scope
/*  4560*/            OPC_CheckPredicate, 12, // Predicate_truncstorei8
/*  4562*/            OPC_Scope, 17, /*->4581*/ // 2 children in Scope
/*  4564*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  4566*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  4569*/              OPC_EmitMergeInputChains1_0,
/*  4570*/              OPC_EmitInteger, MVT::i32, 0, 
/*  4573*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 3, 4, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 10
                        // Dst: (SB GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4581*/            /*Scope*/ 15, /*->4597*/
/*  4582*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  4585*/              OPC_EmitMergeInputChains1_0,
/*  4586*/              OPC_EmitInteger, MVT::i32, 0, 
/*  4589*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 3, 4, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 10
                        // Dst: (SB GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4597*/            0, /*End of Scope*/
/*  4598*/          /*Scope*/ 38, /*->4637*/
/*  4599*/            OPC_CheckPredicate, 13, // Predicate_truncstorei16
/*  4601*/            OPC_Scope, 17, /*->4620*/ // 2 children in Scope
/*  4603*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  4605*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  4608*/              OPC_EmitMergeInputChains1_0,
/*  4609*/              OPC_EmitInteger, MVT::i32, 0, 
/*  4612*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 3, 4, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 10
                        // Dst: (SH GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4620*/            /*Scope*/ 15, /*->4636*/
/*  4621*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  4624*/              OPC_EmitMergeInputChains1_0,
/*  4625*/              OPC_EmitInteger, MVT::i32, 0, 
/*  4628*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 3, 4, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 10
                        // Dst: (SH GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4636*/            0, /*End of Scope*/
/*  4637*/          0, /*End of Scope*/
/*  4638*/        /*Scope*/ 40, /*->4679*/
/*  4639*/          OPC_CheckPredicate, 14, // Predicate_store
/*  4641*/          OPC_Scope, 17, /*->4660*/ // 2 children in Scope
/*  4643*/            OPC_CheckPatternPredicate, 1, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4645*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  4648*/            OPC_EmitMergeInputChains1_0,
/*  4649*/            OPC_EmitInteger, MVT::i32, 0, 
/*  4652*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 3, 4, 
                      // Src: (st GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 10
                      // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4660*/          /*Scope*/ 17, /*->4678*/
/*  4661*/            OPC_CheckPatternPredicate, 2, // (!Subtarget->is64Bit())
/*  4663*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  4666*/            OPC_EmitMergeInputChains1_0,
/*  4667*/            OPC_EmitInteger, MVT::i32, 0, 
/*  4670*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 3, 4, 
                      // Src: (st GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 10
                      // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4678*/          0, /*End of Scope*/
/*  4679*/        /*Scope*/ 42, /*->4722*/
/*  4680*/          OPC_CheckPredicate, 11, // Predicate_truncstore
/*  4682*/          OPC_CheckPredicate, 15, // Predicate_truncstorei32
/*  4684*/          OPC_Scope, 17, /*->4703*/ // 2 children in Scope
/*  4686*/            OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4688*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  4691*/            OPC_EmitMergeInputChains1_0,
/*  4692*/            OPC_EmitInteger, MVT::i32, 0, 
/*  4695*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 3, 4, 
                      // Src: (st GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 10
                      // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4703*/          /*Scope*/ 17, /*->4721*/
/*  4704*/            OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  4706*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  4709*/            OPC_EmitMergeInputChains1_0,
/*  4710*/            OPC_EmitInteger, MVT::i32, 0, 
/*  4713*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 3, 4, 
                      // Src: (st GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 10
                      // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4721*/          0, /*End of Scope*/
/*  4722*/        /*Scope*/ 40, /*->4763*/
/*  4723*/          OPC_CheckPredicate, 14, // Predicate_store
/*  4725*/          OPC_Scope, 17, /*->4744*/ // 2 children in Scope
/*  4727*/            OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4729*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  4732*/            OPC_EmitMergeInputChains1_0,
/*  4733*/            OPC_EmitInteger, MVT::i32, 0, 
/*  4736*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 3, 4, 
                      // Src: (st GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 10
                      // Dst: (SD GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4744*/          /*Scope*/ 17, /*->4762*/
/*  4745*/            OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  4747*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  4750*/            OPC_EmitMergeInputChains1_0,
/*  4751*/            OPC_EmitInteger, MVT::i32, 0, 
/*  4754*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 3, 4, 
                      // Src: (st GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 10
                      // Dst: (SD GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4762*/          0, /*End of Scope*/
/*  4763*/        /*Scope*/ 54|128,1/*182*/, /*->4947*/
/*  4765*/          OPC_CheckChild2Type, MVT::i32,
/*  4767*/          OPC_Scope, 70, /*->4839*/ // 4 children in Scope
/*  4769*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  4771*/            OPC_Scope, 32, /*->4805*/ // 2 children in Scope
/*  4773*/              OPC_CheckPredicate, 12, // Predicate_truncstorei8
/*  4775*/              OPC_Scope, 14, /*->4791*/ // 2 children in Scope
/*  4777*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  4779*/                OPC_EmitMergeInputChains1_0,
/*  4780*/                OPC_EmitInteger, MVT::i32, 0, 
/*  4783*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 2, 3, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 4
                          // Dst: (SB GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4791*/              /*Scope*/ 12, /*->4804*/
/*  4792*/                OPC_EmitMergeInputChains1_0,
/*  4793*/                OPC_EmitInteger, MVT::i32, 0, 
/*  4796*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 2, 3, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 4
                          // Dst: (SB GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4804*/              0, /*End of Scope*/
/*  4805*/            /*Scope*/ 32, /*->4838*/
/*  4806*/              OPC_CheckPredicate, 13, // Predicate_truncstorei16
/*  4808*/              OPC_Scope, 14, /*->4824*/ // 2 children in Scope
/*  4810*/                OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  4812*/                OPC_EmitMergeInputChains1_0,
/*  4813*/                OPC_EmitInteger, MVT::i32, 0, 
/*  4816*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 2, 3, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 4
                          // Dst: (SH GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4824*/              /*Scope*/ 12, /*->4837*/
/*  4825*/                OPC_EmitMergeInputChains1_0,
/*  4826*/                OPC_EmitInteger, MVT::i32, 0, 
/*  4829*/                OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                              3/*#Ops*/, 1, 2, 3, 
                          // Src: (st GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 4
                          // Dst: (SH GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4837*/              0, /*End of Scope*/
/*  4838*/            0, /*End of Scope*/
/*  4839*/          /*Scope*/ 34, /*->4874*/
/*  4840*/            OPC_CheckPredicate, 14, // Predicate_store
/*  4842*/            OPC_Scope, 14, /*->4858*/ // 2 children in Scope
/*  4844*/              OPC_CheckPatternPredicate, 1, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4846*/              OPC_EmitMergeInputChains1_0,
/*  4847*/              OPC_EmitInteger, MVT::i32, 0, 
/*  4850*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 3, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 4
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4858*/            /*Scope*/ 14, /*->4873*/
/*  4859*/              OPC_CheckPatternPredicate, 2, // (!Subtarget->is64Bit())
/*  4861*/              OPC_EmitMergeInputChains1_0,
/*  4862*/              OPC_EmitInteger, MVT::i32, 0, 
/*  4865*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 3, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 4
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4873*/            0, /*End of Scope*/
/*  4874*/          /*Scope*/ 36, /*->4911*/
/*  4875*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  4877*/            OPC_CheckPredicate, 15, // Predicate_truncstorei32
/*  4879*/            OPC_Scope, 14, /*->4895*/ // 2 children in Scope
/*  4881*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4883*/              OPC_EmitMergeInputChains1_0,
/*  4884*/              OPC_EmitInteger, MVT::i32, 0, 
/*  4887*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 3, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 4
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4895*/            /*Scope*/ 14, /*->4910*/
/*  4896*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  4898*/              OPC_EmitMergeInputChains1_0,
/*  4899*/              OPC_EmitInteger, MVT::i32, 0, 
/*  4902*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 3, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 4
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4910*/            0, /*End of Scope*/
/*  4911*/          /*Scope*/ 34, /*->4946*/
/*  4912*/            OPC_CheckPredicate, 14, // Predicate_store
/*  4914*/            OPC_Scope, 14, /*->4930*/ // 2 children in Scope
/*  4916*/              OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  4918*/              OPC_EmitMergeInputChains1_0,
/*  4919*/              OPC_EmitInteger, MVT::i32, 0, 
/*  4922*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 3, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 4
                        // Dst: (SD GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4930*/            /*Scope*/ 14, /*->4945*/
/*  4931*/              OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/*  4933*/              OPC_EmitMergeInputChains1_0,
/*  4934*/              OPC_EmitInteger, MVT::i32, 0, 
/*  4937*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 3, 
                        // Src: (st GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 4
                        // Dst: (SD GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  4945*/            0, /*End of Scope*/
/*  4946*/          0, /*End of Scope*/
/*  4947*/        0, /*End of Scope*/
/*  4948*/      0, /*End of Scope*/
/*  4949*/    /*Scope*/ 40|128,4/*552*/, /*->5503*/
/*  4951*/      OPC_CheckChild1Type, MVT::i64,
/*  4953*/      OPC_Scope, 79|128,2/*335*/, /*->5291*/ // 2 children in Scope
/*  4956*/        OPC_MoveChild2,
/*  4957*/        OPC_SwitchOpcode /*2 cases */, 120, TARGET_VAL(ISD::OR),// ->5081
/*  4961*/          OPC_RecordChild0, // #2 = $rs1
/*  4962*/          OPC_RecordChild1, // #3 = $imm12
/*  4963*/          OPC_MoveChild1,
/*  4964*/          OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  4967*/          OPC_CheckPredicate, 0, // Predicate_simm12
/*  4969*/          OPC_MoveParent,
/*  4970*/          OPC_CheckPredicate, 1, // Predicate_IsOrAdd
/*  4972*/          OPC_CheckType, MVT::i64,
/*  4974*/          OPC_MoveParent,
/*  4975*/          OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  4977*/          OPC_Scope, 42, /*->5021*/ // 4 children in Scope
/*  4979*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  4981*/            OPC_Scope, 18, /*->5001*/ // 2 children in Scope
/*  4983*/              OPC_CheckPredicate, 12, // Predicate_truncstorei8
/*  4985*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  4987*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  4990*/              OPC_EmitMergeInputChains1_0,
/*  4991*/              OPC_EmitConvertToTarget, 3,
/*  4993*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i64] }:$rs2, (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 18
                        // Dst: (SB GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5001*/            /*Scope*/ 18, /*->5020*/
/*  5002*/              OPC_CheckPredicate, 13, // Predicate_truncstorei16
/*  5004*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  5006*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5009*/              OPC_EmitMergeInputChains1_0,
/*  5010*/              OPC_EmitConvertToTarget, 3,
/*  5012*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i64] }:$rs2, (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 18
                        // Dst: (SH GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5020*/            0, /*End of Scope*/
/*  5021*/          /*Scope*/ 18, /*->5040*/
/*  5022*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5024*/            OPC_CheckPatternPredicate, 6, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5026*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5029*/            OPC_EmitMergeInputChains1_0,
/*  5030*/            OPC_EmitConvertToTarget, 3,
/*  5032*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 4, 5, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 18
                      // Dst: (SW GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5040*/          /*Scope*/ 20, /*->5061*/
/*  5041*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  5043*/            OPC_CheckPredicate, 15, // Predicate_truncstorei32
/*  5045*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5047*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5050*/            OPC_EmitMergeInputChains1_0,
/*  5051*/            OPC_EmitConvertToTarget, 3,
/*  5053*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 4, 5, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 18
                      // Dst: (SW GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5061*/          /*Scope*/ 18, /*->5080*/
/*  5062*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5064*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5066*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5069*/            OPC_EmitMergeInputChains1_0,
/*  5070*/            OPC_EmitConvertToTarget, 3,
/*  5072*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 4, 5, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 18
                      // Dst: (SD GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5080*/          0, /*End of Scope*/
/*  5081*/        /*SwitchOpcode*/ 77|128,1/*205*/, TARGET_VAL(ISD::ADD),// ->5290
/*  5085*/          OPC_RecordChild0, // #2 = $rs1
/*  5086*/          OPC_RecordChild1, // #3 = $imm12
/*  5087*/          OPC_MoveChild1,
/*  5088*/          OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  5091*/          OPC_CheckPredicate, 0, // Predicate_simm12
/*  5093*/          OPC_MoveParent,
/*  5094*/          OPC_CheckType, MVT::i64,
/*  5096*/          OPC_MoveParent,
/*  5097*/          OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  5099*/          OPC_Scope, 42, /*->5143*/ // 8 children in Scope
/*  5101*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  5103*/            OPC_Scope, 18, /*->5123*/ // 2 children in Scope
/*  5105*/              OPC_CheckPredicate, 12, // Predicate_truncstorei8
/*  5107*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  5109*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5112*/              OPC_EmitMergeInputChains1_0,
/*  5113*/              OPC_EmitConvertToTarget, 3,
/*  5115*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i64] }:$rs2, (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 17
                        // Dst: (SB GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5123*/            /*Scope*/ 18, /*->5142*/
/*  5124*/              OPC_CheckPredicate, 13, // Predicate_truncstorei16
/*  5126*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  5128*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5131*/              OPC_EmitMergeInputChains1_0,
/*  5132*/              OPC_EmitConvertToTarget, 3,
/*  5134*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st GPR:{ *:[i64] }:$rs2, (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 17
                        // Dst: (SH GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5142*/            0, /*End of Scope*/
/*  5143*/          /*Scope*/ 18, /*->5162*/
/*  5144*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5146*/            OPC_CheckPatternPredicate, 6, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5148*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5151*/            OPC_EmitMergeInputChains1_0,
/*  5152*/            OPC_EmitConvertToTarget, 3,
/*  5154*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 4, 5, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 17
                      // Dst: (SW GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5162*/          /*Scope*/ 20, /*->5183*/
/*  5163*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  5165*/            OPC_CheckPredicate, 15, // Predicate_truncstorei32
/*  5167*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5169*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5172*/            OPC_EmitMergeInputChains1_0,
/*  5173*/            OPC_EmitConvertToTarget, 3,
/*  5175*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 4, 5, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 17
                      // Dst: (SW GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5183*/          /*Scope*/ 18, /*->5202*/
/*  5184*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5186*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5188*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5191*/            OPC_EmitMergeInputChains1_0,
/*  5192*/            OPC_EmitConvertToTarget, 3,
/*  5194*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 4, 5, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 17
                      // Dst: (SD GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5202*/          /*Scope*/ 36, /*->5239*/
/*  5203*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  5205*/            OPC_Scope, 15, /*->5222*/ // 2 children in Scope
/*  5207*/              OPC_CheckPredicate, 12, // Predicate_truncstorei8
/*  5209*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  5211*/              OPC_EmitMergeInputChains1_0,
/*  5212*/              OPC_EmitConvertToTarget, 3,
/*  5214*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st GPR:{ *:[i64] }:$rs2, (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 11
                        // Dst: (SB GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5222*/            /*Scope*/ 15, /*->5238*/
/*  5223*/              OPC_CheckPredicate, 13, // Predicate_truncstorei16
/*  5225*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  5227*/              OPC_EmitMergeInputChains1_0,
/*  5228*/              OPC_EmitConvertToTarget, 3,
/*  5230*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st GPR:{ *:[i64] }:$rs2, (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 11
                        // Dst: (SH GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5238*/            0, /*End of Scope*/
/*  5239*/          /*Scope*/ 15, /*->5255*/
/*  5240*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5242*/            OPC_CheckPatternPredicate, 6, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5244*/            OPC_EmitMergeInputChains1_0,
/*  5245*/            OPC_EmitConvertToTarget, 3,
/*  5247*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 2, 4, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 11
                      // Dst: (SW GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5255*/          /*Scope*/ 17, /*->5273*/
/*  5256*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  5258*/            OPC_CheckPredicate, 15, // Predicate_truncstorei32
/*  5260*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5262*/            OPC_EmitMergeInputChains1_0,
/*  5263*/            OPC_EmitConvertToTarget, 3,
/*  5265*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 2, 4, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 11
                      // Dst: (SW GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5273*/          /*Scope*/ 15, /*->5289*/
/*  5274*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5276*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5278*/            OPC_EmitMergeInputChains1_0,
/*  5279*/            OPC_EmitConvertToTarget, 3,
/*  5281*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 2, 4, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 11
                      // Dst: (SD GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5289*/          0, /*End of Scope*/
/*  5290*/        0, // EndSwitchOpcode
/*  5291*/      /*Scope*/ 81|128,1/*209*/, /*->5502*/
/*  5293*/        OPC_RecordChild2, // #2 = $rs1
/*  5294*/        OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  5296*/        OPC_Scope, 44, /*->5342*/ // 5 children in Scope
/*  5298*/          OPC_CheckPredicate, 11, // Predicate_truncstore
/*  5300*/          OPC_Scope, 19, /*->5321*/ // 2 children in Scope
/*  5302*/            OPC_CheckPredicate, 12, // Predicate_truncstorei8
/*  5304*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  5306*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  5309*/            OPC_EmitMergeInputChains1_0,
/*  5310*/            OPC_EmitInteger, MVT::i64, 0, 
/*  5313*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 3, 4, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 10
                      // Dst: (SB GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  5321*/          /*Scope*/ 19, /*->5341*/
/*  5322*/            OPC_CheckPredicate, 13, // Predicate_truncstorei16
/*  5324*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  5326*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  5329*/            OPC_EmitMergeInputChains1_0,
/*  5330*/            OPC_EmitInteger, MVT::i64, 0, 
/*  5333*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 3, 4, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 10
                      // Dst: (SH GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  5341*/          0, /*End of Scope*/
/*  5342*/        /*Scope*/ 19, /*->5362*/
/*  5343*/          OPC_CheckPredicate, 14, // Predicate_store
/*  5345*/          OPC_CheckPatternPredicate, 6, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5347*/          OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  5350*/          OPC_EmitMergeInputChains1_0,
/*  5351*/          OPC_EmitInteger, MVT::i64, 0, 
/*  5354*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 1, 3, 4, 
                    // Src: (st GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 10
                    // Dst: (SW GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  5362*/        /*Scope*/ 21, /*->5384*/
/*  5363*/          OPC_CheckPredicate, 11, // Predicate_truncstore
/*  5365*/          OPC_CheckPredicate, 15, // Predicate_truncstorei32
/*  5367*/          OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5369*/          OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  5372*/          OPC_EmitMergeInputChains1_0,
/*  5373*/          OPC_EmitInteger, MVT::i64, 0, 
/*  5376*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 1, 3, 4, 
                    // Src: (st GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 10
                    // Dst: (SW GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  5384*/        /*Scope*/ 19, /*->5404*/
/*  5385*/          OPC_CheckPredicate, 14, // Predicate_store
/*  5387*/          OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5389*/          OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  5392*/          OPC_EmitMergeInputChains1_0,
/*  5393*/          OPC_EmitInteger, MVT::i64, 0, 
/*  5396*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 1, 3, 4, 
                    // Src: (st GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 10
                    // Dst: (SD GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  5404*/        /*Scope*/ 96, /*->5501*/
/*  5405*/          OPC_CheckChild2Type, MVT::i64,
/*  5407*/          OPC_Scope, 38, /*->5447*/ // 4 children in Scope
/*  5409*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  5411*/            OPC_Scope, 16, /*->5429*/ // 2 children in Scope
/*  5413*/              OPC_CheckPredicate, 12, // Predicate_truncstorei8
/*  5415*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  5417*/              OPC_EmitMergeInputChains1_0,
/*  5418*/              OPC_EmitInteger, MVT::i64, 0, 
/*  5421*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 3, 
                        // Src: (st GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei8>> - Complexity = 4
                        // Dst: (SB GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  5429*/            /*Scope*/ 16, /*->5446*/
/*  5430*/              OPC_CheckPredicate, 13, // Predicate_truncstorei16
/*  5432*/              OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  5434*/              OPC_EmitMergeInputChains1_0,
/*  5435*/              OPC_EmitInteger, MVT::i64, 0, 
/*  5438*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 3, 
                        // Src: (st GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei16>> - Complexity = 4
                        // Dst: (SH GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  5446*/            0, /*End of Scope*/
/*  5447*/          /*Scope*/ 16, /*->5464*/
/*  5448*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5450*/            OPC_CheckPatternPredicate, 6, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5452*/            OPC_EmitMergeInputChains1_0,
/*  5453*/            OPC_EmitInteger, MVT::i64, 0, 
/*  5456*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 4
                      // Dst: (SW GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  5464*/          /*Scope*/ 18, /*->5483*/
/*  5465*/            OPC_CheckPredicate, 11, // Predicate_truncstore
/*  5467*/            OPC_CheckPredicate, 15, // Predicate_truncstorei32
/*  5469*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5471*/            OPC_EmitMergeInputChains1_0,
/*  5472*/            OPC_EmitInteger, MVT::i64, 0, 
/*  5475*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_truncstore>><<P:Predicate_truncstorei32>> - Complexity = 4
                      // Dst: (SW GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  5483*/          /*Scope*/ 16, /*->5500*/
/*  5484*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5486*/            OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5488*/            OPC_EmitMergeInputChains1_0,
/*  5489*/            OPC_EmitInteger, MVT::i64, 0, 
/*  5492*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SD), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (st GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 4
                      // Dst: (SD GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  5500*/          0, /*End of Scope*/
/*  5501*/        0, /*End of Scope*/
/*  5502*/      0, /*End of Scope*/
/*  5503*/    /*Scope*/ 72|128,2/*328*/, /*->5833*/
/*  5505*/      OPC_CheckChild1Type, MVT::f32,
/*  5507*/      OPC_Scope, 80|128,1/*208*/, /*->5718*/ // 2 children in Scope
/*  5510*/        OPC_MoveChild2,
/*  5511*/        OPC_SwitchOpcode /*2 cases */, 79, TARGET_VAL(ISD::OR),// ->5594
/*  5515*/          OPC_RecordChild0, // #2 = $rs1
/*  5516*/          OPC_RecordChild1, // #3 = $imm12
/*  5517*/          OPC_MoveChild1,
/*  5518*/          OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  5521*/          OPC_CheckPredicate, 0, // Predicate_simm12
/*  5523*/          OPC_MoveParent,
/*  5524*/          OPC_CheckPredicate, 1, // Predicate_IsOrAdd
/*  5526*/          OPC_SwitchType /*2 cases */, 41, MVT::i32,// ->5570
/*  5529*/            OPC_MoveParent,
/*  5530*/            OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  5532*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5534*/            OPC_Scope, 16, /*->5552*/ // 2 children in Scope
/*  5536*/              OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  5538*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5541*/              OPC_EmitMergeInputChains1_0,
/*  5542*/              OPC_EmitConvertToTarget, 3,
/*  5544*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st FPR32:{ *:[f32] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 18
                        // Dst: (FSW FPR32:{ *:[f32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  5552*/            /*Scope*/ 16, /*->5569*/
/*  5553*/              OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/*  5555*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5558*/              OPC_EmitMergeInputChains1_0,
/*  5559*/              OPC_EmitConvertToTarget, 3,
/*  5561*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st FPR32:{ *:[f32] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 18
                        // Dst: (FSW FPR32:{ *:[f32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  5569*/            0, /*End of Scope*/
/*  5570*/          /*SwitchType*/ 21, MVT::i64,// ->5593
/*  5572*/            OPC_MoveParent,
/*  5573*/            OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  5575*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5577*/            OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5579*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5582*/            OPC_EmitMergeInputChains1_0,
/*  5583*/            OPC_EmitConvertToTarget, 3,
/*  5585*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 4, 5, 
                      // Src: (st FPR32:{ *:[f32] }:$rs2, (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 18
                      // Dst: (FSW FPR32:{ *:[f32] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5593*/          0, // EndSwitchType
/*  5594*/        /*SwitchOpcode*/ 120, TARGET_VAL(ISD::ADD),// ->5717
/*  5597*/          OPC_RecordChild0, // #2 = $rs1
/*  5598*/          OPC_RecordChild1, // #3 = $imm12
/*  5599*/          OPC_MoveChild1,
/*  5600*/          OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  5603*/          OPC_CheckPredicate, 0, // Predicate_simm12
/*  5605*/          OPC_MoveParent,
/*  5606*/          OPC_SwitchType /*2 cases */, 69, MVT::i32,// ->5678
/*  5609*/            OPC_MoveParent,
/*  5610*/            OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  5612*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5614*/            OPC_Scope, 16, /*->5632*/ // 4 children in Scope
/*  5616*/              OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  5618*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5621*/              OPC_EmitMergeInputChains1_0,
/*  5622*/              OPC_EmitConvertToTarget, 3,
/*  5624*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st FPR32:{ *:[f32] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 17
                        // Dst: (FSW FPR32:{ *:[f32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  5632*/            /*Scope*/ 16, /*->5649*/
/*  5633*/              OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/*  5635*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5638*/              OPC_EmitMergeInputChains1_0,
/*  5639*/              OPC_EmitConvertToTarget, 3,
/*  5641*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st FPR32:{ *:[f32] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 17
                        // Dst: (FSW FPR32:{ *:[f32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  5649*/            /*Scope*/ 13, /*->5663*/
/*  5650*/              OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  5652*/              OPC_EmitMergeInputChains1_0,
/*  5653*/              OPC_EmitConvertToTarget, 3,
/*  5655*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st FPR32:{ *:[f32] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 11
                        // Dst: (FSW FPR32:{ *:[f32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  5663*/            /*Scope*/ 13, /*->5677*/
/*  5664*/              OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/*  5666*/              OPC_EmitMergeInputChains1_0,
/*  5667*/              OPC_EmitConvertToTarget, 3,
/*  5669*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st FPR32:{ *:[f32] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 11
                        // Dst: (FSW FPR32:{ *:[f32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  5677*/            0, /*End of Scope*/
/*  5678*/          /*SwitchType*/ 36, MVT::i64,// ->5716
/*  5680*/            OPC_MoveParent,
/*  5681*/            OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  5683*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5685*/            OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5687*/            OPC_Scope, 14, /*->5703*/ // 2 children in Scope
/*  5689*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5692*/              OPC_EmitMergeInputChains1_0,
/*  5693*/              OPC_EmitConvertToTarget, 3,
/*  5695*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st FPR32:{ *:[f32] }:$rs2, (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 17
                        // Dst: (FSW FPR32:{ *:[f32] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5703*/            /*Scope*/ 11, /*->5715*/
/*  5704*/              OPC_EmitMergeInputChains1_0,
/*  5705*/              OPC_EmitConvertToTarget, 3,
/*  5707*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st FPR32:{ *:[f32] }:$rs2, (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 11
                        // Dst: (FSW FPR32:{ *:[f32] }:$rs2, GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5715*/            0, /*End of Scope*/
/*  5716*/          0, // EndSwitchType
/*  5717*/        0, // EndSwitchOpcode
/*  5718*/      /*Scope*/ 113, /*->5832*/
/*  5719*/        OPC_RecordChild2, // #2 = $rs1
/*  5720*/        OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  5722*/        OPC_CheckPredicate, 14, // Predicate_store
/*  5724*/        OPC_Scope, 17, /*->5743*/ // 5 children in Scope
/*  5726*/          OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  5728*/          OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  5731*/          OPC_EmitMergeInputChains1_0,
/*  5732*/          OPC_EmitInteger, MVT::i32, 0, 
/*  5735*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 1, 3, 4, 
                    // Src: (st FPR32:{ *:[f32] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 10
                    // Dst: (FSW FPR32:{ *:[f32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  5743*/        /*Scope*/ 17, /*->5761*/
/*  5744*/          OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5746*/          OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  5749*/          OPC_EmitMergeInputChains1_0,
/*  5750*/          OPC_EmitInteger, MVT::i64, 0, 
/*  5753*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 1, 3, 4, 
                    // Src: (st FPR32:{ *:[f32] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 10
                    // Dst: (FSW FPR32:{ *:[f32] }:$rs2, AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  5761*/        /*Scope*/ 17, /*->5779*/
/*  5762*/          OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/*  5764*/          OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  5767*/          OPC_EmitMergeInputChains1_0,
/*  5768*/          OPC_EmitInteger, MVT::i32, 0, 
/*  5771*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 1, 3, 4, 
                    // Src: (st FPR32:{ *:[f32] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 10
                    // Dst: (FSW FPR32:{ *:[f32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  5779*/        /*Scope*/ 34, /*->5814*/
/*  5780*/          OPC_CheckChild2Type, MVT::i32,
/*  5782*/          OPC_Scope, 14, /*->5798*/ // 2 children in Scope
/*  5784*/            OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  5786*/            OPC_EmitMergeInputChains1_0,
/*  5787*/            OPC_EmitInteger, MVT::i32, 0, 
/*  5790*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (st FPR32:{ *:[f32] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 4
                      // Dst: (FSW FPR32:{ *:[f32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  5798*/          /*Scope*/ 14, /*->5813*/
/*  5799*/            OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/*  5801*/            OPC_EmitMergeInputChains1_0,
/*  5802*/            OPC_EmitInteger, MVT::i32, 0, 
/*  5805*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (st FPR32:{ *:[f32] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 4
                      // Dst: (FSW FPR32:{ *:[f32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  5813*/          0, /*End of Scope*/
/*  5814*/        /*Scope*/ 16, /*->5831*/
/*  5815*/          OPC_CheckChild2Type, MVT::i64,
/*  5817*/          OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5819*/          OPC_EmitMergeInputChains1_0,
/*  5820*/          OPC_EmitInteger, MVT::i64, 0, 
/*  5823*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSW), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 1, 2, 3, 
                    // Src: (st FPR32:{ *:[f32] }:$rs2, GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 4
                    // Dst: (FSW FPR32:{ *:[f32] }:$rs2, GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  5831*/        0, /*End of Scope*/
/*  5832*/      0, /*End of Scope*/
/*  5833*/    /*Scope*/ 72|128,2/*328*/, /*->6163*/
/*  5835*/      OPC_CheckChild1Type, MVT::f64,
/*  5837*/      OPC_Scope, 80|128,1/*208*/, /*->6048*/ // 2 children in Scope
/*  5840*/        OPC_MoveChild2,
/*  5841*/        OPC_SwitchOpcode /*2 cases */, 79, TARGET_VAL(ISD::OR),// ->5924
/*  5845*/          OPC_RecordChild0, // #2 = $rs1
/*  5846*/          OPC_RecordChild1, // #3 = $imm12
/*  5847*/          OPC_MoveChild1,
/*  5848*/          OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  5851*/          OPC_CheckPredicate, 0, // Predicate_simm12
/*  5853*/          OPC_MoveParent,
/*  5854*/          OPC_CheckPredicate, 1, // Predicate_IsOrAdd
/*  5856*/          OPC_SwitchType /*2 cases */, 41, MVT::i32,// ->5900
/*  5859*/            OPC_MoveParent,
/*  5860*/            OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  5862*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5864*/            OPC_Scope, 16, /*->5882*/ // 2 children in Scope
/*  5866*/              OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  5868*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5871*/              OPC_EmitMergeInputChains1_0,
/*  5872*/              OPC_EmitConvertToTarget, 3,
/*  5874*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st FPR64:{ *:[f64] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 18
                        // Dst: (FSD FPR64:{ *:[f64] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  5882*/            /*Scope*/ 16, /*->5899*/
/*  5883*/              OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/*  5885*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5888*/              OPC_EmitMergeInputChains1_0,
/*  5889*/              OPC_EmitConvertToTarget, 3,
/*  5891*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st FPR64:{ *:[f64] }:$rs2, (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 18
                        // Dst: (FSD FPR64:{ *:[f64] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  5899*/            0, /*End of Scope*/
/*  5900*/          /*SwitchType*/ 21, MVT::i64,// ->5923
/*  5902*/            OPC_MoveParent,
/*  5903*/            OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  5905*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5907*/            OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  5909*/            OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5912*/            OPC_EmitMergeInputChains1_0,
/*  5913*/            OPC_EmitConvertToTarget, 3,
/*  5915*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 4, 5, 
                      // Src: (st FPR64:{ *:[f64] }:$rs2, (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 18
                      // Dst: (FSD FPR64:{ *:[f64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  5923*/          0, // EndSwitchType
/*  5924*/        /*SwitchOpcode*/ 120, TARGET_VAL(ISD::ADD),// ->6047
/*  5927*/          OPC_RecordChild0, // #2 = $rs1
/*  5928*/          OPC_RecordChild1, // #3 = $imm12
/*  5929*/          OPC_MoveChild1,
/*  5930*/          OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  5933*/          OPC_CheckPredicate, 0, // Predicate_simm12
/*  5935*/          OPC_MoveParent,
/*  5936*/          OPC_SwitchType /*2 cases */, 69, MVT::i32,// ->6008
/*  5939*/            OPC_MoveParent,
/*  5940*/            OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  5942*/            OPC_CheckPredicate, 14, // Predicate_store
/*  5944*/            OPC_Scope, 16, /*->5962*/ // 4 children in Scope
/*  5946*/              OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  5948*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5951*/              OPC_EmitMergeInputChains1_0,
/*  5952*/              OPC_EmitConvertToTarget, 3,
/*  5954*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st FPR64:{ *:[f64] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 17
                        // Dst: (FSD FPR64:{ *:[f64] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  5962*/            /*Scope*/ 16, /*->5979*/
/*  5963*/              OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/*  5965*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  5968*/              OPC_EmitMergeInputChains1_0,
/*  5969*/              OPC_EmitConvertToTarget, 3,
/*  5971*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st FPR64:{ *:[f64] }:$rs2, (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 17
                        // Dst: (FSD FPR64:{ *:[f64] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  5979*/            /*Scope*/ 13, /*->5993*/
/*  5980*/              OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  5982*/              OPC_EmitMergeInputChains1_0,
/*  5983*/              OPC_EmitConvertToTarget, 3,
/*  5985*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st FPR64:{ *:[f64] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 11
                        // Dst: (FSD FPR64:{ *:[f64] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  5993*/            /*Scope*/ 13, /*->6007*/
/*  5994*/              OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/*  5996*/              OPC_EmitMergeInputChains1_0,
/*  5997*/              OPC_EmitConvertToTarget, 3,
/*  5999*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st FPR64:{ *:[f64] }:$rs2, (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 11
                        // Dst: (FSD FPR64:{ *:[f64] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6007*/            0, /*End of Scope*/
/*  6008*/          /*SwitchType*/ 36, MVT::i64,// ->6046
/*  6010*/            OPC_MoveParent,
/*  6011*/            OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  6013*/            OPC_CheckPredicate, 14, // Predicate_store
/*  6015*/            OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6017*/            OPC_Scope, 14, /*->6033*/ // 2 children in Scope
/*  6019*/              OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #4
/*  6022*/              OPC_EmitMergeInputChains1_0,
/*  6023*/              OPC_EmitConvertToTarget, 3,
/*  6025*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 4, 5, 
                        // Src: (st FPR64:{ *:[f64] }:$rs2, (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 17
                        // Dst: (FSD FPR64:{ *:[f64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  6033*/            /*Scope*/ 11, /*->6045*/
/*  6034*/              OPC_EmitMergeInputChains1_0,
/*  6035*/              OPC_EmitConvertToTarget, 3,
/*  6037*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 1, 2, 4, 
                        // Src: (st FPR64:{ *:[f64] }:$rs2, (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 11
                        // Dst: (FSD FPR64:{ *:[f64] }:$rs2, GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  6045*/            0, /*End of Scope*/
/*  6046*/          0, // EndSwitchType
/*  6047*/        0, // EndSwitchOpcode
/*  6048*/      /*Scope*/ 113, /*->6162*/
/*  6049*/        OPC_RecordChild2, // #2 = $rs1
/*  6050*/        OPC_CheckPredicate, 10, // Predicate_unindexedstore
/*  6052*/        OPC_CheckPredicate, 14, // Predicate_store
/*  6054*/        OPC_Scope, 17, /*->6073*/ // 5 children in Scope
/*  6056*/          OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6058*/          OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  6061*/          OPC_EmitMergeInputChains1_0,
/*  6062*/          OPC_EmitInteger, MVT::i32, 0, 
/*  6065*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 1, 3, 4, 
                    // Src: (st FPR64:{ *:[f64] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 10
                    // Dst: (FSD FPR64:{ *:[f64] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  6073*/        /*Scope*/ 17, /*->6091*/
/*  6074*/          OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6076*/          OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  6079*/          OPC_EmitMergeInputChains1_0,
/*  6080*/          OPC_EmitInteger, MVT::i64, 0, 
/*  6083*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 1, 3, 4, 
                    // Src: (st FPR64:{ *:[f64] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 10
                    // Dst: (FSD FPR64:{ *:[f64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  6091*/        /*Scope*/ 17, /*->6109*/
/*  6092*/          OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/*  6094*/          OPC_CheckComplexPat, /*CP*/0, /*#*/2, // SelectAddrFI:$rs1 #3
/*  6097*/          OPC_EmitMergeInputChains1_0,
/*  6098*/          OPC_EmitInteger, MVT::i32, 0, 
/*  6101*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 1, 3, 4, 
                    // Src: (st FPR64:{ *:[f64] }:$rs2, AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 10
                    // Dst: (FSD FPR64:{ *:[f64] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  6109*/        /*Scope*/ 34, /*->6144*/
/*  6110*/          OPC_CheckChild2Type, MVT::i32,
/*  6112*/          OPC_Scope, 14, /*->6128*/ // 2 children in Scope
/*  6114*/            OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6116*/            OPC_EmitMergeInputChains1_0,
/*  6117*/            OPC_EmitInteger, MVT::i32, 0, 
/*  6120*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (st FPR64:{ *:[f64] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 4
                      // Dst: (FSD FPR64:{ *:[f64] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  6128*/          /*Scope*/ 14, /*->6143*/
/*  6129*/            OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/*  6131*/            OPC_EmitMergeInputChains1_0,
/*  6132*/            OPC_EmitInteger, MVT::i32, 0, 
/*  6135*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (st FPR64:{ *:[f64] }:$rs2, GPR:{ *:[i32] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 4
                      // Dst: (FSD FPR64:{ *:[f64] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  6143*/          0, /*End of Scope*/
/*  6144*/        /*Scope*/ 16, /*->6161*/
/*  6145*/          OPC_CheckChild2Type, MVT::i64,
/*  6147*/          OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6149*/          OPC_EmitMergeInputChains1_0,
/*  6150*/          OPC_EmitInteger, MVT::i64, 0, 
/*  6153*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FSD), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 1, 2, 3, 
                    // Src: (st FPR64:{ *:[f64] }:$rs2, GPR:{ *:[i64] }:$rs1)<<P:Predicate_unindexedstore>><<P:Predicate_store>> - Complexity = 4
                    // Dst: (FSD FPR64:{ *:[f64] }:$rs2, GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  6161*/        0, /*End of Scope*/
/*  6162*/      0, /*End of Scope*/
/*  6163*/    0, /*End of Scope*/
/*  6164*/  /*SwitchOpcode*/ 48|128,7/*944*/, TARGET_VAL(ISD::ATOMIC_STORE),// ->7112
/*  6168*/    OPC_RecordMemRef,
/*  6169*/    OPC_RecordNode, // #0 = 'atomic_store' chained node
/*  6170*/    OPC_Scope, 51|128,4/*563*/, /*->6736*/ // 2 children in Scope
/*  6173*/      OPC_MoveChild1,
/*  6174*/      OPC_SwitchOpcode /*2 cases */, 75|128,1/*203*/, TARGET_VAL(ISD::OR),// ->6382
/*  6179*/        OPC_RecordChild0, // #1 = $rs1
/*  6180*/        OPC_RecordChild1, // #2 = $imm12
/*  6181*/        OPC_MoveChild1,
/*  6182*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  6185*/        OPC_CheckPredicate, 0, // Predicate_simm12
/*  6187*/        OPC_MoveParent,
/*  6188*/        OPC_CheckPredicate, 1, // Predicate_IsOrAdd
/*  6190*/        OPC_SwitchType /*2 cases */, 123, MVT::i32,// ->6316
/*  6193*/          OPC_MoveParent,
/*  6194*/          OPC_RecordChild2, // #3 = $rs2
/*  6195*/          OPC_CheckChild2Type, MVT::i32,
/*  6197*/          OPC_Scope, 38, /*->6237*/ // 3 children in Scope
/*  6199*/            OPC_CheckPredicate, 16, // Predicate_atomic_store_8
/*  6201*/            OPC_Scope, 16, /*->6219*/ // 2 children in Scope
/*  6203*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6205*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6208*/              OPC_EmitMergeInputChains1_0,
/*  6209*/              OPC_EmitConvertToTarget, 2,
/*  6211*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 4, 5, 
                        // Src: (atomic_store (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 18
                        // Dst: (SB GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6219*/            /*Scope*/ 16, /*->6236*/
/*  6220*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  6222*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6225*/              OPC_EmitMergeInputChains1_0,
/*  6226*/              OPC_EmitConvertToTarget, 2,
/*  6228*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 4, 5, 
                        // Src: (atomic_store (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 18
                        // Dst: (SB GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6236*/            0, /*End of Scope*/
/*  6237*/          /*Scope*/ 38, /*->6276*/
/*  6238*/            OPC_CheckPredicate, 17, // Predicate_atomic_store_16
/*  6240*/            OPC_Scope, 16, /*->6258*/ // 2 children in Scope
/*  6242*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6244*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6247*/              OPC_EmitMergeInputChains1_0,
/*  6248*/              OPC_EmitConvertToTarget, 2,
/*  6250*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 4, 5, 
                        // Src: (atomic_store (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 18
                        // Dst: (SH GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6258*/            /*Scope*/ 16, /*->6275*/
/*  6259*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  6261*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6264*/              OPC_EmitMergeInputChains1_0,
/*  6265*/              OPC_EmitConvertToTarget, 2,
/*  6267*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 4, 5, 
                        // Src: (atomic_store (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 18
                        // Dst: (SH GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6275*/            0, /*End of Scope*/
/*  6276*/          /*Scope*/ 38, /*->6315*/
/*  6277*/            OPC_CheckPredicate, 18, // Predicate_atomic_store_32
/*  6279*/            OPC_Scope, 16, /*->6297*/ // 2 children in Scope
/*  6281*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6283*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6286*/              OPC_EmitMergeInputChains1_0,
/*  6287*/              OPC_EmitConvertToTarget, 2,
/*  6289*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 4, 5, 
                        // Src: (atomic_store (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 18
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6297*/            /*Scope*/ 16, /*->6314*/
/*  6298*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  6300*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6303*/              OPC_EmitMergeInputChains1_0,
/*  6304*/              OPC_EmitConvertToTarget, 2,
/*  6306*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 4, 5, 
                        // Src: (atomic_store (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 18
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6314*/            0, /*End of Scope*/
/*  6315*/          0, /*End of Scope*/
/*  6316*/        /*SwitchType*/ 63, MVT::i64,// ->6381
/*  6318*/          OPC_MoveParent,
/*  6319*/          OPC_RecordChild2, // #3 = $rs2
/*  6320*/          OPC_CheckChild2Type, MVT::i64,
/*  6322*/          OPC_Scope, 18, /*->6342*/ // 3 children in Scope
/*  6324*/            OPC_CheckPredicate, 16, // Predicate_atomic_store_8
/*  6326*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6328*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6331*/            OPC_EmitMergeInputChains1_0,
/*  6332*/            OPC_EmitConvertToTarget, 2,
/*  6334*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 3, 4, 5, 
                      // Src: (atomic_store (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 18
                      // Dst: (SB GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  6342*/          /*Scope*/ 18, /*->6361*/
/*  6343*/            OPC_CheckPredicate, 17, // Predicate_atomic_store_16
/*  6345*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6347*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6350*/            OPC_EmitMergeInputChains1_0,
/*  6351*/            OPC_EmitConvertToTarget, 2,
/*  6353*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 3, 4, 5, 
                      // Src: (atomic_store (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 18
                      // Dst: (SH GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  6361*/          /*Scope*/ 18, /*->6380*/
/*  6362*/            OPC_CheckPredicate, 18, // Predicate_atomic_store_32
/*  6364*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6366*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6369*/            OPC_EmitMergeInputChains1_0,
/*  6370*/            OPC_EmitConvertToTarget, 2,
/*  6372*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 3, 4, 5, 
                      // Src: (atomic_store (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 18
                      // Dst: (SW GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  6380*/          0, /*End of Scope*/
/*  6381*/        0, // EndSwitchType
/*  6382*/      /*SwitchOpcode*/ 93|128,2/*349*/, TARGET_VAL(ISD::ADD),// ->6735
/*  6386*/        OPC_RecordChild0, // #1 = $rs1
/*  6387*/        OPC_RecordChild1, // #2 = $imm12
/*  6388*/        OPC_MoveChild1,
/*  6389*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  6392*/        OPC_CheckPredicate, 0, // Predicate_simm12
/*  6394*/        OPC_MoveParent,
/*  6395*/        OPC_SwitchType /*2 cases */, 94|128,1/*222*/, MVT::i32,// ->6621
/*  6399*/          OPC_MoveParent,
/*  6400*/          OPC_RecordChild2, // #3 = $rs2
/*  6401*/          OPC_CheckChild2Type, MVT::i32,
/*  6403*/          OPC_Scope, 38, /*->6443*/ // 6 children in Scope
/*  6405*/            OPC_CheckPredicate, 16, // Predicate_atomic_store_8
/*  6407*/            OPC_Scope, 16, /*->6425*/ // 2 children in Scope
/*  6409*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6411*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6414*/              OPC_EmitMergeInputChains1_0,
/*  6415*/              OPC_EmitConvertToTarget, 2,
/*  6417*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 4, 5, 
                        // Src: (atomic_store (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 17
                        // Dst: (SB GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6425*/            /*Scope*/ 16, /*->6442*/
/*  6426*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  6428*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6431*/              OPC_EmitMergeInputChains1_0,
/*  6432*/              OPC_EmitConvertToTarget, 2,
/*  6434*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 4, 5, 
                        // Src: (atomic_store (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 17
                        // Dst: (SB GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6442*/            0, /*End of Scope*/
/*  6443*/          /*Scope*/ 38, /*->6482*/
/*  6444*/            OPC_CheckPredicate, 17, // Predicate_atomic_store_16
/*  6446*/            OPC_Scope, 16, /*->6464*/ // 2 children in Scope
/*  6448*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6450*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6453*/              OPC_EmitMergeInputChains1_0,
/*  6454*/              OPC_EmitConvertToTarget, 2,
/*  6456*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 4, 5, 
                        // Src: (atomic_store (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 17
                        // Dst: (SH GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6464*/            /*Scope*/ 16, /*->6481*/
/*  6465*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  6467*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6470*/              OPC_EmitMergeInputChains1_0,
/*  6471*/              OPC_EmitConvertToTarget, 2,
/*  6473*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 4, 5, 
                        // Src: (atomic_store (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 17
                        // Dst: (SH GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6481*/            0, /*End of Scope*/
/*  6482*/          /*Scope*/ 38, /*->6521*/
/*  6483*/            OPC_CheckPredicate, 18, // Predicate_atomic_store_32
/*  6485*/            OPC_Scope, 16, /*->6503*/ // 2 children in Scope
/*  6487*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6489*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6492*/              OPC_EmitMergeInputChains1_0,
/*  6493*/              OPC_EmitConvertToTarget, 2,
/*  6495*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 4, 5, 
                        // Src: (atomic_store (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 17
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6503*/            /*Scope*/ 16, /*->6520*/
/*  6504*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  6506*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6509*/              OPC_EmitMergeInputChains1_0,
/*  6510*/              OPC_EmitConvertToTarget, 2,
/*  6512*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 4, 5, 
                        // Src: (atomic_store (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 17
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6520*/            0, /*End of Scope*/
/*  6521*/          /*Scope*/ 32, /*->6554*/
/*  6522*/            OPC_CheckPredicate, 16, // Predicate_atomic_store_8
/*  6524*/            OPC_Scope, 13, /*->6539*/ // 2 children in Scope
/*  6526*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6528*/              OPC_EmitMergeInputChains1_0,
/*  6529*/              OPC_EmitConvertToTarget, 2,
/*  6531*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 1, 4, 
                        // Src: (atomic_store (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 11
                        // Dst: (SB GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6539*/            /*Scope*/ 13, /*->6553*/
/*  6540*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  6542*/              OPC_EmitMergeInputChains1_0,
/*  6543*/              OPC_EmitConvertToTarget, 2,
/*  6545*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 1, 4, 
                        // Src: (atomic_store (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 11
                        // Dst: (SB GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6553*/            0, /*End of Scope*/
/*  6554*/          /*Scope*/ 32, /*->6587*/
/*  6555*/            OPC_CheckPredicate, 17, // Predicate_atomic_store_16
/*  6557*/            OPC_Scope, 13, /*->6572*/ // 2 children in Scope
/*  6559*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6561*/              OPC_EmitMergeInputChains1_0,
/*  6562*/              OPC_EmitConvertToTarget, 2,
/*  6564*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 1, 4, 
                        // Src: (atomic_store (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 11
                        // Dst: (SH GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6572*/            /*Scope*/ 13, /*->6586*/
/*  6573*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  6575*/              OPC_EmitMergeInputChains1_0,
/*  6576*/              OPC_EmitConvertToTarget, 2,
/*  6578*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 1, 4, 
                        // Src: (atomic_store (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 11
                        // Dst: (SH GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6586*/            0, /*End of Scope*/
/*  6587*/          /*Scope*/ 32, /*->6620*/
/*  6588*/            OPC_CheckPredicate, 18, // Predicate_atomic_store_32
/*  6590*/            OPC_Scope, 13, /*->6605*/ // 2 children in Scope
/*  6592*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6594*/              OPC_EmitMergeInputChains1_0,
/*  6595*/              OPC_EmitConvertToTarget, 2,
/*  6597*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 1, 4, 
                        // Src: (atomic_store (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 11
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6605*/            /*Scope*/ 13, /*->6619*/
/*  6606*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  6608*/              OPC_EmitMergeInputChains1_0,
/*  6609*/              OPC_EmitConvertToTarget, 2,
/*  6611*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 3, 1, 4, 
                        // Src: (atomic_store (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 11
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  6619*/            0, /*End of Scope*/
/*  6620*/          0, /*End of Scope*/
/*  6621*/        /*SwitchType*/ 111, MVT::i64,// ->6734
/*  6623*/          OPC_MoveParent,
/*  6624*/          OPC_RecordChild2, // #3 = $rs2
/*  6625*/          OPC_CheckChild2Type, MVT::i64,
/*  6627*/          OPC_Scope, 18, /*->6647*/ // 6 children in Scope
/*  6629*/            OPC_CheckPredicate, 16, // Predicate_atomic_store_8
/*  6631*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6633*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6636*/            OPC_EmitMergeInputChains1_0,
/*  6637*/            OPC_EmitConvertToTarget, 2,
/*  6639*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 3, 4, 5, 
                      // Src: (atomic_store (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 17
                      // Dst: (SB GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  6647*/          /*Scope*/ 18, /*->6666*/
/*  6648*/            OPC_CheckPredicate, 17, // Predicate_atomic_store_16
/*  6650*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6652*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6655*/            OPC_EmitMergeInputChains1_0,
/*  6656*/            OPC_EmitConvertToTarget, 2,
/*  6658*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 3, 4, 5, 
                      // Src: (atomic_store (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 17
                      // Dst: (SH GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  6666*/          /*Scope*/ 18, /*->6685*/
/*  6667*/            OPC_CheckPredicate, 18, // Predicate_atomic_store_32
/*  6669*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6671*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #4
/*  6674*/            OPC_EmitMergeInputChains1_0,
/*  6675*/            OPC_EmitConvertToTarget, 2,
/*  6677*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 3, 4, 5, 
                      // Src: (atomic_store (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 17
                      // Dst: (SW GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  6685*/          /*Scope*/ 15, /*->6701*/
/*  6686*/            OPC_CheckPredicate, 16, // Predicate_atomic_store_8
/*  6688*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6690*/            OPC_EmitMergeInputChains1_0,
/*  6691*/            OPC_EmitConvertToTarget, 2,
/*  6693*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 3, 1, 4, 
                      // Src: (atomic_store (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 11
                      // Dst: (SB GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  6701*/          /*Scope*/ 15, /*->6717*/
/*  6702*/            OPC_CheckPredicate, 17, // Predicate_atomic_store_16
/*  6704*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6706*/            OPC_EmitMergeInputChains1_0,
/*  6707*/            OPC_EmitConvertToTarget, 2,
/*  6709*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 3, 1, 4, 
                      // Src: (atomic_store (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 11
                      // Dst: (SH GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  6717*/          /*Scope*/ 15, /*->6733*/
/*  6718*/            OPC_CheckPredicate, 18, // Predicate_atomic_store_32
/*  6720*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6722*/            OPC_EmitMergeInputChains1_0,
/*  6723*/            OPC_EmitConvertToTarget, 2,
/*  6725*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 3, 1, 4, 
                      // Src: (atomic_store (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12), GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 11
                      // Dst: (SW GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  6733*/          0, /*End of Scope*/
/*  6734*/        0, // EndSwitchType
/*  6735*/      0, // EndSwitchOpcode
/*  6736*/    /*Scope*/ 117|128,2/*373*/, /*->7111*/
/*  6738*/      OPC_RecordChild1, // #1 = $rs1
/*  6739*/      OPC_Scope, 68|128,1/*196*/, /*->6938*/ // 3 children in Scope
/*  6742*/        OPC_RecordChild2, // #2 = $rs2
/*  6743*/        OPC_Scope, 127, /*->6872*/ // 2 children in Scope
/*  6745*/          OPC_CheckChild2Type, MVT::i32,
/*  6747*/          OPC_Scope, 40, /*->6789*/ // 3 children in Scope
/*  6749*/            OPC_CheckPredicate, 16, // Predicate_atomic_store_8
/*  6751*/            OPC_Scope, 17, /*->6770*/ // 2 children in Scope
/*  6753*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6755*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  6758*/              OPC_EmitMergeInputChains1_0,
/*  6759*/              OPC_EmitInteger, MVT::i32, 0, 
/*  6762*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 2, 3, 4, 
                        // Src: (atomic_store AddrFI:{ *:[iPTR] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 10
                        // Dst: (SB GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  6770*/            /*Scope*/ 17, /*->6788*/
/*  6771*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  6773*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  6776*/              OPC_EmitMergeInputChains1_0,
/*  6777*/              OPC_EmitInteger, MVT::i32, 0, 
/*  6780*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 2, 3, 4, 
                        // Src: (atomic_store AddrFI:{ *:[iPTR] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 10
                        // Dst: (SB GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  6788*/            0, /*End of Scope*/
/*  6789*/          /*Scope*/ 40, /*->6830*/
/*  6790*/            OPC_CheckPredicate, 17, // Predicate_atomic_store_16
/*  6792*/            OPC_Scope, 17, /*->6811*/ // 2 children in Scope
/*  6794*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6796*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  6799*/              OPC_EmitMergeInputChains1_0,
/*  6800*/              OPC_EmitInteger, MVT::i32, 0, 
/*  6803*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 2, 3, 4, 
                        // Src: (atomic_store AddrFI:{ *:[iPTR] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 10
                        // Dst: (SH GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  6811*/            /*Scope*/ 17, /*->6829*/
/*  6812*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  6814*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  6817*/              OPC_EmitMergeInputChains1_0,
/*  6818*/              OPC_EmitInteger, MVT::i32, 0, 
/*  6821*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 2, 3, 4, 
                        // Src: (atomic_store AddrFI:{ *:[iPTR] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 10
                        // Dst: (SH GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  6829*/            0, /*End of Scope*/
/*  6830*/          /*Scope*/ 40, /*->6871*/
/*  6831*/            OPC_CheckPredicate, 18, // Predicate_atomic_store_32
/*  6833*/            OPC_Scope, 17, /*->6852*/ // 2 children in Scope
/*  6835*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6837*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  6840*/              OPC_EmitMergeInputChains1_0,
/*  6841*/              OPC_EmitInteger, MVT::i32, 0, 
/*  6844*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 2, 3, 4, 
                        // Src: (atomic_store AddrFI:{ *:[iPTR] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 10
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  6852*/            /*Scope*/ 17, /*->6870*/
/*  6853*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  6855*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  6858*/              OPC_EmitMergeInputChains1_0,
/*  6859*/              OPC_EmitInteger, MVT::i32, 0, 
/*  6862*/              OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                            3/*#Ops*/, 2, 3, 4, 
                        // Src: (atomic_store AddrFI:{ *:[iPTR] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 10
                        // Dst: (SW GPR:{ *:[i32] }:$rs2, AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  6870*/            0, /*End of Scope*/
/*  6871*/          0, /*End of Scope*/
/*  6872*/        /*Scope*/ 64, /*->6937*/
/*  6873*/          OPC_CheckChild2Type, MVT::i64,
/*  6875*/          OPC_Scope, 19, /*->6896*/ // 3 children in Scope
/*  6877*/            OPC_CheckPredicate, 16, // Predicate_atomic_store_8
/*  6879*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6881*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  6884*/            OPC_EmitMergeInputChains1_0,
/*  6885*/            OPC_EmitInteger, MVT::i64, 0, 
/*  6888*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 2, 3, 4, 
                      // Src: (atomic_store AddrFI:{ *:[iPTR] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 10
                      // Dst: (SB GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  6896*/          /*Scope*/ 19, /*->6916*/
/*  6897*/            OPC_CheckPredicate, 17, // Predicate_atomic_store_16
/*  6899*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6901*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  6904*/            OPC_EmitMergeInputChains1_0,
/*  6905*/            OPC_EmitInteger, MVT::i64, 0, 
/*  6908*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 2, 3, 4, 
                      // Src: (atomic_store AddrFI:{ *:[iPTR] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 10
                      // Dst: (SH GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  6916*/          /*Scope*/ 19, /*->6936*/
/*  6917*/            OPC_CheckPredicate, 18, // Predicate_atomic_store_32
/*  6919*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  6921*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  6924*/            OPC_EmitMergeInputChains1_0,
/*  6925*/            OPC_EmitInteger, MVT::i64, 0, 
/*  6928*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 2, 3, 4, 
                      // Src: (atomic_store AddrFI:{ *:[iPTR] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 10
                      // Dst: (SW GPR:{ *:[i64] }:$rs2, AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  6936*/          0, /*End of Scope*/
/*  6937*/        0, /*End of Scope*/
/*  6938*/      /*Scope*/ 112, /*->7051*/
/*  6939*/        OPC_CheckChild1Type, MVT::i32,
/*  6941*/        OPC_RecordChild2, // #2 = $rs2
/*  6942*/        OPC_CheckChild2Type, MVT::i32,
/*  6944*/        OPC_Scope, 34, /*->6980*/ // 3 children in Scope
/*  6946*/          OPC_CheckPredicate, 16, // Predicate_atomic_store_8
/*  6948*/          OPC_Scope, 14, /*->6964*/ // 2 children in Scope
/*  6950*/            OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6952*/            OPC_EmitMergeInputChains1_0,
/*  6953*/            OPC_EmitInteger, MVT::i32, 0, 
/*  6956*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (atomic_store GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 4
                      // Dst: (SB GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  6964*/          /*Scope*/ 14, /*->6979*/
/*  6965*/            OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  6967*/            OPC_EmitMergeInputChains1_0,
/*  6968*/            OPC_EmitInteger, MVT::i32, 0, 
/*  6971*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (atomic_store GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 4
                      // Dst: (SB GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  6979*/          0, /*End of Scope*/
/*  6980*/        /*Scope*/ 34, /*->7015*/
/*  6981*/          OPC_CheckPredicate, 17, // Predicate_atomic_store_16
/*  6983*/          OPC_Scope, 14, /*->6999*/ // 2 children in Scope
/*  6985*/            OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  6987*/            OPC_EmitMergeInputChains1_0,
/*  6988*/            OPC_EmitInteger, MVT::i32, 0, 
/*  6991*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (atomic_store GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 4
                      // Dst: (SH GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  6999*/          /*Scope*/ 14, /*->7014*/
/*  7000*/            OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7002*/            OPC_EmitMergeInputChains1_0,
/*  7003*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7006*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (atomic_store GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 4
                      // Dst: (SH GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7014*/          0, /*End of Scope*/
/*  7015*/        /*Scope*/ 34, /*->7050*/
/*  7016*/          OPC_CheckPredicate, 18, // Predicate_atomic_store_32
/*  7018*/          OPC_Scope, 14, /*->7034*/ // 2 children in Scope
/*  7020*/            OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7022*/            OPC_EmitMergeInputChains1_0,
/*  7023*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7026*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (atomic_store GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 4
                      // Dst: (SW GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7034*/          /*Scope*/ 14, /*->7049*/
/*  7035*/            OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7037*/            OPC_EmitMergeInputChains1_0,
/*  7038*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7041*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (atomic_store GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 4
                      // Dst: (SW GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7049*/          0, /*End of Scope*/
/*  7050*/        0, /*End of Scope*/
/*  7051*/      /*Scope*/ 58, /*->7110*/
/*  7052*/        OPC_CheckChild1Type, MVT::i64,
/*  7054*/        OPC_RecordChild2, // #2 = $rs2
/*  7055*/        OPC_CheckChild2Type, MVT::i64,
/*  7057*/        OPC_Scope, 16, /*->7075*/ // 3 children in Scope
/*  7059*/          OPC_CheckPredicate, 16, // Predicate_atomic_store_8
/*  7061*/          OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7063*/          OPC_EmitMergeInputChains1_0,
/*  7064*/          OPC_EmitInteger, MVT::i64, 0, 
/*  7067*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::SB), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 2, 1, 3, 
                    // Src: (atomic_store GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_8>> - Complexity = 4
                    // Dst: (SB GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  7075*/        /*Scope*/ 16, /*->7092*/
/*  7076*/          OPC_CheckPredicate, 17, // Predicate_atomic_store_16
/*  7078*/          OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7080*/          OPC_EmitMergeInputChains1_0,
/*  7081*/          OPC_EmitInteger, MVT::i64, 0, 
/*  7084*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::SH), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 2, 1, 3, 
                    // Src: (atomic_store GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_16>> - Complexity = 4
                    // Dst: (SH GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  7092*/        /*Scope*/ 16, /*->7109*/
/*  7093*/          OPC_CheckPredicate, 18, // Predicate_atomic_store_32
/*  7095*/          OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7097*/          OPC_EmitMergeInputChains1_0,
/*  7098*/          OPC_EmitInteger, MVT::i64, 0, 
/*  7101*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::SW), 0|OPFL_Chain|OPFL_MemRefs,
                        3/*#Ops*/, 2, 1, 3, 
                    // Src: (atomic_store GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_store_32>> - Complexity = 4
                    // Dst: (SW GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  7109*/        0, /*End of Scope*/
/*  7110*/      0, /*End of Scope*/
/*  7111*/    0, /*End of Scope*/
/*  7112*/  /*SwitchOpcode*/ 36|128,7/*932*/, TARGET_VAL(ISD::ATOMIC_LOAD),// ->8048
/*  7116*/    OPC_RecordMemRef,
/*  7117*/    OPC_RecordNode, // #0 = 'atomic_load' chained node
/*  7118*/    OPC_Scope, 47|128,4/*559*/, /*->7680*/ // 2 children in Scope
/*  7121*/      OPC_MoveChild1,
/*  7122*/      OPC_SwitchOpcode /*2 cases */, 73|128,1/*201*/, TARGET_VAL(ISD::OR),// ->7328
/*  7127*/        OPC_RecordChild0, // #1 = $rs1
/*  7128*/        OPC_RecordChild1, // #2 = $imm12
/*  7129*/        OPC_MoveChild1,
/*  7130*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  7133*/        OPC_CheckPredicate, 0, // Predicate_simm12
/*  7135*/        OPC_MoveParent,
/*  7136*/        OPC_CheckPredicate, 1, // Predicate_IsOrAdd
/*  7138*/        OPC_SwitchType /*2 cases */, 122, MVT::i32,// ->7263
/*  7141*/          OPC_MoveParent,
/*  7142*/          OPC_CheckType, MVT::i32,
/*  7144*/          OPC_Scope, 38, /*->7184*/ // 3 children in Scope
/*  7146*/            OPC_CheckPredicate, 16, // Predicate_atomic_load_8
/*  7148*/            OPC_Scope, 16, /*->7166*/ // 2 children in Scope
/*  7150*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7152*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7155*/              OPC_EmitMergeInputChains1_0,
/*  7156*/              OPC_EmitConvertToTarget, 2,
/*  7158*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (atomic_load:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_atomic_load_8>> - Complexity = 18
                        // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7166*/            /*Scope*/ 16, /*->7183*/
/*  7167*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7169*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7172*/              OPC_EmitMergeInputChains1_0,
/*  7173*/              OPC_EmitConvertToTarget, 2,
/*  7175*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (atomic_load:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_atomic_load_8>> - Complexity = 18
                        // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7183*/            0, /*End of Scope*/
/*  7184*/          /*Scope*/ 38, /*->7223*/
/*  7185*/            OPC_CheckPredicate, 17, // Predicate_atomic_load_16
/*  7187*/            OPC_Scope, 16, /*->7205*/ // 2 children in Scope
/*  7189*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7191*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7194*/              OPC_EmitMergeInputChains1_0,
/*  7195*/              OPC_EmitConvertToTarget, 2,
/*  7197*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (atomic_load:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_atomic_load_16>> - Complexity = 18
                        // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7205*/            /*Scope*/ 16, /*->7222*/
/*  7206*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7208*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7211*/              OPC_EmitMergeInputChains1_0,
/*  7212*/              OPC_EmitConvertToTarget, 2,
/*  7214*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (atomic_load:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_atomic_load_16>> - Complexity = 18
                        // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7222*/            0, /*End of Scope*/
/*  7223*/          /*Scope*/ 38, /*->7262*/
/*  7224*/            OPC_CheckPredicate, 18, // Predicate_atomic_load_32
/*  7226*/            OPC_Scope, 16, /*->7244*/ // 2 children in Scope
/*  7228*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7230*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7233*/              OPC_EmitMergeInputChains1_0,
/*  7234*/              OPC_EmitConvertToTarget, 2,
/*  7236*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (atomic_load:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_atomic_load_32>> - Complexity = 18
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7244*/            /*Scope*/ 16, /*->7261*/
/*  7245*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7247*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7250*/              OPC_EmitMergeInputChains1_0,
/*  7251*/              OPC_EmitConvertToTarget, 2,
/*  7253*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (atomic_load:{ *:[i32] } (or:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_atomic_load_32>> - Complexity = 18
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7261*/            0, /*End of Scope*/
/*  7262*/          0, /*End of Scope*/
/*  7263*/        /*SwitchType*/ 62, MVT::i64,// ->7327
/*  7265*/          OPC_MoveParent,
/*  7266*/          OPC_CheckType, MVT::i64,
/*  7268*/          OPC_Scope, 18, /*->7288*/ // 3 children in Scope
/*  7270*/            OPC_CheckPredicate, 16, // Predicate_atomic_load_8
/*  7272*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7274*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7277*/            OPC_EmitMergeInputChains1_0,
/*  7278*/            OPC_EmitConvertToTarget, 2,
/*  7280*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (atomic_load:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_atomic_load_8>> - Complexity = 18
                      // Dst: (LB:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  7288*/          /*Scope*/ 18, /*->7307*/
/*  7289*/            OPC_CheckPredicate, 17, // Predicate_atomic_load_16
/*  7291*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7293*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7296*/            OPC_EmitMergeInputChains1_0,
/*  7297*/            OPC_EmitConvertToTarget, 2,
/*  7299*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (atomic_load:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_atomic_load_16>> - Complexity = 18
                      // Dst: (LH:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  7307*/          /*Scope*/ 18, /*->7326*/
/*  7308*/            OPC_CheckPredicate, 18, // Predicate_atomic_load_32
/*  7310*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7312*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7315*/            OPC_EmitMergeInputChains1_0,
/*  7316*/            OPC_EmitConvertToTarget, 2,
/*  7318*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (atomic_load:{ *:[i64] } (or:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>>)<<P:Predicate_atomic_load_32>> - Complexity = 18
                      // Dst: (LW:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  7326*/          0, /*End of Scope*/
/*  7327*/        0, // EndSwitchType
/*  7328*/      /*SwitchOpcode*/ 91|128,2/*347*/, TARGET_VAL(ISD::ADD),// ->7679
/*  7332*/        OPC_RecordChild0, // #1 = $rs1
/*  7333*/        OPC_RecordChild1, // #2 = $imm12
/*  7334*/        OPC_MoveChild1,
/*  7335*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  7338*/        OPC_CheckPredicate, 0, // Predicate_simm12
/*  7340*/        OPC_MoveParent,
/*  7341*/        OPC_SwitchType /*2 cases */, 93|128,1/*221*/, MVT::i32,// ->7566
/*  7345*/          OPC_MoveParent,
/*  7346*/          OPC_CheckType, MVT::i32,
/*  7348*/          OPC_Scope, 38, /*->7388*/ // 6 children in Scope
/*  7350*/            OPC_CheckPredicate, 16, // Predicate_atomic_load_8
/*  7352*/            OPC_Scope, 16, /*->7370*/ // 2 children in Scope
/*  7354*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7356*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7359*/              OPC_EmitMergeInputChains1_0,
/*  7360*/              OPC_EmitConvertToTarget, 2,
/*  7362*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (atomic_load:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_8>> - Complexity = 17
                        // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7370*/            /*Scope*/ 16, /*->7387*/
/*  7371*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7373*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7376*/              OPC_EmitMergeInputChains1_0,
/*  7377*/              OPC_EmitConvertToTarget, 2,
/*  7379*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (atomic_load:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_8>> - Complexity = 17
                        // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7387*/            0, /*End of Scope*/
/*  7388*/          /*Scope*/ 38, /*->7427*/
/*  7389*/            OPC_CheckPredicate, 17, // Predicate_atomic_load_16
/*  7391*/            OPC_Scope, 16, /*->7409*/ // 2 children in Scope
/*  7393*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7395*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7398*/              OPC_EmitMergeInputChains1_0,
/*  7399*/              OPC_EmitConvertToTarget, 2,
/*  7401*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (atomic_load:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_16>> - Complexity = 17
                        // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7409*/            /*Scope*/ 16, /*->7426*/
/*  7410*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7412*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7415*/              OPC_EmitMergeInputChains1_0,
/*  7416*/              OPC_EmitConvertToTarget, 2,
/*  7418*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (atomic_load:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_16>> - Complexity = 17
                        // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7426*/            0, /*End of Scope*/
/*  7427*/          /*Scope*/ 38, /*->7466*/
/*  7428*/            OPC_CheckPredicate, 18, // Predicate_atomic_load_32
/*  7430*/            OPC_Scope, 16, /*->7448*/ // 2 children in Scope
/*  7432*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7434*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7437*/              OPC_EmitMergeInputChains1_0,
/*  7438*/              OPC_EmitConvertToTarget, 2,
/*  7440*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (atomic_load:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_32>> - Complexity = 17
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7448*/            /*Scope*/ 16, /*->7465*/
/*  7449*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7451*/              OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7454*/              OPC_EmitMergeInputChains1_0,
/*  7455*/              OPC_EmitConvertToTarget, 2,
/*  7457*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 3, 4, 
                        // Src: (atomic_load:{ *:[i32] } (add:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_32>> - Complexity = 17
                        // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7465*/            0, /*End of Scope*/
/*  7466*/          /*Scope*/ 32, /*->7499*/
/*  7467*/            OPC_CheckPredicate, 16, // Predicate_atomic_load_8
/*  7469*/            OPC_Scope, 13, /*->7484*/ // 2 children in Scope
/*  7471*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7473*/              OPC_EmitMergeInputChains1_0,
/*  7474*/              OPC_EmitConvertToTarget, 2,
/*  7476*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (atomic_load:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_8>> - Complexity = 11
                        // Dst: (LB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7484*/            /*Scope*/ 13, /*->7498*/
/*  7485*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7487*/              OPC_EmitMergeInputChains1_0,
/*  7488*/              OPC_EmitConvertToTarget, 2,
/*  7490*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (atomic_load:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_8>> - Complexity = 11
                        // Dst: (LB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7498*/            0, /*End of Scope*/
/*  7499*/          /*Scope*/ 32, /*->7532*/
/*  7500*/            OPC_CheckPredicate, 17, // Predicate_atomic_load_16
/*  7502*/            OPC_Scope, 13, /*->7517*/ // 2 children in Scope
/*  7504*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7506*/              OPC_EmitMergeInputChains1_0,
/*  7507*/              OPC_EmitConvertToTarget, 2,
/*  7509*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (atomic_load:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_16>> - Complexity = 11
                        // Dst: (LH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7517*/            /*Scope*/ 13, /*->7531*/
/*  7518*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7520*/              OPC_EmitMergeInputChains1_0,
/*  7521*/              OPC_EmitConvertToTarget, 2,
/*  7523*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (atomic_load:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_16>> - Complexity = 11
                        // Dst: (LH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7531*/            0, /*End of Scope*/
/*  7532*/          /*Scope*/ 32, /*->7565*/
/*  7533*/            OPC_CheckPredicate, 18, // Predicate_atomic_load_32
/*  7535*/            OPC_Scope, 13, /*->7550*/ // 2 children in Scope
/*  7537*/              OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7539*/              OPC_EmitMergeInputChains1_0,
/*  7540*/              OPC_EmitConvertToTarget, 2,
/*  7542*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (atomic_load:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_32>> - Complexity = 11
                        // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7550*/            /*Scope*/ 13, /*->7564*/
/*  7551*/              OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7553*/              OPC_EmitMergeInputChains1_0,
/*  7554*/              OPC_EmitConvertToTarget, 2,
/*  7556*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                            MVT::i32, 2/*#Ops*/, 1, 3, 
                        // Src: (atomic_load:{ *:[i32] } (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_32>> - Complexity = 11
                        // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  7564*/            0, /*End of Scope*/
/*  7565*/          0, /*End of Scope*/
/*  7566*/        /*SwitchType*/ 110, MVT::i64,// ->7678
/*  7568*/          OPC_MoveParent,
/*  7569*/          OPC_CheckType, MVT::i64,
/*  7571*/          OPC_Scope, 18, /*->7591*/ // 6 children in Scope
/*  7573*/            OPC_CheckPredicate, 16, // Predicate_atomic_load_8
/*  7575*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7577*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7580*/            OPC_EmitMergeInputChains1_0,
/*  7581*/            OPC_EmitConvertToTarget, 2,
/*  7583*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (atomic_load:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_8>> - Complexity = 17
                      // Dst: (LB:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  7591*/          /*Scope*/ 18, /*->7610*/
/*  7592*/            OPC_CheckPredicate, 17, // Predicate_atomic_load_16
/*  7594*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7596*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7599*/            OPC_EmitMergeInputChains1_0,
/*  7600*/            OPC_EmitConvertToTarget, 2,
/*  7602*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (atomic_load:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_16>> - Complexity = 17
                      // Dst: (LH:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  7610*/          /*Scope*/ 18, /*->7629*/
/*  7611*/            OPC_CheckPredicate, 18, // Predicate_atomic_load_32
/*  7613*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7615*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #3
/*  7618*/            OPC_EmitMergeInputChains1_0,
/*  7619*/            OPC_EmitConvertToTarget, 2,
/*  7621*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 3, 4, 
                      // Src: (atomic_load:{ *:[i64] } (add:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_32>> - Complexity = 17
                      // Dst: (LW:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  7629*/          /*Scope*/ 15, /*->7645*/
/*  7630*/            OPC_CheckPredicate, 16, // Predicate_atomic_load_8
/*  7632*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7634*/            OPC_EmitMergeInputChains1_0,
/*  7635*/            OPC_EmitConvertToTarget, 2,
/*  7637*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 3, 
                      // Src: (atomic_load:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_8>> - Complexity = 11
                      // Dst: (LB:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  7645*/          /*Scope*/ 15, /*->7661*/
/*  7646*/            OPC_CheckPredicate, 17, // Predicate_atomic_load_16
/*  7648*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7650*/            OPC_EmitMergeInputChains1_0,
/*  7651*/            OPC_EmitConvertToTarget, 2,
/*  7653*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 3, 
                      // Src: (atomic_load:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_16>> - Complexity = 11
                      // Dst: (LH:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  7661*/          /*Scope*/ 15, /*->7677*/
/*  7662*/            OPC_CheckPredicate, 18, // Predicate_atomic_load_32
/*  7664*/            OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7666*/            OPC_EmitMergeInputChains1_0,
/*  7667*/            OPC_EmitConvertToTarget, 2,
/*  7669*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i64, 2/*#Ops*/, 1, 3, 
                      // Src: (atomic_load:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12))<<P:Predicate_atomic_load_32>> - Complexity = 11
                      // Dst: (LW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  7677*/          0, /*End of Scope*/
/*  7678*/        0, // EndSwitchType
/*  7679*/      0, // EndSwitchOpcode
/*  7680*/    /*Scope*/ 109|128,2/*365*/, /*->8047*/
/*  7682*/      OPC_RecordChild1, // #1 = $rs1
/*  7683*/      OPC_Scope, 63, /*->7748*/ // 5 children in Scope
/*  7685*/        OPC_CheckPredicate, 16, // Predicate_atomic_load_8
/*  7687*/        OPC_SwitchType /*2 cases */, 38, MVT::i32,// ->7728
/*  7690*/          OPC_Scope, 17, /*->7709*/ // 2 children in Scope
/*  7692*/            OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7694*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  7697*/            OPC_EmitMergeInputChains1_0,
/*  7698*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7701*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (atomic_load:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_atomic_load_8>> - Complexity = 10
                      // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7709*/          /*Scope*/ 17, /*->7727*/
/*  7710*/            OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7712*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  7715*/            OPC_EmitMergeInputChains1_0,
/*  7716*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7719*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (atomic_load:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_atomic_load_8>> - Complexity = 10
                      // Dst: (LB:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7727*/          0, /*End of Scope*/
/*  7728*/        /*SwitchType*/ 17, MVT::i64,// ->7747
/*  7730*/          OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7732*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  7735*/          OPC_EmitMergeInputChains1_0,
/*  7736*/          OPC_EmitInteger, MVT::i64, 0, 
/*  7739*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 2, 3, 
                    // Src: (atomic_load:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_atomic_load_8>> - Complexity = 10
                    // Dst: (LB:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  7747*/        0, // EndSwitchType
/*  7748*/      /*Scope*/ 63, /*->7812*/
/*  7749*/        OPC_CheckPredicate, 17, // Predicate_atomic_load_16
/*  7751*/        OPC_SwitchType /*2 cases */, 38, MVT::i32,// ->7792
/*  7754*/          OPC_Scope, 17, /*->7773*/ // 2 children in Scope
/*  7756*/            OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7758*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  7761*/            OPC_EmitMergeInputChains1_0,
/*  7762*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7765*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (atomic_load:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_atomic_load_16>> - Complexity = 10
                      // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7773*/          /*Scope*/ 17, /*->7791*/
/*  7774*/            OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7776*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  7779*/            OPC_EmitMergeInputChains1_0,
/*  7780*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7783*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (atomic_load:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_atomic_load_16>> - Complexity = 10
                      // Dst: (LH:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7791*/          0, /*End of Scope*/
/*  7792*/        /*SwitchType*/ 17, MVT::i64,// ->7811
/*  7794*/          OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7796*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  7799*/          OPC_EmitMergeInputChains1_0,
/*  7800*/          OPC_EmitInteger, MVT::i64, 0, 
/*  7803*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 2, 3, 
                    // Src: (atomic_load:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_atomic_load_16>> - Complexity = 10
                    // Dst: (LH:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  7811*/        0, // EndSwitchType
/*  7812*/      /*Scope*/ 63, /*->7876*/
/*  7813*/        OPC_CheckPredicate, 18, // Predicate_atomic_load_32
/*  7815*/        OPC_SwitchType /*2 cases */, 38, MVT::i32,// ->7856
/*  7818*/          OPC_Scope, 17, /*->7837*/ // 2 children in Scope
/*  7820*/            OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7822*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  7825*/            OPC_EmitMergeInputChains1_0,
/*  7826*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7829*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (atomic_load:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_atomic_load_32>> - Complexity = 10
                      // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7837*/          /*Scope*/ 17, /*->7855*/
/*  7838*/            OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7840*/            OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  7843*/            OPC_EmitMergeInputChains1_0,
/*  7844*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7847*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (atomic_load:{ *:[i32] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_atomic_load_32>> - Complexity = 10
                      // Dst: (LW:{ *:[i32] } AddrFI:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7855*/          0, /*End of Scope*/
/*  7856*/        /*SwitchType*/ 17, MVT::i64,// ->7875
/*  7858*/          OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7860*/          OPC_CheckComplexPat, /*CP*/0, /*#*/1, // SelectAddrFI:$rs1 #2
/*  7863*/          OPC_EmitMergeInputChains1_0,
/*  7864*/          OPC_EmitInteger, MVT::i64, 0, 
/*  7867*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 2, 3, 
                    // Src: (atomic_load:{ *:[i64] } AddrFI:{ *:[iPTR] }:$rs1)<<P:Predicate_atomic_load_32>> - Complexity = 10
                    // Dst: (LW:{ *:[i64] } AddrFI:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  7875*/        0, // EndSwitchType
/*  7876*/      /*Scope*/ 111, /*->7988*/
/*  7877*/        OPC_CheckChild1Type, MVT::i32,
/*  7879*/        OPC_CheckType, MVT::i32,
/*  7881*/        OPC_Scope, 34, /*->7917*/ // 3 children in Scope
/*  7883*/          OPC_CheckPredicate, 16, // Predicate_atomic_load_8
/*  7885*/          OPC_Scope, 14, /*->7901*/ // 2 children in Scope
/*  7887*/            OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7889*/            OPC_EmitMergeInputChains1_0,
/*  7890*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7893*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (atomic_load:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_atomic_load_8>> - Complexity = 4
                      // Dst: (LB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7901*/          /*Scope*/ 14, /*->7916*/
/*  7902*/            OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7904*/            OPC_EmitMergeInputChains1_0,
/*  7905*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7908*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (atomic_load:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_atomic_load_8>> - Complexity = 4
                      // Dst: (LB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7916*/          0, /*End of Scope*/
/*  7917*/        /*Scope*/ 34, /*->7952*/
/*  7918*/          OPC_CheckPredicate, 17, // Predicate_atomic_load_16
/*  7920*/          OPC_Scope, 14, /*->7936*/ // 2 children in Scope
/*  7922*/            OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7924*/            OPC_EmitMergeInputChains1_0,
/*  7925*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7928*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (atomic_load:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_atomic_load_16>> - Complexity = 4
                      // Dst: (LH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7936*/          /*Scope*/ 14, /*->7951*/
/*  7937*/            OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7939*/            OPC_EmitMergeInputChains1_0,
/*  7940*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7943*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (atomic_load:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_atomic_load_16>> - Complexity = 4
                      // Dst: (LH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7951*/          0, /*End of Scope*/
/*  7952*/        /*Scope*/ 34, /*->7987*/
/*  7953*/          OPC_CheckPredicate, 18, // Predicate_atomic_load_32
/*  7955*/          OPC_Scope, 14, /*->7971*/ // 2 children in Scope
/*  7957*/            OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  7959*/            OPC_EmitMergeInputChains1_0,
/*  7960*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7963*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (atomic_load:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_atomic_load_32>> - Complexity = 4
                      // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7971*/          /*Scope*/ 14, /*->7986*/
/*  7972*/            OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  7974*/            OPC_EmitMergeInputChains1_0,
/*  7975*/            OPC_EmitInteger, MVT::i32, 0, 
/*  7978*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                          MVT::i32, 2/*#Ops*/, 1, 2, 
                      // Src: (atomic_load:{ *:[i32] } GPR:{ *:[i32] }:$rs1)<<P:Predicate_atomic_load_32>> - Complexity = 4
                      // Dst: (LW:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  7986*/          0, /*End of Scope*/
/*  7987*/        0, /*End of Scope*/
/*  7988*/      /*Scope*/ 57, /*->8046*/
/*  7989*/        OPC_CheckChild1Type, MVT::i64,
/*  7991*/        OPC_CheckType, MVT::i64,
/*  7993*/        OPC_Scope, 16, /*->8011*/ // 3 children in Scope
/*  7995*/          OPC_CheckPredicate, 16, // Predicate_atomic_load_8
/*  7997*/          OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  7999*/          OPC_EmitMergeInputChains1_0,
/*  8000*/          OPC_EmitInteger, MVT::i64, 0, 
/*  8003*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LB), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_atomic_load_8>> - Complexity = 4
                    // Dst: (LB:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  8011*/        /*Scope*/ 16, /*->8028*/
/*  8012*/          OPC_CheckPredicate, 17, // Predicate_atomic_load_16
/*  8014*/          OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  8016*/          OPC_EmitMergeInputChains1_0,
/*  8017*/          OPC_EmitInteger, MVT::i64, 0, 
/*  8020*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LH), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_atomic_load_16>> - Complexity = 4
                    // Dst: (LH:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  8028*/        /*Scope*/ 16, /*->8045*/
/*  8029*/          OPC_CheckPredicate, 18, // Predicate_atomic_load_32
/*  8031*/          OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  8033*/          OPC_EmitMergeInputChains1_0,
/*  8034*/          OPC_EmitInteger, MVT::i64, 0, 
/*  8037*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LW), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i64, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load:{ *:[i64] } GPR:{ *:[i64] }:$rs1)<<P:Predicate_atomic_load_32>> - Complexity = 4
                    // Dst: (LW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  8045*/        0, /*End of Scope*/
/*  8046*/      0, /*End of Scope*/
/*  8047*/    0, /*End of Scope*/
/*  8048*/  /*SwitchOpcode*/ 1|128,1/*129*/, TARGET_VAL(ISD::OR),// ->8181
/*  8052*/    OPC_RecordChild0, // #0 = $Rs
/*  8053*/    OPC_RecordChild1, // #1 = $imm12
/*  8054*/    OPC_Scope, 86, /*->8142*/ // 3 children in Scope
/*  8056*/      OPC_MoveChild1,
/*  8057*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8060*/      OPC_CheckPredicate, 0, // Predicate_simm12
/*  8062*/      OPC_MoveParent,
/*  8063*/      OPC_SwitchType /*2 cases */, 61, MVT::i32,// ->8127
/*  8066*/        OPC_Scope, 34, /*->8102*/ // 3 children in Scope
/*  8068*/          OPC_CheckPredicate, 1, // Predicate_IsOrAdd
/*  8070*/          OPC_Scope, 15, /*->8087*/ // 2 children in Scope
/*  8072*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  8074*/            OPC_CheckComplexPat, /*CP*/0, /*#*/0, // SelectAddrFI:$Rs #2
/*  8077*/            OPC_EmitConvertToTarget, 1,
/*  8079*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDI), 0,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (or:{ *:[i32] } AddrFI:{ *:[i32] }:$Rs, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>> - Complexity = 14
                      // Dst: (ADDI:{ *:[i32] } AddrFI:{ *:[i32] }:$Rs, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  8087*/          /*Scope*/ 13, /*->8101*/
/*  8088*/            OPC_CheckComplexPat, /*CP*/0, /*#*/0, // SelectAddrFI:$Rs #2
/*  8091*/            OPC_EmitConvertToTarget, 1,
/*  8093*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDI), 0,
                          MVT::i32, 2/*#Ops*/, 2, 3, 
                      // Src: (or:{ *:[i32] } AddrFI:{ *:[i32] }:$Rs, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)<<P:Predicate_IsOrAdd>> - Complexity = 14
                      // Dst: (ADDI:{ *:[i32] } AddrFI:{ *:[i32] }:$Rs, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  8101*/          0, /*End of Scope*/
/*  8102*/        /*Scope*/ 12, /*->8115*/
/*  8103*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  8105*/          OPC_EmitConvertToTarget, 1,
/*  8107*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::ORI), 0,
                        MVT::i32, 2/*#Ops*/, 0, 2, 
                    // Src: (or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12) - Complexity = 7
                    // Dst: (ORI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  8115*/        /*Scope*/ 10, /*->8126*/
/*  8116*/          OPC_EmitConvertToTarget, 1,
/*  8118*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::ORI), 0,
                        MVT::i32, 2/*#Ops*/, 0, 2, 
                    // Src: (or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12) - Complexity = 7
                    // Dst: (ORI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  8126*/        0, /*End of Scope*/
/*  8127*/      /*SwitchType*/ 12, MVT::i64,// ->8141
/*  8129*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  8131*/        OPC_EmitConvertToTarget, 1,
/*  8133*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::ORI), 0,
                      MVT::i64, 2/*#Ops*/, 0, 2, 
                  // Src: (or:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12) - Complexity = 7
                  // Dst: (ORI:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  8141*/      0, // EndSwitchType
/*  8142*/    /*Scope*/ 24, /*->8167*/
/*  8143*/      OPC_CheckType, MVT::i32,
/*  8145*/      OPC_Scope, 10, /*->8157*/ // 2 children in Scope
/*  8147*/        OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  8149*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::OR), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (OR:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  8157*/      /*Scope*/ 8, /*->8166*/
/*  8158*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::OR), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (OR:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  8166*/      0, /*End of Scope*/
/*  8167*/    /*Scope*/ 12, /*->8180*/
/*  8168*/      OPC_CheckType, MVT::i64,
/*  8170*/      OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  8172*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::OR), 0,
                    MVT::i64, 2/*#Ops*/, 0, 1, 
                // Src: (or:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                // Dst: (OR:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/*  8180*/    0, /*End of Scope*/
/*  8181*/  /*SwitchOpcode*/ 124, TARGET_VAL(ISD::ADD),// ->8308
/*  8184*/    OPC_RecordChild0, // #0 = $Rs
/*  8185*/    OPC_RecordChild1, // #1 = $imm12
/*  8186*/    OPC_Scope, 81, /*->8269*/ // 3 children in Scope
/*  8188*/      OPC_MoveChild1,
/*  8189*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8192*/      OPC_CheckPredicate, 0, // Predicate_simm12
/*  8194*/      OPC_MoveParent,
/*  8195*/      OPC_SwitchType /*2 cases */, 56, MVT::i32,// ->8254
/*  8198*/        OPC_Scope, 15, /*->8215*/ // 4 children in Scope
/*  8200*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  8202*/          OPC_CheckComplexPat, /*CP*/0, /*#*/0, // SelectAddrFI:$Rs #2
/*  8205*/          OPC_EmitConvertToTarget, 1,
/*  8207*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDI), 0,
                        MVT::i32, 2/*#Ops*/, 2, 3, 
                    // Src: (add:{ *:[i32] } AddrFI:{ *:[i32] }:$Rs, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12) - Complexity = 13
                    // Dst: (ADDI:{ *:[i32] } AddrFI:{ *:[i32] }:$Rs, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  8215*/        /*Scope*/ 13, /*->8229*/
/*  8216*/          OPC_CheckComplexPat, /*CP*/0, /*#*/0, // SelectAddrFI:$Rs #2
/*  8219*/          OPC_EmitConvertToTarget, 1,
/*  8221*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDI), 0,
                        MVT::i32, 2/*#Ops*/, 2, 3, 
                    // Src: (add:{ *:[i32] } AddrFI:{ *:[i32] }:$Rs, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12) - Complexity = 13
                    // Dst: (ADDI:{ *:[i32] } AddrFI:{ *:[i32] }:$Rs, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  8229*/        /*Scope*/ 12, /*->8242*/
/*  8230*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  8232*/          OPC_EmitConvertToTarget, 1,
/*  8234*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDI), 0,
                        MVT::i32, 2/*#Ops*/, 0, 2, 
                    // Src: (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12) - Complexity = 7
                    // Dst: (ADDI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  8242*/        /*Scope*/ 10, /*->8253*/
/*  8243*/          OPC_EmitConvertToTarget, 1,
/*  8245*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDI), 0,
                        MVT::i32, 2/*#Ops*/, 0, 2, 
                    // Src: (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12) - Complexity = 7
                    // Dst: (ADDI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  8253*/        0, /*End of Scope*/
/*  8254*/      /*SwitchType*/ 12, MVT::i64,// ->8268
/*  8256*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  8258*/        OPC_EmitConvertToTarget, 1,
/*  8260*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDI), 0,
                      MVT::i64, 2/*#Ops*/, 0, 2, 
                  // Src: (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12) - Complexity = 7
                  // Dst: (ADDI:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  8268*/      0, // EndSwitchType
/*  8269*/    /*Scope*/ 24, /*->8294*/
/*  8270*/      OPC_CheckType, MVT::i32,
/*  8272*/      OPC_Scope, 10, /*->8284*/ // 2 children in Scope
/*  8274*/        OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  8276*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADD), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (ADD:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  8284*/      /*Scope*/ 8, /*->8293*/
/*  8285*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADD), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (ADD:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  8293*/      0, /*End of Scope*/
/*  8294*/    /*Scope*/ 12, /*->8307*/
/*  8295*/      OPC_CheckType, MVT::i64,
/*  8297*/      OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  8299*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADD), 0,
                    MVT::i64, 2/*#Ops*/, 0, 1, 
                // Src: (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                // Dst: (ADD:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/*  8307*/    0, /*End of Scope*/
/*  8308*/  /*SwitchOpcode*/ 7|128,2/*263*/, TARGET_VAL(ISD::ATOMIC_FENCE),// ->8575
/*  8312*/    OPC_RecordNode, // #0 = 'atomic_fence' chained node
/*  8313*/    OPC_Scope, 70, /*->8385*/ // 4 children in Scope
/*  8315*/      OPC_CheckChild1Integer, 4, 
/*  8317*/      OPC_Scope, 41, /*->8360*/ // 2 children in Scope
/*  8319*/        OPC_CheckChild1Type, MVT::i32,
/*  8321*/        OPC_MoveChild2,
/*  8322*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8325*/        OPC_MoveParent,
/*  8326*/        OPC_Scope, 16, /*->8344*/ // 2 children in Scope
/*  8328*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  8330*/          OPC_EmitMergeInputChains1_0,
/*  8331*/          OPC_EmitInteger, MVT::i32, 2, 
/*  8334*/          OPC_EmitInteger, MVT::i32, 3, 
/*  8337*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FENCE), 0|OPFL_Chain,
                        2/*#Ops*/, 1, 2, 
                    // Src: (atomic_fence 4:{ *:[i32] }, (imm:{ *:[i32] })) - Complexity = 11
                    // Dst: (FENCE 2:{ *:[i32] }, 3:{ *:[i32] })
/*  8344*/        /*Scope*/ 14, /*->8359*/
/*  8345*/          OPC_EmitMergeInputChains1_0,
/*  8346*/          OPC_EmitInteger, MVT::i32, 2, 
/*  8349*/          OPC_EmitInteger, MVT::i32, 3, 
/*  8352*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FENCE), 0|OPFL_Chain,
                        2/*#Ops*/, 1, 2, 
                    // Src: (atomic_fence 4:{ *:[i32] }, (imm:{ *:[i32] })) - Complexity = 11
                    // Dst: (FENCE 2:{ *:[i32] }, 3:{ *:[i32] })
/*  8359*/        0, /*End of Scope*/
/*  8360*/      /*Scope*/ 23, /*->8384*/
/*  8361*/        OPC_CheckChild1Type, MVT::i64,
/*  8363*/        OPC_MoveChild2,
/*  8364*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8367*/        OPC_MoveParent,
/*  8368*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  8370*/        OPC_EmitMergeInputChains1_0,
/*  8371*/        OPC_EmitInteger, MVT::i64, 2, 
/*  8374*/        OPC_EmitInteger, MVT::i64, 3, 
/*  8377*/        OPC_MorphNodeTo0, TARGET_VAL(RISCV::FENCE), 0|OPFL_Chain,
                      2/*#Ops*/, 1, 2, 
                  // Src: (atomic_fence 4:{ *:[i64] }, (imm:{ *:[i64] })) - Complexity = 11
                  // Dst: (FENCE 2:{ *:[i64] }, 3:{ *:[i64] })
/*  8384*/      0, /*End of Scope*/
/*  8385*/    /*Scope*/ 70, /*->8456*/
/*  8386*/      OPC_CheckChild1Integer, 5, 
/*  8388*/      OPC_Scope, 41, /*->8431*/ // 2 children in Scope
/*  8390*/        OPC_CheckChild1Type, MVT::i32,
/*  8392*/        OPC_MoveChild2,
/*  8393*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8396*/        OPC_MoveParent,
/*  8397*/        OPC_Scope, 16, /*->8415*/ // 2 children in Scope
/*  8399*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  8401*/          OPC_EmitMergeInputChains1_0,
/*  8402*/          OPC_EmitInteger, MVT::i32, 3, 
/*  8405*/          OPC_EmitInteger, MVT::i32, 1, 
/*  8408*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FENCE), 0|OPFL_Chain,
                        2/*#Ops*/, 1, 2, 
                    // Src: (atomic_fence 5:{ *:[i32] }, (imm:{ *:[i32] })) - Complexity = 11
                    // Dst: (FENCE 3:{ *:[i32] }, 1:{ *:[i32] })
/*  8415*/        /*Scope*/ 14, /*->8430*/
/*  8416*/          OPC_EmitMergeInputChains1_0,
/*  8417*/          OPC_EmitInteger, MVT::i32, 3, 
/*  8420*/          OPC_EmitInteger, MVT::i32, 1, 
/*  8423*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FENCE), 0|OPFL_Chain,
                        2/*#Ops*/, 1, 2, 
                    // Src: (atomic_fence 5:{ *:[i32] }, (imm:{ *:[i32] })) - Complexity = 11
                    // Dst: (FENCE 3:{ *:[i32] }, 1:{ *:[i32] })
/*  8430*/        0, /*End of Scope*/
/*  8431*/      /*Scope*/ 23, /*->8455*/
/*  8432*/        OPC_CheckChild1Type, MVT::i64,
/*  8434*/        OPC_MoveChild2,
/*  8435*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8438*/        OPC_MoveParent,
/*  8439*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  8441*/        OPC_EmitMergeInputChains1_0,
/*  8442*/        OPC_EmitInteger, MVT::i64, 3, 
/*  8445*/        OPC_EmitInteger, MVT::i64, 1, 
/*  8448*/        OPC_MorphNodeTo0, TARGET_VAL(RISCV::FENCE), 0|OPFL_Chain,
                      2/*#Ops*/, 1, 2, 
                  // Src: (atomic_fence 5:{ *:[i64] }, (imm:{ *:[i64] })) - Complexity = 11
                  // Dst: (FENCE 3:{ *:[i64] }, 1:{ *:[i64] })
/*  8455*/      0, /*End of Scope*/
/*  8456*/    /*Scope*/ 46, /*->8503*/
/*  8457*/      OPC_CheckChild1Integer, 6, 
/*  8459*/      OPC_Scope, 25, /*->8486*/ // 2 children in Scope
/*  8461*/        OPC_CheckChild1Type, MVT::i32,
/*  8463*/        OPC_MoveChild2,
/*  8464*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8467*/        OPC_MoveParent,
/*  8468*/        OPC_Scope, 8, /*->8478*/ // 2 children in Scope
/*  8470*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  8472*/          OPC_EmitMergeInputChains1_0,
/*  8473*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FENCE_TSO), 0|OPFL_Chain,
                        0/*#Ops*/, 
                    // Src: (atomic_fence 6:{ *:[i32] }, (imm:{ *:[i32] })) - Complexity = 11
                    // Dst: (FENCE_TSO)
/*  8478*/        /*Scope*/ 6, /*->8485*/
/*  8479*/          OPC_EmitMergeInputChains1_0,
/*  8480*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FENCE_TSO), 0|OPFL_Chain,
                        0/*#Ops*/, 
                    // Src: (atomic_fence 6:{ *:[i32] }, (imm:{ *:[i32] })) - Complexity = 11
                    // Dst: (FENCE_TSO)
/*  8485*/        0, /*End of Scope*/
/*  8486*/      /*Scope*/ 15, /*->8502*/
/*  8487*/        OPC_CheckChild1Type, MVT::i64,
/*  8489*/        OPC_MoveChild2,
/*  8490*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8493*/        OPC_MoveParent,
/*  8494*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  8496*/        OPC_EmitMergeInputChains1_0,
/*  8497*/        OPC_MorphNodeTo0, TARGET_VAL(RISCV::FENCE_TSO), 0|OPFL_Chain,
                      0/*#Ops*/, 
                  // Src: (atomic_fence 6:{ *:[i64] }, (imm:{ *:[i64] })) - Complexity = 11
                  // Dst: (FENCE_TSO)
/*  8502*/      0, /*End of Scope*/
/*  8503*/    /*Scope*/ 70, /*->8574*/
/*  8504*/      OPC_CheckChild1Integer, 7, 
/*  8506*/      OPC_Scope, 41, /*->8549*/ // 2 children in Scope
/*  8508*/        OPC_CheckChild1Type, MVT::i32,
/*  8510*/        OPC_MoveChild2,
/*  8511*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8514*/        OPC_MoveParent,
/*  8515*/        OPC_Scope, 16, /*->8533*/ // 2 children in Scope
/*  8517*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  8519*/          OPC_EmitMergeInputChains1_0,
/*  8520*/          OPC_EmitInteger, MVT::i32, 3, 
/*  8523*/          OPC_EmitInteger, MVT::i32, 3, 
/*  8526*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FENCE), 0|OPFL_Chain,
                        2/*#Ops*/, 1, 2, 
                    // Src: (atomic_fence 7:{ *:[i32] }, (imm:{ *:[i32] })) - Complexity = 11
                    // Dst: (FENCE 3:{ *:[i32] }, 3:{ *:[i32] })
/*  8533*/        /*Scope*/ 14, /*->8548*/
/*  8534*/          OPC_EmitMergeInputChains1_0,
/*  8535*/          OPC_EmitInteger, MVT::i32, 3, 
/*  8538*/          OPC_EmitInteger, MVT::i32, 3, 
/*  8541*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::FENCE), 0|OPFL_Chain,
                        2/*#Ops*/, 1, 2, 
                    // Src: (atomic_fence 7:{ *:[i32] }, (imm:{ *:[i32] })) - Complexity = 11
                    // Dst: (FENCE 3:{ *:[i32] }, 3:{ *:[i32] })
/*  8548*/        0, /*End of Scope*/
/*  8549*/      /*Scope*/ 23, /*->8573*/
/*  8550*/        OPC_CheckChild1Type, MVT::i64,
/*  8552*/        OPC_MoveChild2,
/*  8553*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8556*/        OPC_MoveParent,
/*  8557*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  8559*/        OPC_EmitMergeInputChains1_0,
/*  8560*/        OPC_EmitInteger, MVT::i64, 3, 
/*  8563*/        OPC_EmitInteger, MVT::i64, 3, 
/*  8566*/        OPC_MorphNodeTo0, TARGET_VAL(RISCV::FENCE), 0|OPFL_Chain,
                      2/*#Ops*/, 1, 2, 
                  // Src: (atomic_fence 7:{ *:[i64] }, (imm:{ *:[i64] })) - Complexity = 11
                  // Dst: (FENCE 3:{ *:[i64] }, 3:{ *:[i64] })
/*  8573*/      0, /*End of Scope*/
/*  8574*/    0, /*End of Scope*/
/*  8575*/  /*SwitchOpcode*/ 103|128,3/*487*/, TARGET_VAL(ISD::INTRINSIC_W_CHAIN),// ->9066
/*  8579*/    OPC_RecordNode, // #0 = 'intrinsic_w_chain' chained node
/*  8580*/    OPC_Scope, 50, /*->8632*/ // 9 children in Scope
/*  8582*/      OPC_CheckChild1Integer, 57|128,41/*5305*/, 
/*  8585*/      OPC_RecordChild2, // #1 = $addr
/*  8586*/      OPC_CheckChild2Type, MVT::i32,
/*  8588*/      OPC_RecordChild3, // #2 = $incr
/*  8589*/      OPC_RecordChild4, // #3 = $mask
/*  8590*/      OPC_RecordChild5, // #4 = $ordering
/*  8591*/      OPC_MoveChild5,
/*  8592*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8595*/      OPC_MoveParent,
/*  8596*/      OPC_Scope, 16, /*->8614*/ // 2 children in Scope
/*  8598*/        OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  8600*/        OPC_EmitMergeInputChains1_0,
/*  8601*/        OPC_EmitConvertToTarget, 4,
/*  8603*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoMaskedAtomicSwap32), 0|OPFL_Chain,
                      MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 5, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5305:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicSwap32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  8614*/      /*Scope*/ 16, /*->8631*/
/*  8615*/        OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  8617*/        OPC_EmitMergeInputChains1_0,
/*  8618*/        OPC_EmitConvertToTarget, 4,
/*  8620*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoMaskedAtomicSwap32), 0|OPFL_Chain,
                      MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 5, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5305:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicSwap32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  8631*/      0, /*End of Scope*/
/*  8632*/    /*Scope*/ 50, /*->8683*/
/*  8633*/      OPC_CheckChild1Integer, 50|128,41/*5298*/, 
/*  8636*/      OPC_RecordChild2, // #1 = $addr
/*  8637*/      OPC_CheckChild2Type, MVT::i32,
/*  8639*/      OPC_RecordChild3, // #2 = $incr
/*  8640*/      OPC_RecordChild4, // #3 = $mask
/*  8641*/      OPC_RecordChild5, // #4 = $ordering
/*  8642*/      OPC_MoveChild5,
/*  8643*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8646*/      OPC_MoveParent,
/*  8647*/      OPC_Scope, 16, /*->8665*/ // 2 children in Scope
/*  8649*/        OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  8651*/        OPC_EmitMergeInputChains1_0,
/*  8652*/        OPC_EmitConvertToTarget, 4,
/*  8654*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadAdd32), 0|OPFL_Chain,
                      MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 5, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5298:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadAdd32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  8665*/      /*Scope*/ 16, /*->8682*/
/*  8666*/        OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  8668*/        OPC_EmitMergeInputChains1_0,
/*  8669*/        OPC_EmitConvertToTarget, 4,
/*  8671*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadAdd32), 0|OPFL_Chain,
                      MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 5, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5298:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadAdd32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  8682*/      0, /*End of Scope*/
/*  8683*/    /*Scope*/ 50, /*->8734*/
/*  8684*/      OPC_CheckChild1Integer, 54|128,41/*5302*/, 
/*  8687*/      OPC_RecordChild2, // #1 = $addr
/*  8688*/      OPC_CheckChild2Type, MVT::i32,
/*  8690*/      OPC_RecordChild3, // #2 = $incr
/*  8691*/      OPC_RecordChild4, // #3 = $mask
/*  8692*/      OPC_RecordChild5, // #4 = $ordering
/*  8693*/      OPC_MoveChild5,
/*  8694*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8697*/      OPC_MoveParent,
/*  8698*/      OPC_Scope, 16, /*->8716*/ // 2 children in Scope
/*  8700*/        OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  8702*/        OPC_EmitMergeInputChains1_0,
/*  8703*/        OPC_EmitConvertToTarget, 4,
/*  8705*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadSub32), 0|OPFL_Chain,
                      MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 5, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5302:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadSub32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  8716*/      /*Scope*/ 16, /*->8733*/
/*  8717*/        OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  8719*/        OPC_EmitMergeInputChains1_0,
/*  8720*/        OPC_EmitConvertToTarget, 4,
/*  8722*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadSub32), 0|OPFL_Chain,
                      MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 5, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5302:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadSub32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  8733*/      0, /*End of Scope*/
/*  8734*/    /*Scope*/ 50, /*->8785*/
/*  8735*/      OPC_CheckChild1Integer, 53|128,41/*5301*/, 
/*  8738*/      OPC_RecordChild2, // #1 = $addr
/*  8739*/      OPC_CheckChild2Type, MVT::i32,
/*  8741*/      OPC_RecordChild3, // #2 = $incr
/*  8742*/      OPC_RecordChild4, // #3 = $mask
/*  8743*/      OPC_RecordChild5, // #4 = $ordering
/*  8744*/      OPC_MoveChild5,
/*  8745*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8748*/      OPC_MoveParent,
/*  8749*/      OPC_Scope, 16, /*->8767*/ // 2 children in Scope
/*  8751*/        OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  8753*/        OPC_EmitMergeInputChains1_0,
/*  8754*/        OPC_EmitConvertToTarget, 4,
/*  8756*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadNand32), 0|OPFL_Chain,
                      MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 5, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5301:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadNand32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  8767*/      /*Scope*/ 16, /*->8784*/
/*  8768*/        OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  8770*/        OPC_EmitMergeInputChains1_0,
/*  8771*/        OPC_EmitConvertToTarget, 4,
/*  8773*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadNand32), 0|OPFL_Chain,
                      MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 5, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5301:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadNand32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  8784*/      0, /*End of Scope*/
/*  8785*/    /*Scope*/ 57, /*->8843*/
/*  8786*/      OPC_CheckChild1Integer, 51|128,41/*5299*/, 
/*  8789*/      OPC_RecordChild2, // #1 = $addr
/*  8790*/      OPC_CheckChild2Type, MVT::i32,
/*  8792*/      OPC_RecordChild3, // #2 = $incr
/*  8793*/      OPC_RecordChild4, // #3 = $mask
/*  8794*/      OPC_RecordChild5, // #4 = $shiftamt
/*  8795*/      OPC_RecordChild6, // #5 = $ordering
/*  8796*/      OPC_MoveChild6,
/*  8797*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8800*/      OPC_MoveParent,
/*  8801*/      OPC_Scope, 19, /*->8822*/ // 2 children in Scope
/*  8803*/        OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  8805*/        OPC_EmitMergeInputChains1_0,
/*  8806*/        OPC_EmitConvertToTarget, 5,
/*  8808*/        OPC_MorphNodeTo, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadMax32), 0|OPFL_Chain,
                      3/*#VTs*/, MVT::i32, MVT::i32, MVT::i32, 5/*#Ops*/, 1, 2, 3, 4, 6, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5299:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, GPR:{ *:[i32] }:$shiftamt, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadMax32:{ *:[i32] }:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, GPR:{ *:[i32] }:$shiftamt, (imm:{ *:[i32] }):$ordering)
/*  8822*/      /*Scope*/ 19, /*->8842*/
/*  8823*/        OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  8825*/        OPC_EmitMergeInputChains1_0,
/*  8826*/        OPC_EmitConvertToTarget, 5,
/*  8828*/        OPC_MorphNodeTo, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadMax32), 0|OPFL_Chain,
                      3/*#VTs*/, MVT::i32, MVT::i32, MVT::i32, 5/*#Ops*/, 1, 2, 3, 4, 6, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5299:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, GPR:{ *:[i32] }:$shiftamt, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadMax32:{ *:[i32] }:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, GPR:{ *:[i32] }:$shiftamt, (imm:{ *:[i32] }):$ordering)
/*  8842*/      0, /*End of Scope*/
/*  8843*/    /*Scope*/ 57, /*->8901*/
/*  8844*/      OPC_CheckChild1Integer, 52|128,41/*5300*/, 
/*  8847*/      OPC_RecordChild2, // #1 = $addr
/*  8848*/      OPC_CheckChild2Type, MVT::i32,
/*  8850*/      OPC_RecordChild3, // #2 = $incr
/*  8851*/      OPC_RecordChild4, // #3 = $mask
/*  8852*/      OPC_RecordChild5, // #4 = $shiftamt
/*  8853*/      OPC_RecordChild6, // #5 = $ordering
/*  8854*/      OPC_MoveChild6,
/*  8855*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8858*/      OPC_MoveParent,
/*  8859*/      OPC_Scope, 19, /*->8880*/ // 2 children in Scope
/*  8861*/        OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  8863*/        OPC_EmitMergeInputChains1_0,
/*  8864*/        OPC_EmitConvertToTarget, 5,
/*  8866*/        OPC_MorphNodeTo, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadMin32), 0|OPFL_Chain,
                      3/*#VTs*/, MVT::i32, MVT::i32, MVT::i32, 5/*#Ops*/, 1, 2, 3, 4, 6, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5300:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, GPR:{ *:[i32] }:$shiftamt, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadMin32:{ *:[i32] }:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, GPR:{ *:[i32] }:$shiftamt, (imm:{ *:[i32] }):$ordering)
/*  8880*/      /*Scope*/ 19, /*->8900*/
/*  8881*/        OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  8883*/        OPC_EmitMergeInputChains1_0,
/*  8884*/        OPC_EmitConvertToTarget, 5,
/*  8886*/        OPC_MorphNodeTo, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadMin32), 0|OPFL_Chain,
                      3/*#VTs*/, MVT::i32, MVT::i32, MVT::i32, 5/*#Ops*/, 1, 2, 3, 4, 6, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5300:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, GPR:{ *:[i32] }:$shiftamt, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadMin32:{ *:[i32] }:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, GPR:{ *:[i32] }:$shiftamt, (imm:{ *:[i32] }):$ordering)
/*  8900*/      0, /*End of Scope*/
/*  8901*/    /*Scope*/ 54, /*->8956*/
/*  8902*/      OPC_CheckChild1Integer, 55|128,41/*5303*/, 
/*  8905*/      OPC_RecordChild2, // #1 = $addr
/*  8906*/      OPC_CheckChild2Type, MVT::i32,
/*  8908*/      OPC_RecordChild3, // #2 = $incr
/*  8909*/      OPC_RecordChild4, // #3 = $mask
/*  8910*/      OPC_RecordChild5, // #4 = $ordering
/*  8911*/      OPC_MoveChild5,
/*  8912*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8915*/      OPC_MoveParent,
/*  8916*/      OPC_Scope, 18, /*->8936*/ // 2 children in Scope
/*  8918*/        OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  8920*/        OPC_EmitMergeInputChains1_0,
/*  8921*/        OPC_EmitConvertToTarget, 4,
/*  8923*/        OPC_MorphNodeTo, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadUMax32), 0|OPFL_Chain,
                      3/*#VTs*/, MVT::i32, MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 5, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5303:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadUMax32:{ *:[i32] }:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  8936*/      /*Scope*/ 18, /*->8955*/
/*  8937*/        OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  8939*/        OPC_EmitMergeInputChains1_0,
/*  8940*/        OPC_EmitConvertToTarget, 4,
/*  8942*/        OPC_MorphNodeTo, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadUMax32), 0|OPFL_Chain,
                      3/*#VTs*/, MVT::i32, MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 5, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5303:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadUMax32:{ *:[i32] }:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  8955*/      0, /*End of Scope*/
/*  8956*/    /*Scope*/ 54, /*->9011*/
/*  8957*/      OPC_CheckChild1Integer, 56|128,41/*5304*/, 
/*  8960*/      OPC_RecordChild2, // #1 = $addr
/*  8961*/      OPC_CheckChild2Type, MVT::i32,
/*  8963*/      OPC_RecordChild3, // #2 = $incr
/*  8964*/      OPC_RecordChild4, // #3 = $mask
/*  8965*/      OPC_RecordChild5, // #4 = $ordering
/*  8966*/      OPC_MoveChild5,
/*  8967*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  8970*/      OPC_MoveParent,
/*  8971*/      OPC_Scope, 18, /*->8991*/ // 2 children in Scope
/*  8973*/        OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  8975*/        OPC_EmitMergeInputChains1_0,
/*  8976*/        OPC_EmitConvertToTarget, 4,
/*  8978*/        OPC_MorphNodeTo, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadUMin32), 0|OPFL_Chain,
                      3/*#VTs*/, MVT::i32, MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 5, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5304:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadUMin32:{ *:[i32] }:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  8991*/      /*Scope*/ 18, /*->9010*/
/*  8992*/        OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  8994*/        OPC_EmitMergeInputChains1_0,
/*  8995*/        OPC_EmitConvertToTarget, 4,
/*  8997*/        OPC_MorphNodeTo, TARGET_VAL(RISCV::PseudoMaskedAtomicLoadUMin32), 0|OPFL_Chain,
                      3/*#VTs*/, MVT::i32, MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 5, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5304:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedAtomicLoadUMin32:{ *:[i32] }:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  9010*/      0, /*End of Scope*/
/*  9011*/    /*Scope*/ 53, /*->9065*/
/*  9012*/      OPC_CheckChild1Integer, 58|128,41/*5306*/, 
/*  9015*/      OPC_RecordChild2, // #1 = $addr
/*  9016*/      OPC_CheckChild2Type, MVT::i32,
/*  9018*/      OPC_RecordChild3, // #2 = $cmpval
/*  9019*/      OPC_RecordChild4, // #3 = $newval
/*  9020*/      OPC_RecordChild5, // #4 = $mask
/*  9021*/      OPC_RecordChild6, // #5 = $ordering
/*  9022*/      OPC_MoveChild6,
/*  9023*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  9026*/      OPC_MoveParent,
/*  9027*/      OPC_Scope, 17, /*->9046*/ // 2 children in Scope
/*  9029*/        OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/*  9031*/        OPC_EmitMergeInputChains1_0,
/*  9032*/        OPC_EmitConvertToTarget, 5,
/*  9034*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoMaskedCmpXchg32), 0|OPFL_Chain,
                      MVT::i32, MVT::i32, 5/*#Ops*/, 1, 2, 3, 4, 6, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5306:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmpval, GPR:{ *:[i32] }:$newval, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedCmpXchg32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmpval, GPR:{ *:[i32] }:$newval, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  9046*/      /*Scope*/ 17, /*->9064*/
/*  9047*/        OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/*  9049*/        OPC_EmitMergeInputChains1_0,
/*  9050*/        OPC_EmitConvertToTarget, 5,
/*  9052*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoMaskedCmpXchg32), 0|OPFL_Chain,
                      MVT::i32, MVT::i32, 5/*#Ops*/, 1, 2, 3, 4, 6, 
                  // Src: (intrinsic_w_chain:{ *:[i32] } 5306:{ *:[iPTR] }, GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmpval, GPR:{ *:[i32] }:$newval, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering) - Complexity = 11
                  // Dst: (PseudoMaskedCmpXchg32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmpval, GPR:{ *:[i32] }:$newval, GPR:{ *:[i32] }:$mask, (imm:{ *:[i32] }):$ordering)
/*  9064*/      0, /*End of Scope*/
/*  9065*/    0, /*End of Scope*/
/*  9066*/  /*SwitchOpcode*/ 35|128,1/*163*/, TARGET_VAL(ISD::SHL),// ->9233
/*  9070*/    OPC_RecordChild0, // #0 = $rs1
/*  9071*/    OPC_Scope, 56, /*->9129*/ // 2 children in Scope
/*  9073*/      OPC_MoveChild1,
/*  9074*/      OPC_CheckOpcode, TARGET_VAL(ISD::AND),
/*  9077*/      OPC_RecordChild0, // #1 = $rs2
/*  9078*/      OPC_MoveChild1,
/*  9079*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  9082*/      OPC_CheckPredicate, 19, // Predicate_immbottomxlenset
/*  9084*/      OPC_MoveParent,
/*  9085*/      OPC_SwitchType /*2 cases */, 25, MVT::i32,// ->9113
/*  9088*/        OPC_MoveParent,
/*  9089*/        OPC_CheckType, MVT::i32,
/*  9091*/        OPC_Scope, 10, /*->9103*/ // 2 children in Scope
/*  9093*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  9095*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLL), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (shl:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (and:{ *:[i32] } GPR:{ *:[i32] }:$rs2, (imm:{ *:[i32] })<<P:Predicate_immbottomxlenset>>)) - Complexity = 10
                    // Dst: (SLL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  9103*/        /*Scope*/ 8, /*->9112*/
/*  9104*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLL), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (shl:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (and:{ *:[i32] } GPR:{ *:[i32] }:$rs2, (imm:{ *:[i32] })<<P:Predicate_immbottomxlenset>>)) - Complexity = 10
                    // Dst: (SLL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  9112*/        0, /*End of Scope*/
/*  9113*/      /*SwitchType*/ 13, MVT::i64,// ->9128
/*  9115*/        OPC_MoveParent,
/*  9116*/        OPC_CheckType, MVT::i64,
/*  9118*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  9120*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLL), 0,
                      MVT::i64, 2/*#Ops*/, 0, 1, 
                  // Src: (shl:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (and:{ *:[i64] } GPR:{ *:[i64] }:$rs2, (imm:{ *:[i64] })<<P:Predicate_immbottomxlenset>>)) - Complexity = 10
                  // Dst: (SLL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/*  9128*/      0, // EndSwitchType
/*  9129*/    /*Scope*/ 102, /*->9232*/
/*  9130*/      OPC_RecordChild1, // #1 = $shamt
/*  9131*/      OPC_Scope, 56, /*->9189*/ // 3 children in Scope
/*  9133*/        OPC_MoveChild1,
/*  9134*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  9137*/        OPC_CheckPredicate, 20, // Predicate_uimmlog2xlen
/*  9139*/        OPC_SwitchType /*2 cases */, 29, MVT::i32,// ->9171
/*  9142*/          OPC_MoveParent,
/*  9143*/          OPC_CheckType, MVT::i32,
/*  9145*/          OPC_Scope, 12, /*->9159*/ // 2 children in Scope
/*  9147*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  9149*/            OPC_EmitConvertToTarget, 1,
/*  9151*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLLI), 0,
                          MVT::i32, 2/*#Ops*/, 0, 2, 
                      // Src: (shl:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_uimmlog2xlen>>:$shamt) - Complexity = 7
                      // Dst: (SLLI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_uimmlog2xlen>>:$shamt)
/*  9159*/          /*Scope*/ 10, /*->9170*/
/*  9160*/            OPC_EmitConvertToTarget, 1,
/*  9162*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLLI), 0,
                          MVT::i32, 2/*#Ops*/, 0, 2, 
                      // Src: (shl:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_uimmlog2xlen>>:$shamt) - Complexity = 7
                      // Dst: (SLLI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_uimmlog2xlen>>:$shamt)
/*  9170*/          0, /*End of Scope*/
/*  9171*/        /*SwitchType*/ 15, MVT::i64,// ->9188
/*  9173*/          OPC_MoveParent,
/*  9174*/          OPC_CheckType, MVT::i64,
/*  9176*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  9178*/          OPC_EmitConvertToTarget, 1,
/*  9180*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLLI), 0,
                        MVT::i64, 2/*#Ops*/, 0, 2, 
                    // Src: (shl:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_uimmlog2xlen>>:$shamt) - Complexity = 7
                    // Dst: (SLLI:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_uimmlog2xlen>>:$shamt)
/*  9188*/        0, // EndSwitchType
/*  9189*/      /*Scope*/ 26, /*->9216*/
/*  9190*/        OPC_CheckChild1Type, MVT::i32,
/*  9192*/        OPC_CheckType, MVT::i32,
/*  9194*/        OPC_Scope, 10, /*->9206*/ // 2 children in Scope
/*  9196*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  9198*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLL), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (shl:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                    // Dst: (SLL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  9206*/        /*Scope*/ 8, /*->9215*/
/*  9207*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLL), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (shl:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                    // Dst: (SLL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  9215*/        0, /*End of Scope*/
/*  9216*/      /*Scope*/ 14, /*->9231*/
/*  9217*/        OPC_CheckChild1Type, MVT::i64,
/*  9219*/        OPC_CheckType, MVT::i64,
/*  9221*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  9223*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLL), 0,
                      MVT::i64, 2/*#Ops*/, 0, 1, 
                  // Src: (shl:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                  // Dst: (SLL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/*  9231*/      0, /*End of Scope*/
/*  9232*/    0, /*End of Scope*/
/*  9233*/  /*SwitchOpcode*/ 35|128,1/*163*/, TARGET_VAL(ISD::SRL),// ->9400
/*  9237*/    OPC_RecordChild0, // #0 = $rs1
/*  9238*/    OPC_Scope, 56, /*->9296*/ // 2 children in Scope
/*  9240*/      OPC_MoveChild1,
/*  9241*/      OPC_CheckOpcode, TARGET_VAL(ISD::AND),
/*  9244*/      OPC_RecordChild0, // #1 = $rs2
/*  9245*/      OPC_MoveChild1,
/*  9246*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  9249*/      OPC_CheckPredicate, 19, // Predicate_immbottomxlenset
/*  9251*/      OPC_MoveParent,
/*  9252*/      OPC_SwitchType /*2 cases */, 25, MVT::i32,// ->9280
/*  9255*/        OPC_MoveParent,
/*  9256*/        OPC_CheckType, MVT::i32,
/*  9258*/        OPC_Scope, 10, /*->9270*/ // 2 children in Scope
/*  9260*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  9262*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRL), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (srl:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (and:{ *:[i32] } GPR:{ *:[i32] }:$rs2, (imm:{ *:[i32] })<<P:Predicate_immbottomxlenset>>)) - Complexity = 10
                    // Dst: (SRL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  9270*/        /*Scope*/ 8, /*->9279*/
/*  9271*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRL), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (srl:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (and:{ *:[i32] } GPR:{ *:[i32] }:$rs2, (imm:{ *:[i32] })<<P:Predicate_immbottomxlenset>>)) - Complexity = 10
                    // Dst: (SRL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  9279*/        0, /*End of Scope*/
/*  9280*/      /*SwitchType*/ 13, MVT::i64,// ->9295
/*  9282*/        OPC_MoveParent,
/*  9283*/        OPC_CheckType, MVT::i64,
/*  9285*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  9287*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRL), 0,
                      MVT::i64, 2/*#Ops*/, 0, 1, 
                  // Src: (srl:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (and:{ *:[i64] } GPR:{ *:[i64] }:$rs2, (imm:{ *:[i64] })<<P:Predicate_immbottomxlenset>>)) - Complexity = 10
                  // Dst: (SRL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/*  9295*/      0, // EndSwitchType
/*  9296*/    /*Scope*/ 102, /*->9399*/
/*  9297*/      OPC_RecordChild1, // #1 = $shamt
/*  9298*/      OPC_Scope, 56, /*->9356*/ // 3 children in Scope
/*  9300*/        OPC_MoveChild1,
/*  9301*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  9304*/        OPC_CheckPredicate, 20, // Predicate_uimmlog2xlen
/*  9306*/        OPC_SwitchType /*2 cases */, 29, MVT::i32,// ->9338
/*  9309*/          OPC_MoveParent,
/*  9310*/          OPC_CheckType, MVT::i32,
/*  9312*/          OPC_Scope, 12, /*->9326*/ // 2 children in Scope
/*  9314*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  9316*/            OPC_EmitConvertToTarget, 1,
/*  9318*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRLI), 0,
                          MVT::i32, 2/*#Ops*/, 0, 2, 
                      // Src: (srl:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_uimmlog2xlen>>:$shamt) - Complexity = 7
                      // Dst: (SRLI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_uimmlog2xlen>>:$shamt)
/*  9326*/          /*Scope*/ 10, /*->9337*/
/*  9327*/            OPC_EmitConvertToTarget, 1,
/*  9329*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRLI), 0,
                          MVT::i32, 2/*#Ops*/, 0, 2, 
                      // Src: (srl:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_uimmlog2xlen>>:$shamt) - Complexity = 7
                      // Dst: (SRLI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_uimmlog2xlen>>:$shamt)
/*  9337*/          0, /*End of Scope*/
/*  9338*/        /*SwitchType*/ 15, MVT::i64,// ->9355
/*  9340*/          OPC_MoveParent,
/*  9341*/          OPC_CheckType, MVT::i64,
/*  9343*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  9345*/          OPC_EmitConvertToTarget, 1,
/*  9347*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRLI), 0,
                        MVT::i64, 2/*#Ops*/, 0, 2, 
                    // Src: (srl:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_uimmlog2xlen>>:$shamt) - Complexity = 7
                    // Dst: (SRLI:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_uimmlog2xlen>>:$shamt)
/*  9355*/        0, // EndSwitchType
/*  9356*/      /*Scope*/ 26, /*->9383*/
/*  9357*/        OPC_CheckChild1Type, MVT::i32,
/*  9359*/        OPC_CheckType, MVT::i32,
/*  9361*/        OPC_Scope, 10, /*->9373*/ // 2 children in Scope
/*  9363*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  9365*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRL), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (srl:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                    // Dst: (SRL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  9373*/        /*Scope*/ 8, /*->9382*/
/*  9374*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRL), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (srl:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                    // Dst: (SRL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  9382*/        0, /*End of Scope*/
/*  9383*/      /*Scope*/ 14, /*->9398*/
/*  9384*/        OPC_CheckChild1Type, MVT::i64,
/*  9386*/        OPC_CheckType, MVT::i64,
/*  9388*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  9390*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRL), 0,
                      MVT::i64, 2/*#Ops*/, 0, 1, 
                  // Src: (srl:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                  // Dst: (SRL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/*  9398*/      0, /*End of Scope*/
/*  9399*/    0, /*End of Scope*/
/*  9400*/  /*SwitchOpcode*/ 69|128,1/*197*/, TARGET_VAL(ISD::SRA),// ->9601
/*  9404*/    OPC_Scope, 57, /*->9463*/ // 3 children in Scope
/*  9406*/      OPC_RecordChild0, // #0 = $rs1
/*  9407*/      OPC_MoveChild1,
/*  9408*/      OPC_CheckOpcode, TARGET_VAL(ISD::AND),
/*  9411*/      OPC_RecordChild0, // #1 = $rs2
/*  9412*/      OPC_MoveChild1,
/*  9413*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  9416*/      OPC_CheckPredicate, 19, // Predicate_immbottomxlenset
/*  9418*/      OPC_MoveParent,
/*  9419*/      OPC_SwitchType /*2 cases */, 25, MVT::i32,// ->9447
/*  9422*/        OPC_MoveParent,
/*  9423*/        OPC_CheckType, MVT::i32,
/*  9425*/        OPC_Scope, 10, /*->9437*/ // 2 children in Scope
/*  9427*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  9429*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRA), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (sra:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (and:{ *:[i32] } GPR:{ *:[i32] }:$rs2, (imm:{ *:[i32] })<<P:Predicate_immbottomxlenset>>)) - Complexity = 10
                    // Dst: (SRA:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  9437*/        /*Scope*/ 8, /*->9446*/
/*  9438*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRA), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (sra:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (and:{ *:[i32] } GPR:{ *:[i32] }:$rs2, (imm:{ *:[i32] })<<P:Predicate_immbottomxlenset>>)) - Complexity = 10
                    // Dst: (SRA:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  9446*/        0, /*End of Scope*/
/*  9447*/      /*SwitchType*/ 13, MVT::i64,// ->9462
/*  9449*/        OPC_MoveParent,
/*  9450*/        OPC_CheckType, MVT::i64,
/*  9452*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  9454*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRA), 0,
                      MVT::i64, 2/*#Ops*/, 0, 1, 
                  // Src: (sra:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (and:{ *:[i64] } GPR:{ *:[i64] }:$rs2, (imm:{ *:[i64] })<<P:Predicate_immbottomxlenset>>)) - Complexity = 10
                  // Dst: (SRA:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/*  9462*/      0, // EndSwitchType
/*  9463*/    /*Scope*/ 32, /*->9496*/
/*  9464*/      OPC_MoveChild0,
/*  9465*/      OPC_CheckOpcode, TARGET_VAL(ISD::SIGN_EXTEND_INREG),
/*  9468*/      OPC_RecordChild0, // #0 = $rs1
/*  9469*/      OPC_MoveChild1,
/*  9470*/      OPC_CheckValueType, MVT::i32,
/*  9472*/      OPC_MoveParent,
/*  9473*/      OPC_MoveParent,
/*  9474*/      OPC_RecordChild1, // #1 = $shamt
/*  9475*/      OPC_MoveChild1,
/*  9476*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  9479*/      OPC_CheckPredicate, 21, // Predicate_uimm5
/*  9481*/      OPC_CheckType, MVT::i64,
/*  9483*/      OPC_MoveParent,
/*  9484*/      OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  9486*/      OPC_EmitConvertToTarget, 1,
/*  9488*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRAIW), 0,
                    MVT::i64, 2/*#Ops*/, 0, 2, 
                // Src: (sra:{ *:[i64] } (sext_inreg:{ *:[i64] } GPR:{ *:[i64] }:$rs1, i32:{ *:[Other] }), (imm:{ *:[i64] })<<P:Predicate_uimm5>>:$shamt) - Complexity = 10
                // Dst: (SRAIW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_uimm5>>:$shamt)
/*  9496*/    /*Scope*/ 103, /*->9600*/
/*  9497*/      OPC_RecordChild0, // #0 = $rs1
/*  9498*/      OPC_RecordChild1, // #1 = $shamt
/*  9499*/      OPC_Scope, 56, /*->9557*/ // 3 children in Scope
/*  9501*/        OPC_MoveChild1,
/*  9502*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  9505*/        OPC_CheckPredicate, 20, // Predicate_uimmlog2xlen
/*  9507*/        OPC_SwitchType /*2 cases */, 29, MVT::i32,// ->9539
/*  9510*/          OPC_MoveParent,
/*  9511*/          OPC_CheckType, MVT::i32,
/*  9513*/          OPC_Scope, 12, /*->9527*/ // 2 children in Scope
/*  9515*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  9517*/            OPC_EmitConvertToTarget, 1,
/*  9519*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRAI), 0,
                          MVT::i32, 2/*#Ops*/, 0, 2, 
                      // Src: (sra:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_uimmlog2xlen>>:$shamt) - Complexity = 7
                      // Dst: (SRAI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_uimmlog2xlen>>:$shamt)
/*  9527*/          /*Scope*/ 10, /*->9538*/
/*  9528*/            OPC_EmitConvertToTarget, 1,
/*  9530*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRAI), 0,
                          MVT::i32, 2/*#Ops*/, 0, 2, 
                      // Src: (sra:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_uimmlog2xlen>>:$shamt) - Complexity = 7
                      // Dst: (SRAI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_uimmlog2xlen>>:$shamt)
/*  9538*/          0, /*End of Scope*/
/*  9539*/        /*SwitchType*/ 15, MVT::i64,// ->9556
/*  9541*/          OPC_MoveParent,
/*  9542*/          OPC_CheckType, MVT::i64,
/*  9544*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  9546*/          OPC_EmitConvertToTarget, 1,
/*  9548*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRAI), 0,
                        MVT::i64, 2/*#Ops*/, 0, 2, 
                    // Src: (sra:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_uimmlog2xlen>>:$shamt) - Complexity = 7
                    // Dst: (SRAI:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_uimmlog2xlen>>:$shamt)
/*  9556*/        0, // EndSwitchType
/*  9557*/      /*Scope*/ 26, /*->9584*/
/*  9558*/        OPC_CheckChild1Type, MVT::i32,
/*  9560*/        OPC_CheckType, MVT::i32,
/*  9562*/        OPC_Scope, 10, /*->9574*/ // 2 children in Scope
/*  9564*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  9566*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRA), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (sra:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                    // Dst: (SRA:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  9574*/        /*Scope*/ 8, /*->9583*/
/*  9575*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRA), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (sra:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                    // Dst: (SRA:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/*  9583*/        0, /*End of Scope*/
/*  9584*/      /*Scope*/ 14, /*->9599*/
/*  9585*/        OPC_CheckChild1Type, MVT::i64,
/*  9587*/        OPC_CheckType, MVT::i64,
/*  9589*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  9591*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRA), 0,
                      MVT::i64, 2/*#Ops*/, 0, 1, 
                  // Src: (sra:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                  // Dst: (SRA:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/*  9599*/      0, /*End of Scope*/
/*  9600*/    0, /*End of Scope*/
/*  9601*/  /*SwitchOpcode*/ 114, TARGET_VAL(ISD::BRIND),// ->9718
/*  9604*/    OPC_RecordNode, // #0 = 'brind' chained node
/*  9605*/    OPC_Scope, 59, /*->9666*/ // 2 children in Scope
/*  9607*/      OPC_MoveChild1,
/*  9608*/      OPC_CheckOpcode, TARGET_VAL(ISD::ADD),
/*  9611*/      OPC_RecordChild0, // #1 = $rs1
/*  9612*/      OPC_RecordChild1, // #2 = $imm12
/*  9613*/      OPC_MoveChild1,
/*  9614*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  9617*/      OPC_CheckPredicate, 0, // Predicate_simm12
/*  9619*/      OPC_MoveParent,
/*  9620*/      OPC_SwitchType /*2 cases */, 27, MVT::i32,// ->9650
/*  9623*/        OPC_MoveParent,
/*  9624*/        OPC_Scope, 12, /*->9638*/ // 2 children in Scope
/*  9626*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  9628*/          OPC_EmitMergeInputChains1_0,
/*  9629*/          OPC_EmitConvertToTarget, 2,
/*  9631*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoBRIND), 0|OPFL_Chain,
                        2/*#Ops*/, 1, 3, 
                    // Src: (brind (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)) - Complexity = 10
                    // Dst: (PseudoBRIND GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  9638*/        /*Scope*/ 10, /*->9649*/
/*  9639*/          OPC_EmitMergeInputChains1_0,
/*  9640*/          OPC_EmitConvertToTarget, 2,
/*  9642*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoBRIND), 0|OPFL_Chain,
                        2/*#Ops*/, 1, 3, 
                    // Src: (brind (add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)) - Complexity = 10
                    // Dst: (PseudoBRIND GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/*  9649*/        0, /*End of Scope*/
/*  9650*/      /*SwitchType*/ 13, MVT::i64,// ->9665
/*  9652*/        OPC_MoveParent,
/*  9653*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  9655*/        OPC_EmitMergeInputChains1_0,
/*  9656*/        OPC_EmitConvertToTarget, 2,
/*  9658*/        OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoBRIND), 0|OPFL_Chain,
                      2/*#Ops*/, 1, 3, 
                  // Src: (brind (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)) - Complexity = 10
                  // Dst: (PseudoBRIND GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  9665*/      0, // EndSwitchType
/*  9666*/    /*Scope*/ 50, /*->9717*/
/*  9667*/      OPC_RecordChild1, // #1 = $rs1
/*  9668*/      OPC_Scope, 30, /*->9700*/ // 2 children in Scope
/*  9670*/        OPC_CheckChild1Type, MVT::i32,
/*  9672*/        OPC_Scope, 13, /*->9687*/ // 2 children in Scope
/*  9674*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  9676*/          OPC_EmitMergeInputChains1_0,
/*  9677*/          OPC_EmitInteger, MVT::i32, 0, 
/*  9680*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoBRIND), 0|OPFL_Chain,
                        2/*#Ops*/, 1, 2, 
                    // Src: (brind GPR:{ *:[i32] }:$rs1) - Complexity = 3
                    // Dst: (PseudoBRIND GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  9687*/        /*Scope*/ 11, /*->9699*/
/*  9688*/          OPC_EmitMergeInputChains1_0,
/*  9689*/          OPC_EmitInteger, MVT::i32, 0, 
/*  9692*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoBRIND), 0|OPFL_Chain,
                        2/*#Ops*/, 1, 2, 
                    // Src: (brind GPR:{ *:[i32] }:$rs1) - Complexity = 3
                    // Dst: (PseudoBRIND GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] })
/*  9699*/        0, /*End of Scope*/
/*  9700*/      /*Scope*/ 15, /*->9716*/
/*  9701*/        OPC_CheckChild1Type, MVT::i64,
/*  9703*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/*  9705*/        OPC_EmitMergeInputChains1_0,
/*  9706*/        OPC_EmitInteger, MVT::i64, 0, 
/*  9709*/        OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoBRIND), 0|OPFL_Chain,
                      2/*#Ops*/, 1, 2, 
                  // Src: (brind GPR:{ *:[i64] }:$rs1) - Complexity = 3
                  // Dst: (PseudoBRIND GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  9716*/      0, /*End of Scope*/
/*  9717*/    0, /*End of Scope*/
/*  9718*/  /*SwitchOpcode*/ 124, TARGET_VAL(ISD::SIGN_EXTEND_INREG),// ->9845
/*  9721*/    OPC_Scope, 102, /*->9825*/ // 2 children in Scope
/*  9723*/      OPC_MoveChild0,
/*  9724*/      OPC_SwitchOpcode /*3 cases */, 45, TARGET_VAL(ISD::ADD),// ->9773
/*  9728*/        OPC_RecordChild0, // #0 = $rs1
/*  9729*/        OPC_RecordChild1, // #1 = $imm12
/*  9730*/        OPC_Scope, 24, /*->9756*/ // 2 children in Scope
/*  9732*/          OPC_MoveChild1,
/*  9733*/          OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  9736*/          OPC_CheckPredicate, 0, // Predicate_simm12
/*  9738*/          OPC_MoveParent,
/*  9739*/          OPC_MoveParent,
/*  9740*/          OPC_MoveChild1,
/*  9741*/          OPC_CheckValueType, MVT::i32,
/*  9743*/          OPC_MoveParent,
/*  9744*/          OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  9746*/          OPC_EmitConvertToTarget, 1,
/*  9748*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDIW), 0,
                        MVT::i64, 2/*#Ops*/, 0, 2, 
                    // Src: (sext_inreg:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12), i32:{ *:[Other] }) - Complexity = 10
                    // Dst: (ADDIW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/*  9756*/        /*Scope*/ 15, /*->9772*/
/*  9757*/          OPC_MoveParent,
/*  9758*/          OPC_MoveChild1,
/*  9759*/          OPC_CheckValueType, MVT::i32,
/*  9761*/          OPC_MoveParent,
/*  9762*/          OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  9764*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDW), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (sext_inreg:{ *:[i64] } (add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2), i32:{ *:[Other] }) - Complexity = 6
                    // Dst: (ADDW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/*  9772*/        0, /*End of Scope*/
/*  9773*/      /*SwitchOpcode*/ 28, TARGET_VAL(ISD::SHL),// ->9804
/*  9776*/        OPC_RecordChild0, // #0 = $rs1
/*  9777*/        OPC_RecordChild1, // #1 = $shamt
/*  9778*/        OPC_MoveChild1,
/*  9779*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  9782*/        OPC_CheckPredicate, 21, // Predicate_uimm5
/*  9784*/        OPC_CheckType, MVT::i64,
/*  9786*/        OPC_MoveParent,
/*  9787*/        OPC_MoveParent,
/*  9788*/        OPC_MoveChild1,
/*  9789*/        OPC_CheckValueType, MVT::i32,
/*  9791*/        OPC_MoveParent,
/*  9792*/        OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  9794*/        OPC_EmitConvertToTarget, 1,
/*  9796*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLLIW), 0,
                      MVT::i64, 2/*#Ops*/, 0, 2, 
                  // Src: (sext_inreg:{ *:[i64] } (shl:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_uimm5>>:$shamt), i32:{ *:[Other] }) - Complexity = 10
                  // Dst: (SLLIW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_uimm5>>:$shamt)
/*  9804*/      /*SwitchOpcode*/ 17, TARGET_VAL(ISD::SUB),// ->9824
/*  9807*/        OPC_RecordChild0, // #0 = $rs1
/*  9808*/        OPC_RecordChild1, // #1 = $rs2
/*  9809*/        OPC_MoveParent,
/*  9810*/        OPC_MoveChild1,
/*  9811*/        OPC_CheckValueType, MVT::i32,
/*  9813*/        OPC_MoveParent,
/*  9814*/        OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  9816*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::SUBW), 0,
                      MVT::i64, 2/*#Ops*/, 0, 1, 
                  // Src: (sext_inreg:{ *:[i64] } (sub:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2), i32:{ *:[Other] }) - Complexity = 6
                  // Dst: (SUBW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/*  9824*/      0, // EndSwitchOpcode
/*  9825*/    /*Scope*/ 18, /*->9844*/
/*  9826*/      OPC_RecordChild0, // #0 = $rs1
/*  9827*/      OPC_MoveChild1,
/*  9828*/      OPC_CheckValueType, MVT::i32,
/*  9830*/      OPC_MoveParent,
/*  9831*/      OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/*  9833*/      OPC_EmitInteger, MVT::i64, 0, 
/*  9836*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDIW), 0,
                    MVT::i64, 2/*#Ops*/, 0, 1, 
                // Src: (sext_inreg:{ *:[i64] } GPR:{ *:[i64] }:$rs1, i32:{ *:[Other] }) - Complexity = 3
                // Dst: (ADDIW:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] })
/*  9844*/    0, /*End of Scope*/
/*  9845*/  /*SwitchOpcode*/ 21, TARGET_VAL(ISD::CALLSEQ_START),// ->9869
/*  9848*/    OPC_RecordNode, // #0 = 'CallSeqStart' chained node
/*  9849*/    OPC_RecordChild1, // #1 = $amt1
/*  9850*/    OPC_MoveChild1,
/*  9851*/    OPC_CheckOpcode, TARGET_VAL(ISD::TargetConstant),
/*  9854*/    OPC_MoveParent,
/*  9855*/    OPC_RecordChild2, // #2 = $amt2
/*  9856*/    OPC_MoveChild2,
/*  9857*/    OPC_CheckOpcode, TARGET_VAL(ISD::TargetConstant),
/*  9860*/    OPC_MoveParent,
/*  9861*/    OPC_EmitMergeInputChains1_0,
/*  9862*/    OPC_MorphNodeTo0, TARGET_VAL(RISCV::ADJCALLSTACKDOWN), 0|OPFL_Chain|OPFL_GlueOutput,
                  2/*#Ops*/, 1, 2, 
              // Src: (CallSeqStart (timm:{ *:[i32] }):$amt1, (timm:{ *:[i32] }):$amt2) - Complexity = 9
              // Dst: (ADJCALLSTACKDOWN (timm:{ *:[i32] }):$amt1, (timm:{ *:[i32] }):$amt2)
/*  9869*/  /*SwitchOpcode*/ 22, TARGET_VAL(ISD::CALLSEQ_END),// ->9894
/*  9872*/    OPC_RecordNode, // #0 = 'CallSeqEnd' chained node
/*  9873*/    OPC_CaptureGlueInput,
/*  9874*/    OPC_RecordChild1, // #1 = $amt1
/*  9875*/    OPC_MoveChild1,
/*  9876*/    OPC_CheckOpcode, TARGET_VAL(ISD::TargetConstant),
/*  9879*/    OPC_MoveParent,
/*  9880*/    OPC_RecordChild2, // #2 = $amt2
/*  9881*/    OPC_MoveChild2,
/*  9882*/    OPC_CheckOpcode, TARGET_VAL(ISD::TargetConstant),
/*  9885*/    OPC_MoveParent,
/*  9886*/    OPC_EmitMergeInputChains1_0,
/*  9887*/    OPC_MorphNodeTo0, TARGET_VAL(RISCV::ADJCALLSTACKUP), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput,
                  2/*#Ops*/, 1, 2, 
              // Src: (CallSeqEnd (timm:{ *:[i32] }):$amt1, (timm:{ *:[i32] }):$amt2) - Complexity = 9
              // Dst: (ADJCALLSTACKUP (timm:{ *:[i32] }):$amt1, (timm:{ *:[i32] }):$amt2)
/*  9894*/  /*SwitchOpcode*/ 43|128,13/*1707*/, TARGET_VAL(ISD::SETCC),// ->11605
/*  9898*/    OPC_RecordChild0, // #0 = $rs1
/*  9899*/    OPC_Scope, 63|128,4/*575*/, /*->10477*/ // 4 children in Scope
/*  9902*/      OPC_CheckChild0Type, MVT::i32,
/*  9904*/      OPC_Scope, 73, /*->9979*/ // 2 children in Scope
/*  9906*/        OPC_CheckChild1Integer, 0, 
/*  9908*/        OPC_MoveChild2,
/*  9909*/        OPC_Scope, 33, /*->9944*/ // 2 children in Scope
/*  9911*/          OPC_CheckCondCode, ISD::SETEQ,
/*  9913*/          OPC_MoveParent,
/*  9914*/          OPC_CheckType, MVT::i32,
/*  9916*/          OPC_Scope, 13, /*->9931*/ // 2 children in Scope
/*  9918*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  9920*/            OPC_EmitInteger, MVT::i32, 1, 
/*  9923*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] }, SETEQ:{ *:[Other] }) - Complexity = 8
                      // Dst: (SLTIU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 1:{ *:[i32] })
/*  9931*/          /*Scope*/ 11, /*->9943*/
/*  9932*/            OPC_EmitInteger, MVT::i32, 1, 
/*  9935*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] }, SETEQ:{ *:[Other] }) - Complexity = 8
                      // Dst: (SLTIU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 1:{ *:[i32] })
/*  9943*/          0, /*End of Scope*/
/*  9944*/        /*Scope*/ 33, /*->9978*/
/*  9945*/          OPC_CheckCondCode, ISD::SETNE,
/*  9947*/          OPC_MoveParent,
/*  9948*/          OPC_CheckType, MVT::i32,
/*  9950*/          OPC_Scope, 13, /*->9965*/ // 2 children in Scope
/*  9952*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/*  9954*/            OPC_EmitRegister, MVT::i32, RISCV::X0,
/*  9957*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTU), 0,
                          MVT::i32, 2/*#Ops*/, 1, 0, 
                      // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] }, SETNE:{ *:[Other] }) - Complexity = 8
                      // Dst: (SLTU:{ *:[i32] } X0:{ *:[i32] }, GPR:{ *:[i32] }:$rs1)
/*  9965*/          /*Scope*/ 11, /*->9977*/
/*  9966*/            OPC_EmitRegister, MVT::i32, RISCV::X0,
/*  9969*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTU), 0,
                          MVT::i32, 2/*#Ops*/, 1, 0, 
                      // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 0:{ *:[i32] }, SETNE:{ *:[Other] }) - Complexity = 8
                      // Dst: (SLTU:{ *:[i32] } X0:{ *:[i32] }, GPR:{ *:[i32] }:$rs1)
/*  9977*/          0, /*End of Scope*/
/*  9978*/        0, /*End of Scope*/
/*  9979*/      /*Scope*/ 111|128,3/*495*/, /*->10476*/
/*  9981*/        OPC_RecordChild1, // #1 = $imm12
/*  9982*/        OPC_Scope, 74, /*->10058*/ // 2 children in Scope
/*  9984*/          OPC_MoveChild1,
/*  9985*/          OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/*  9988*/          OPC_CheckPredicate, 0, // Predicate_simm12
/*  9990*/          OPC_MoveParent,
/*  9991*/          OPC_MoveChild2,
/*  9992*/          OPC_Scope, 31, /*->10025*/ // 2 children in Scope
/*  9994*/            OPC_CheckCondCode, ISD::SETLT,
/*  9996*/            OPC_MoveParent,
/*  9997*/            OPC_CheckType, MVT::i32,
/*  9999*/            OPC_Scope, 12, /*->10013*/ // 2 children in Scope
/* 10001*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 10003*/              OPC_EmitConvertToTarget, 1,
/* 10005*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTI), 0,
                            MVT::i32, 2/*#Ops*/, 0, 2, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12, SETLT:{ *:[Other] }) - Complexity = 7
                        // Dst: (SLTI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/* 10013*/            /*Scope*/ 10, /*->10024*/
/* 10014*/              OPC_EmitConvertToTarget, 1,
/* 10016*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTI), 0,
                            MVT::i32, 2/*#Ops*/, 0, 2, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12, SETLT:{ *:[Other] }) - Complexity = 7
                        // Dst: (SLTI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/* 10024*/            0, /*End of Scope*/
/* 10025*/          /*Scope*/ 31, /*->10057*/
/* 10026*/            OPC_CheckCondCode, ISD::SETULT,
/* 10028*/            OPC_MoveParent,
/* 10029*/            OPC_CheckType, MVT::i32,
/* 10031*/            OPC_Scope, 12, /*->10045*/ // 2 children in Scope
/* 10033*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 10035*/              OPC_EmitConvertToTarget, 1,
/* 10037*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                            MVT::i32, 2/*#Ops*/, 0, 2, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12, SETULT:{ *:[Other] }) - Complexity = 7
                        // Dst: (SLTIU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/* 10045*/            /*Scope*/ 10, /*->10056*/
/* 10046*/              OPC_EmitConvertToTarget, 1,
/* 10048*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                            MVT::i32, 2/*#Ops*/, 0, 2, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12, SETULT:{ *:[Other] }) - Complexity = 7
                        // Dst: (SLTIU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/* 10056*/            0, /*End of Scope*/
/* 10057*/          0, /*End of Scope*/
/* 10058*/        /*Scope*/ 31|128,3/*415*/, /*->10475*/
/* 10060*/          OPC_MoveChild2,
/* 10061*/          OPC_Scope, 27, /*->10090*/ // 10 children in Scope
/* 10063*/            OPC_CheckCondCode, ISD::SETLT,
/* 10065*/            OPC_MoveParent,
/* 10066*/            OPC_CheckType, MVT::i32,
/* 10068*/            OPC_Scope, 10, /*->10080*/ // 2 children in Scope
/* 10070*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 10072*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLT), 0,
                            MVT::i32, 2/*#Ops*/, 0, 1, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETLT:{ *:[Other] }) - Complexity = 3
                        // Dst: (SLT:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 10080*/            /*Scope*/ 8, /*->10089*/
/* 10081*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLT), 0,
                            MVT::i32, 2/*#Ops*/, 0, 1, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETLT:{ *:[Other] }) - Complexity = 3
                        // Dst: (SLT:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 10089*/            0, /*End of Scope*/
/* 10090*/          /*Scope*/ 27, /*->10118*/
/* 10091*/            OPC_CheckCondCode, ISD::SETULT,
/* 10093*/            OPC_MoveParent,
/* 10094*/            OPC_CheckType, MVT::i32,
/* 10096*/            OPC_Scope, 10, /*->10108*/ // 2 children in Scope
/* 10098*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 10100*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTU), 0,
                            MVT::i32, 2/*#Ops*/, 0, 1, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETULT:{ *:[Other] }) - Complexity = 3
                        // Dst: (SLTU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 10108*/            /*Scope*/ 8, /*->10117*/
/* 10109*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTU), 0,
                            MVT::i32, 2/*#Ops*/, 0, 1, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETULT:{ *:[Other] }) - Complexity = 3
                        // Dst: (SLTU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 10117*/            0, /*End of Scope*/
/* 10118*/          /*Scope*/ 27, /*->10146*/
/* 10119*/            OPC_CheckCondCode, ISD::SETUGT,
/* 10121*/            OPC_MoveParent,
/* 10122*/            OPC_CheckType, MVT::i32,
/* 10124*/            OPC_Scope, 10, /*->10136*/ // 2 children in Scope
/* 10126*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 10128*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTU), 0,
                            MVT::i32, 2/*#Ops*/, 1, 0, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETUGT:{ *:[Other] }) - Complexity = 3
                        // Dst: (SLTU:{ *:[i32] } GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)
/* 10136*/            /*Scope*/ 8, /*->10145*/
/* 10137*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTU), 0,
                            MVT::i32, 2/*#Ops*/, 1, 0, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETUGT:{ *:[Other] }) - Complexity = 3
                        // Dst: (SLTU:{ *:[i32] } GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)
/* 10145*/            0, /*End of Scope*/
/* 10146*/          /*Scope*/ 27, /*->10174*/
/* 10147*/            OPC_CheckCondCode, ISD::SETGT,
/* 10149*/            OPC_MoveParent,
/* 10150*/            OPC_CheckType, MVT::i32,
/* 10152*/            OPC_Scope, 10, /*->10164*/ // 2 children in Scope
/* 10154*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 10156*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLT), 0,
                            MVT::i32, 2/*#Ops*/, 1, 0, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETGT:{ *:[Other] }) - Complexity = 3
                        // Dst: (SLT:{ *:[i32] } GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)
/* 10164*/            /*Scope*/ 8, /*->10173*/
/* 10165*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLT), 0,
                            MVT::i32, 2/*#Ops*/, 1, 0, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETGT:{ *:[Other] }) - Complexity = 3
                        // Dst: (SLT:{ *:[i32] } GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1)
/* 10173*/            0, /*End of Scope*/
/* 10174*/          /*Scope*/ 49, /*->10224*/
/* 10175*/            OPC_CheckCondCode, ISD::SETEQ,
/* 10177*/            OPC_MoveParent,
/* 10178*/            OPC_CheckType, MVT::i32,
/* 10180*/            OPC_Scope, 21, /*->10203*/ // 2 children in Scope
/* 10182*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 10184*/              OPC_EmitNode1, TARGET_VAL(RISCV::XOR), 0,
                            MVT::i32, 2/*#Ops*/, 0, 1,  // Results = #2
/* 10192*/              OPC_EmitInteger, MVT::i32, 1, 
/* 10195*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETEQ:{ *:[Other] }) - Complexity = 3
                        // Dst: (SLTIU:{ *:[i32] } (XOR:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2), 1:{ *:[i32] })
/* 10203*/            /*Scope*/ 19, /*->10223*/
/* 10204*/              OPC_EmitNode1, TARGET_VAL(RISCV::XOR), 0,
                            MVT::i32, 2/*#Ops*/, 0, 1,  // Results = #2
/* 10212*/              OPC_EmitInteger, MVT::i32, 1, 
/* 10215*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETEQ:{ *:[Other] }) - Complexity = 3
                        // Dst: (SLTIU:{ *:[i32] } (XOR:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2), 1:{ *:[i32] })
/* 10223*/            0, /*End of Scope*/
/* 10224*/          /*Scope*/ 49, /*->10274*/
/* 10225*/            OPC_CheckCondCode, ISD::SETNE,
/* 10227*/            OPC_MoveParent,
/* 10228*/            OPC_CheckType, MVT::i32,
/* 10230*/            OPC_Scope, 21, /*->10253*/ // 2 children in Scope
/* 10232*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 10234*/              OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 10237*/              OPC_EmitNode1, TARGET_VAL(RISCV::XOR), 0,
                            MVT::i32, 2/*#Ops*/, 0, 1,  // Results = #3
/* 10245*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTU), 0,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETNE:{ *:[Other] }) - Complexity = 3
                        // Dst: (SLTU:{ *:[i32] } X0:{ *:[i32] }, (XOR:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2))
/* 10253*/            /*Scope*/ 19, /*->10273*/
/* 10254*/              OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 10257*/              OPC_EmitNode1, TARGET_VAL(RISCV::XOR), 0,
                            MVT::i32, 2/*#Ops*/, 0, 1,  // Results = #3
/* 10265*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTU), 0,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETNE:{ *:[Other] }) - Complexity = 3
                        // Dst: (SLTU:{ *:[i32] } X0:{ *:[i32] }, (XOR:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2))
/* 10273*/            0, /*End of Scope*/
/* 10274*/          /*Scope*/ 49, /*->10324*/
/* 10275*/            OPC_CheckCondCode, ISD::SETUGE,
/* 10277*/            OPC_MoveParent,
/* 10278*/            OPC_CheckType, MVT::i32,
/* 10280*/            OPC_Scope, 21, /*->10303*/ // 2 children in Scope
/* 10282*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 10284*/              OPC_EmitNode1, TARGET_VAL(RISCV::SLTU), 0,
                            MVT::i32, 2/*#Ops*/, 0, 1,  // Results = #2
/* 10292*/              OPC_EmitInteger, MVT::i32, 1, 
/* 10295*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETUGE:{ *:[Other] }) - Complexity = 3
                        // Dst: (XORI:{ *:[i32] } (SLTU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2), 1:{ *:[i32] })
/* 10303*/            /*Scope*/ 19, /*->10323*/
/* 10304*/              OPC_EmitNode1, TARGET_VAL(RISCV::SLTU), 0,
                            MVT::i32, 2/*#Ops*/, 0, 1,  // Results = #2
/* 10312*/              OPC_EmitInteger, MVT::i32, 1, 
/* 10315*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETUGE:{ *:[Other] }) - Complexity = 3
                        // Dst: (XORI:{ *:[i32] } (SLTU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2), 1:{ *:[i32] })
/* 10323*/            0, /*End of Scope*/
/* 10324*/          /*Scope*/ 49, /*->10374*/
/* 10325*/            OPC_CheckCondCode, ISD::SETULE,
/* 10327*/            OPC_MoveParent,
/* 10328*/            OPC_CheckType, MVT::i32,
/* 10330*/            OPC_Scope, 21, /*->10353*/ // 2 children in Scope
/* 10332*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 10334*/              OPC_EmitNode1, TARGET_VAL(RISCV::SLTU), 0,
                            MVT::i32, 2/*#Ops*/, 1, 0,  // Results = #2
/* 10342*/              OPC_EmitInteger, MVT::i32, 1, 
/* 10345*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETULE:{ *:[Other] }) - Complexity = 3
                        // Dst: (XORI:{ *:[i32] } (SLTU:{ *:[i32] } GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1), 1:{ *:[i32] })
/* 10353*/            /*Scope*/ 19, /*->10373*/
/* 10354*/              OPC_EmitNode1, TARGET_VAL(RISCV::SLTU), 0,
                            MVT::i32, 2/*#Ops*/, 1, 0,  // Results = #2
/* 10362*/              OPC_EmitInteger, MVT::i32, 1, 
/* 10365*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETULE:{ *:[Other] }) - Complexity = 3
                        // Dst: (XORI:{ *:[i32] } (SLTU:{ *:[i32] } GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1), 1:{ *:[i32] })
/* 10373*/            0, /*End of Scope*/
/* 10374*/          /*Scope*/ 49, /*->10424*/
/* 10375*/            OPC_CheckCondCode, ISD::SETGE,
/* 10377*/            OPC_MoveParent,
/* 10378*/            OPC_CheckType, MVT::i32,
/* 10380*/            OPC_Scope, 21, /*->10403*/ // 2 children in Scope
/* 10382*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 10384*/              OPC_EmitNode1, TARGET_VAL(RISCV::SLT), 0,
                            MVT::i32, 2/*#Ops*/, 0, 1,  // Results = #2
/* 10392*/              OPC_EmitInteger, MVT::i32, 1, 
/* 10395*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETGE:{ *:[Other] }) - Complexity = 3
                        // Dst: (XORI:{ *:[i32] } (SLT:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2), 1:{ *:[i32] })
/* 10403*/            /*Scope*/ 19, /*->10423*/
/* 10404*/              OPC_EmitNode1, TARGET_VAL(RISCV::SLT), 0,
                            MVT::i32, 2/*#Ops*/, 0, 1,  // Results = #2
/* 10412*/              OPC_EmitInteger, MVT::i32, 1, 
/* 10415*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETGE:{ *:[Other] }) - Complexity = 3
                        // Dst: (XORI:{ *:[i32] } (SLT:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2), 1:{ *:[i32] })
/* 10423*/            0, /*End of Scope*/
/* 10424*/          /*Scope*/ 49, /*->10474*/
/* 10425*/            OPC_CheckCondCode, ISD::SETLE,
/* 10427*/            OPC_MoveParent,
/* 10428*/            OPC_CheckType, MVT::i32,
/* 10430*/            OPC_Scope, 21, /*->10453*/ // 2 children in Scope
/* 10432*/              OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 10434*/              OPC_EmitNode1, TARGET_VAL(RISCV::SLT), 0,
                            MVT::i32, 2/*#Ops*/, 1, 0,  // Results = #2
/* 10442*/              OPC_EmitInteger, MVT::i32, 1, 
/* 10445*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETLE:{ *:[Other] }) - Complexity = 3
                        // Dst: (XORI:{ *:[i32] } (SLT:{ *:[i32] } GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1), 1:{ *:[i32] })
/* 10453*/            /*Scope*/ 19, /*->10473*/
/* 10454*/              OPC_EmitNode1, TARGET_VAL(RISCV::SLT), 0,
                            MVT::i32, 2/*#Ops*/, 1, 0,  // Results = #2
/* 10462*/              OPC_EmitInteger, MVT::i32, 1, 
/* 10465*/              OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                            MVT::i32, 2/*#Ops*/, 2, 3, 
                        // Src: (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETLE:{ *:[Other] }) - Complexity = 3
                        // Dst: (XORI:{ *:[i32] } (SLT:{ *:[i32] } GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1), 1:{ *:[i32] })
/* 10473*/            0, /*End of Scope*/
/* 10474*/          0, /*End of Scope*/
/* 10475*/        0, /*End of Scope*/
/* 10476*/      0, /*End of Scope*/
/* 10477*/    /*Scope*/ 75|128,2/*331*/, /*->10810*/
/* 10479*/      OPC_CheckChild0Type, MVT::i64,
/* 10481*/      OPC_Scope, 43, /*->10526*/ // 2 children in Scope
/* 10483*/        OPC_CheckChild1Integer, 0, 
/* 10485*/        OPC_MoveChild2,
/* 10486*/        OPC_Scope, 18, /*->10506*/ // 2 children in Scope
/* 10488*/          OPC_CheckCondCode, ISD::SETEQ,
/* 10490*/          OPC_MoveParent,
/* 10491*/          OPC_CheckType, MVT::i64,
/* 10493*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10495*/          OPC_EmitInteger, MVT::i64, 1, 
/* 10498*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] }, SETEQ:{ *:[Other] }) - Complexity = 8
                    // Dst: (SLTIU:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 1:{ *:[i64] })
/* 10506*/        /*Scope*/ 18, /*->10525*/
/* 10507*/          OPC_CheckCondCode, ISD::SETNE,
/* 10509*/          OPC_MoveParent,
/* 10510*/          OPC_CheckType, MVT::i64,
/* 10512*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10514*/          OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 10517*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTU), 0,
                        MVT::i64, 2/*#Ops*/, 1, 0, 
                    // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 0:{ *:[i64] }, SETNE:{ *:[Other] }) - Complexity = 8
                    // Dst: (SLTU:{ *:[i64] } X0:{ *:[i64] }, GPR:{ *:[i64] }:$rs1)
/* 10525*/        0, /*End of Scope*/
/* 10526*/      /*Scope*/ 25|128,2/*281*/, /*->10809*/
/* 10528*/        OPC_RecordChild1, // #1 = $imm12
/* 10529*/        OPC_Scope, 46, /*->10577*/ // 2 children in Scope
/* 10531*/          OPC_MoveChild1,
/* 10532*/          OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/* 10535*/          OPC_CheckPredicate, 0, // Predicate_simm12
/* 10537*/          OPC_MoveParent,
/* 10538*/          OPC_MoveChild2,
/* 10539*/          OPC_Scope, 17, /*->10558*/ // 2 children in Scope
/* 10541*/            OPC_CheckCondCode, ISD::SETLT,
/* 10543*/            OPC_MoveParent,
/* 10544*/            OPC_CheckType, MVT::i64,
/* 10546*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10548*/            OPC_EmitConvertToTarget, 1,
/* 10550*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTI), 0,
                          MVT::i64, 2/*#Ops*/, 0, 2, 
                      // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12, SETLT:{ *:[Other] }) - Complexity = 7
                      // Dst: (SLTI:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/* 10558*/          /*Scope*/ 17, /*->10576*/
/* 10559*/            OPC_CheckCondCode, ISD::SETULT,
/* 10561*/            OPC_MoveParent,
/* 10562*/            OPC_CheckType, MVT::i64,
/* 10564*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10566*/            OPC_EmitConvertToTarget, 1,
/* 10568*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                          MVT::i64, 2/*#Ops*/, 0, 2, 
                      // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12, SETULT:{ *:[Other] }) - Complexity = 7
                      // Dst: (SLTIU:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/* 10576*/          0, /*End of Scope*/
/* 10577*/        /*Scope*/ 101|128,1/*229*/, /*->10808*/
/* 10579*/          OPC_MoveChild2,
/* 10580*/          OPC_Scope, 15, /*->10597*/ // 10 children in Scope
/* 10582*/            OPC_CheckCondCode, ISD::SETLT,
/* 10584*/            OPC_MoveParent,
/* 10585*/            OPC_CheckType, MVT::i64,
/* 10587*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10589*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLT), 0,
                          MVT::i64, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETLT:{ *:[Other] }) - Complexity = 3
                      // Dst: (SLT:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 10597*/          /*Scope*/ 15, /*->10613*/
/* 10598*/            OPC_CheckCondCode, ISD::SETULT,
/* 10600*/            OPC_MoveParent,
/* 10601*/            OPC_CheckType, MVT::i64,
/* 10603*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10605*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTU), 0,
                          MVT::i64, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETULT:{ *:[Other] }) - Complexity = 3
                      // Dst: (SLTU:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 10613*/          /*Scope*/ 15, /*->10629*/
/* 10614*/            OPC_CheckCondCode, ISD::SETUGT,
/* 10616*/            OPC_MoveParent,
/* 10617*/            OPC_CheckType, MVT::i64,
/* 10619*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10621*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTU), 0,
                          MVT::i64, 2/*#Ops*/, 1, 0, 
                      // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETUGT:{ *:[Other] }) - Complexity = 3
                      // Dst: (SLTU:{ *:[i64] } GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1)
/* 10629*/          /*Scope*/ 15, /*->10645*/
/* 10630*/            OPC_CheckCondCode, ISD::SETGT,
/* 10632*/            OPC_MoveParent,
/* 10633*/            OPC_CheckType, MVT::i64,
/* 10635*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10637*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLT), 0,
                          MVT::i64, 2/*#Ops*/, 1, 0, 
                      // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETGT:{ *:[Other] }) - Complexity = 3
                      // Dst: (SLT:{ *:[i64] } GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1)
/* 10645*/          /*Scope*/ 26, /*->10672*/
/* 10646*/            OPC_CheckCondCode, ISD::SETEQ,
/* 10648*/            OPC_MoveParent,
/* 10649*/            OPC_CheckType, MVT::i64,
/* 10651*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10653*/            OPC_EmitNode1, TARGET_VAL(RISCV::XOR), 0,
                          MVT::i64, 2/*#Ops*/, 0, 1,  // Results = #2
/* 10661*/            OPC_EmitInteger, MVT::i64, 1, 
/* 10664*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                          MVT::i64, 2/*#Ops*/, 2, 3, 
                      // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETEQ:{ *:[Other] }) - Complexity = 3
                      // Dst: (SLTIU:{ *:[i64] } (XOR:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2), 1:{ *:[i64] })
/* 10672*/          /*Scope*/ 26, /*->10699*/
/* 10673*/            OPC_CheckCondCode, ISD::SETNE,
/* 10675*/            OPC_MoveParent,
/* 10676*/            OPC_CheckType, MVT::i64,
/* 10678*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10680*/            OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 10683*/            OPC_EmitNode1, TARGET_VAL(RISCV::XOR), 0,
                          MVT::i64, 2/*#Ops*/, 0, 1,  // Results = #3
/* 10691*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTU), 0,
                          MVT::i64, 2/*#Ops*/, 2, 3, 
                      // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETNE:{ *:[Other] }) - Complexity = 3
                      // Dst: (SLTU:{ *:[i64] } X0:{ *:[i64] }, (XOR:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2))
/* 10699*/          /*Scope*/ 26, /*->10726*/
/* 10700*/            OPC_CheckCondCode, ISD::SETUGE,
/* 10702*/            OPC_MoveParent,
/* 10703*/            OPC_CheckType, MVT::i64,
/* 10705*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10707*/            OPC_EmitNode1, TARGET_VAL(RISCV::SLTU), 0,
                          MVT::i64, 2/*#Ops*/, 0, 1,  // Results = #2
/* 10715*/            OPC_EmitInteger, MVT::i64, 1, 
/* 10718*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                          MVT::i64, 2/*#Ops*/, 2, 3, 
                      // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETUGE:{ *:[Other] }) - Complexity = 3
                      // Dst: (XORI:{ *:[i64] } (SLTU:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2), 1:{ *:[i64] })
/* 10726*/          /*Scope*/ 26, /*->10753*/
/* 10727*/            OPC_CheckCondCode, ISD::SETULE,
/* 10729*/            OPC_MoveParent,
/* 10730*/            OPC_CheckType, MVT::i64,
/* 10732*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10734*/            OPC_EmitNode1, TARGET_VAL(RISCV::SLTU), 0,
                          MVT::i64, 2/*#Ops*/, 1, 0,  // Results = #2
/* 10742*/            OPC_EmitInteger, MVT::i64, 1, 
/* 10745*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                          MVT::i64, 2/*#Ops*/, 2, 3, 
                      // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETULE:{ *:[Other] }) - Complexity = 3
                      // Dst: (XORI:{ *:[i64] } (SLTU:{ *:[i64] } GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1), 1:{ *:[i64] })
/* 10753*/          /*Scope*/ 26, /*->10780*/
/* 10754*/            OPC_CheckCondCode, ISD::SETGE,
/* 10756*/            OPC_MoveParent,
/* 10757*/            OPC_CheckType, MVT::i64,
/* 10759*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10761*/            OPC_EmitNode1, TARGET_VAL(RISCV::SLT), 0,
                          MVT::i64, 2/*#Ops*/, 0, 1,  // Results = #2
/* 10769*/            OPC_EmitInteger, MVT::i64, 1, 
/* 10772*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                          MVT::i64, 2/*#Ops*/, 2, 3, 
                      // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETGE:{ *:[Other] }) - Complexity = 3
                      // Dst: (XORI:{ *:[i64] } (SLT:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2), 1:{ *:[i64] })
/* 10780*/          /*Scope*/ 26, /*->10807*/
/* 10781*/            OPC_CheckCondCode, ISD::SETLE,
/* 10783*/            OPC_MoveParent,
/* 10784*/            OPC_CheckType, MVT::i64,
/* 10786*/            OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 10788*/            OPC_EmitNode1, TARGET_VAL(RISCV::SLT), 0,
                          MVT::i64, 2/*#Ops*/, 1, 0,  // Results = #2
/* 10796*/            OPC_EmitInteger, MVT::i64, 1, 
/* 10799*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                          MVT::i64, 2/*#Ops*/, 2, 3, 
                      // Src: (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETLE:{ *:[Other] }) - Complexity = 3
                      // Dst: (XORI:{ *:[i64] } (SLT:{ *:[i64] } GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1), 1:{ *:[i64] })
/* 10807*/          0, /*End of Scope*/
/* 10808*/        0, /*End of Scope*/
/* 10809*/      0, /*End of Scope*/
/* 10810*/    /*Scope*/ 11|128,3/*395*/, /*->11207*/
/* 10812*/      OPC_CheckChild0Type, MVT::f32,
/* 10814*/      OPC_RecordChild1, // #1 = $rs2
/* 10815*/      OPC_MoveChild2,
/* 10816*/      OPC_Scope, 43, /*->10861*/ // 7 children in Scope
/* 10818*/        OPC_CheckCondCode, ISD::SETEQ,
/* 10820*/        OPC_MoveParent,
/* 10821*/        OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->10848
/* 10824*/          OPC_Scope, 10, /*->10836*/ // 2 children in Scope
/* 10826*/            OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 10828*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FEQ_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETEQ:{ *:[Other] }) - Complexity = 3
                      // Dst: (FEQ_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 10836*/          /*Scope*/ 10, /*->10847*/
/* 10837*/            OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 10839*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FEQ_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETEQ:{ *:[Other] }) - Complexity = 3
                      // Dst: (FEQ_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 10847*/          0, /*End of Scope*/
/* 10848*/        /*SwitchType*/ 10, MVT::i64,// ->10860
/* 10850*/          OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 10852*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FEQ_S), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (setcc:{ *:[i64] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETEQ:{ *:[Other] }) - Complexity = 3
                    // Dst: (FEQ_S:{ *:[i64] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 10860*/        0, // EndSwitchType
/* 10861*/      /*Scope*/ 43, /*->10905*/
/* 10862*/        OPC_CheckCondCode, ISD::SETOEQ,
/* 10864*/        OPC_MoveParent,
/* 10865*/        OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->10892
/* 10868*/          OPC_Scope, 10, /*->10880*/ // 2 children in Scope
/* 10870*/            OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 10872*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FEQ_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETOEQ:{ *:[Other] }) - Complexity = 3
                      // Dst: (FEQ_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 10880*/          /*Scope*/ 10, /*->10891*/
/* 10881*/            OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 10883*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FEQ_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETOEQ:{ *:[Other] }) - Complexity = 3
                      // Dst: (FEQ_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 10891*/          0, /*End of Scope*/
/* 10892*/        /*SwitchType*/ 10, MVT::i64,// ->10904
/* 10894*/          OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 10896*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FEQ_S), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (setcc:{ *:[i64] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETOEQ:{ *:[Other] }) - Complexity = 3
                    // Dst: (FEQ_S:{ *:[i64] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 10904*/        0, // EndSwitchType
/* 10905*/      /*Scope*/ 43, /*->10949*/
/* 10906*/        OPC_CheckCondCode, ISD::SETLT,
/* 10908*/        OPC_MoveParent,
/* 10909*/        OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->10936
/* 10912*/          OPC_Scope, 10, /*->10924*/ // 2 children in Scope
/* 10914*/            OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 10916*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLT_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETLT:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLT_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 10924*/          /*Scope*/ 10, /*->10935*/
/* 10925*/            OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 10927*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLT_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETLT:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLT_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 10935*/          0, /*End of Scope*/
/* 10936*/        /*SwitchType*/ 10, MVT::i64,// ->10948
/* 10938*/          OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 10940*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLT_S), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (setcc:{ *:[i64] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETLT:{ *:[Other] }) - Complexity = 3
                    // Dst: (FLT_S:{ *:[i64] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 10948*/        0, // EndSwitchType
/* 10949*/      /*Scope*/ 43, /*->10993*/
/* 10950*/        OPC_CheckCondCode, ISD::SETOLT,
/* 10952*/        OPC_MoveParent,
/* 10953*/        OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->10980
/* 10956*/          OPC_Scope, 10, /*->10968*/ // 2 children in Scope
/* 10958*/            OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 10960*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLT_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETOLT:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLT_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 10968*/          /*Scope*/ 10, /*->10979*/
/* 10969*/            OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 10971*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLT_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETOLT:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLT_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 10979*/          0, /*End of Scope*/
/* 10980*/        /*SwitchType*/ 10, MVT::i64,// ->10992
/* 10982*/          OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 10984*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLT_S), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (setcc:{ *:[i64] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETOLT:{ *:[Other] }) - Complexity = 3
                    // Dst: (FLT_S:{ *:[i64] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 10992*/        0, // EndSwitchType
/* 10993*/      /*Scope*/ 43, /*->11037*/
/* 10994*/        OPC_CheckCondCode, ISD::SETLE,
/* 10996*/        OPC_MoveParent,
/* 10997*/        OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->11024
/* 11000*/          OPC_Scope, 10, /*->11012*/ // 2 children in Scope
/* 11002*/            OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 11004*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLE_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETLE:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLE_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 11012*/          /*Scope*/ 10, /*->11023*/
/* 11013*/            OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 11015*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLE_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETLE:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLE_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 11023*/          0, /*End of Scope*/
/* 11024*/        /*SwitchType*/ 10, MVT::i64,// ->11036
/* 11026*/          OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 11028*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLE_S), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (setcc:{ *:[i64] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETLE:{ *:[Other] }) - Complexity = 3
                    // Dst: (FLE_S:{ *:[i64] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 11036*/        0, // EndSwitchType
/* 11037*/      /*Scope*/ 43, /*->11081*/
/* 11038*/        OPC_CheckCondCode, ISD::SETOLE,
/* 11040*/        OPC_MoveParent,
/* 11041*/        OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->11068
/* 11044*/          OPC_Scope, 10, /*->11056*/ // 2 children in Scope
/* 11046*/            OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 11048*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLE_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETOLE:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLE_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 11056*/          /*Scope*/ 10, /*->11067*/
/* 11057*/            OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 11059*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLE_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETOLE:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLE_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 11067*/          0, /*End of Scope*/
/* 11068*/        /*SwitchType*/ 10, MVT::i64,// ->11080
/* 11070*/          OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 11072*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLE_S), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (setcc:{ *:[i64] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETOLE:{ *:[Other] }) - Complexity = 3
                    // Dst: (FLE_S:{ *:[i64] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 11080*/        0, // EndSwitchType
/* 11081*/      /*Scope*/ 124, /*->11206*/
/* 11082*/        OPC_CheckCondCode, ISD::SETUO,
/* 11084*/        OPC_MoveParent,
/* 11085*/        OPC_SwitchType /*2 cases */, 78, MVT::i32,// ->11166
/* 11088*/          OPC_Scope, 37, /*->11127*/ // 2 children in Scope
/* 11090*/            OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 11092*/            OPC_EmitNode1, TARGET_VAL(RISCV::FEQ_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 0,  // Results = #2
/* 11100*/            OPC_EmitNode1, TARGET_VAL(RISCV::FEQ_S), 0,
                          MVT::i32, 2/*#Ops*/, 1, 1,  // Results = #3
/* 11108*/            OPC_EmitNode1, TARGET_VAL(RISCV::AND), 0,
                          MVT::i32, 2/*#Ops*/, 2, 3,  // Results = #4
/* 11116*/            OPC_EmitInteger, MVT::i32, 1, 
/* 11119*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                          MVT::i32, 2/*#Ops*/, 4, 5, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETUO:{ *:[Other] }) - Complexity = 3
                      // Dst: (SLTIU:{ *:[i32] } (AND:{ *:[i32] } (FEQ_S:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs1), (FEQ_S:{ *:[i32] } FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs2)), 1:{ *:[i32] })
/* 11127*/          /*Scope*/ 37, /*->11165*/
/* 11128*/            OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 11130*/            OPC_EmitNode1, TARGET_VAL(RISCV::FEQ_S), 0,
                          MVT::i32, 2/*#Ops*/, 0, 0,  // Results = #2
/* 11138*/            OPC_EmitNode1, TARGET_VAL(RISCV::FEQ_S), 0,
                          MVT::i32, 2/*#Ops*/, 1, 1,  // Results = #3
/* 11146*/            OPC_EmitNode1, TARGET_VAL(RISCV::AND), 0,
                          MVT::i32, 2/*#Ops*/, 2, 3,  // Results = #4
/* 11154*/            OPC_EmitInteger, MVT::i32, 1, 
/* 11157*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                          MVT::i32, 2/*#Ops*/, 4, 5, 
                      // Src: (setcc:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETUO:{ *:[Other] }) - Complexity = 3
                      // Dst: (SLTIU:{ *:[i32] } (AND:{ *:[i32] } (FEQ_S:{ *:[i32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs1), (FEQ_S:{ *:[i32] } FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs2)), 1:{ *:[i32] })
/* 11165*/          0, /*End of Scope*/
/* 11166*/        /*SwitchType*/ 37, MVT::i64,// ->11205
/* 11168*/          OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 11170*/          OPC_EmitNode1, TARGET_VAL(RISCV::FEQ_S), 0,
                        MVT::i64, 2/*#Ops*/, 0, 0,  // Results = #2
/* 11178*/          OPC_EmitNode1, TARGET_VAL(RISCV::FEQ_S), 0,
                        MVT::i64, 2/*#Ops*/, 1, 1,  // Results = #3
/* 11186*/          OPC_EmitNode1, TARGET_VAL(RISCV::AND), 0,
                        MVT::i64, 2/*#Ops*/, 2, 3,  // Results = #4
/* 11194*/          OPC_EmitInteger, MVT::i64, 1, 
/* 11197*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                        MVT::i64, 2/*#Ops*/, 4, 5, 
                    // Src: (setcc:{ *:[i64] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, SETUO:{ *:[Other] }) - Complexity = 3
                    // Dst: (SLTIU:{ *:[i64] } (AND:{ *:[i64] } (FEQ_S:{ *:[i64] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs1), (FEQ_S:{ *:[i64] } FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs2)), 1:{ *:[i64] })
/* 11205*/        0, // EndSwitchType
/* 11206*/      0, /*End of Scope*/
/* 11207*/    /*Scope*/ 11|128,3/*395*/, /*->11604*/
/* 11209*/      OPC_CheckChild0Type, MVT::f64,
/* 11211*/      OPC_RecordChild1, // #1 = $rs2
/* 11212*/      OPC_MoveChild2,
/* 11213*/      OPC_Scope, 43, /*->11258*/ // 7 children in Scope
/* 11215*/        OPC_CheckCondCode, ISD::SETEQ,
/* 11217*/        OPC_MoveParent,
/* 11218*/        OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->11245
/* 11221*/          OPC_Scope, 10, /*->11233*/ // 2 children in Scope
/* 11223*/            OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 11225*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FEQ_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETEQ:{ *:[Other] }) - Complexity = 3
                      // Dst: (FEQ_D:{ *:[i32] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11233*/          /*Scope*/ 10, /*->11244*/
/* 11234*/            OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 11236*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FEQ_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETEQ:{ *:[Other] }) - Complexity = 3
                      // Dst: (FEQ_D:{ *:[i32] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11244*/          0, /*End of Scope*/
/* 11245*/        /*SwitchType*/ 10, MVT::i64,// ->11257
/* 11247*/          OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 11249*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FEQ_D), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (setcc:{ *:[i64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETEQ:{ *:[Other] }) - Complexity = 3
                    // Dst: (FEQ_D:{ *:[i64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11257*/        0, // EndSwitchType
/* 11258*/      /*Scope*/ 43, /*->11302*/
/* 11259*/        OPC_CheckCondCode, ISD::SETOEQ,
/* 11261*/        OPC_MoveParent,
/* 11262*/        OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->11289
/* 11265*/          OPC_Scope, 10, /*->11277*/ // 2 children in Scope
/* 11267*/            OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 11269*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FEQ_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETOEQ:{ *:[Other] }) - Complexity = 3
                      // Dst: (FEQ_D:{ *:[i32] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11277*/          /*Scope*/ 10, /*->11288*/
/* 11278*/            OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 11280*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FEQ_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETOEQ:{ *:[Other] }) - Complexity = 3
                      // Dst: (FEQ_D:{ *:[i32] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11288*/          0, /*End of Scope*/
/* 11289*/        /*SwitchType*/ 10, MVT::i64,// ->11301
/* 11291*/          OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 11293*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FEQ_D), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (setcc:{ *:[i64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETOEQ:{ *:[Other] }) - Complexity = 3
                    // Dst: (FEQ_D:{ *:[i64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11301*/        0, // EndSwitchType
/* 11302*/      /*Scope*/ 43, /*->11346*/
/* 11303*/        OPC_CheckCondCode, ISD::SETLT,
/* 11305*/        OPC_MoveParent,
/* 11306*/        OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->11333
/* 11309*/          OPC_Scope, 10, /*->11321*/ // 2 children in Scope
/* 11311*/            OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 11313*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLT_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETLT:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLT_D:{ *:[i32] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11321*/          /*Scope*/ 10, /*->11332*/
/* 11322*/            OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 11324*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLT_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETLT:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLT_D:{ *:[i32] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11332*/          0, /*End of Scope*/
/* 11333*/        /*SwitchType*/ 10, MVT::i64,// ->11345
/* 11335*/          OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 11337*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLT_D), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (setcc:{ *:[i64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETLT:{ *:[Other] }) - Complexity = 3
                    // Dst: (FLT_D:{ *:[i64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11345*/        0, // EndSwitchType
/* 11346*/      /*Scope*/ 43, /*->11390*/
/* 11347*/        OPC_CheckCondCode, ISD::SETOLT,
/* 11349*/        OPC_MoveParent,
/* 11350*/        OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->11377
/* 11353*/          OPC_Scope, 10, /*->11365*/ // 2 children in Scope
/* 11355*/            OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 11357*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLT_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETOLT:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLT_D:{ *:[i32] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11365*/          /*Scope*/ 10, /*->11376*/
/* 11366*/            OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 11368*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLT_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETOLT:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLT_D:{ *:[i32] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11376*/          0, /*End of Scope*/
/* 11377*/        /*SwitchType*/ 10, MVT::i64,// ->11389
/* 11379*/          OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 11381*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLT_D), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (setcc:{ *:[i64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETOLT:{ *:[Other] }) - Complexity = 3
                    // Dst: (FLT_D:{ *:[i64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11389*/        0, // EndSwitchType
/* 11390*/      /*Scope*/ 43, /*->11434*/
/* 11391*/        OPC_CheckCondCode, ISD::SETLE,
/* 11393*/        OPC_MoveParent,
/* 11394*/        OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->11421
/* 11397*/          OPC_Scope, 10, /*->11409*/ // 2 children in Scope
/* 11399*/            OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 11401*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLE_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETLE:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLE_D:{ *:[i32] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11409*/          /*Scope*/ 10, /*->11420*/
/* 11410*/            OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 11412*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLE_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETLE:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLE_D:{ *:[i32] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11420*/          0, /*End of Scope*/
/* 11421*/        /*SwitchType*/ 10, MVT::i64,// ->11433
/* 11423*/          OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 11425*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLE_D), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (setcc:{ *:[i64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETLE:{ *:[Other] }) - Complexity = 3
                    // Dst: (FLE_D:{ *:[i64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11433*/        0, // EndSwitchType
/* 11434*/      /*Scope*/ 43, /*->11478*/
/* 11435*/        OPC_CheckCondCode, ISD::SETOLE,
/* 11437*/        OPC_MoveParent,
/* 11438*/        OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->11465
/* 11441*/          OPC_Scope, 10, /*->11453*/ // 2 children in Scope
/* 11443*/            OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 11445*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLE_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETOLE:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLE_D:{ *:[i32] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11453*/          /*Scope*/ 10, /*->11464*/
/* 11454*/            OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 11456*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLE_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 1, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETOLE:{ *:[Other] }) - Complexity = 3
                      // Dst: (FLE_D:{ *:[i32] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11464*/          0, /*End of Scope*/
/* 11465*/        /*SwitchType*/ 10, MVT::i64,// ->11477
/* 11467*/          OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 11469*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FLE_D), 0,
                        MVT::i64, 2/*#Ops*/, 0, 1, 
                    // Src: (setcc:{ *:[i64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETOLE:{ *:[Other] }) - Complexity = 3
                    // Dst: (FLE_D:{ *:[i64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 11477*/        0, // EndSwitchType
/* 11478*/      /*Scope*/ 124, /*->11603*/
/* 11479*/        OPC_CheckCondCode, ISD::SETUO,
/* 11481*/        OPC_MoveParent,
/* 11482*/        OPC_SwitchType /*2 cases */, 78, MVT::i32,// ->11563
/* 11485*/          OPC_Scope, 37, /*->11524*/ // 2 children in Scope
/* 11487*/            OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 11489*/            OPC_EmitNode1, TARGET_VAL(RISCV::FEQ_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 0,  // Results = #2
/* 11497*/            OPC_EmitNode1, TARGET_VAL(RISCV::FEQ_D), 0,
                          MVT::i32, 2/*#Ops*/, 1, 1,  // Results = #3
/* 11505*/            OPC_EmitNode1, TARGET_VAL(RISCV::AND), 0,
                          MVT::i32, 2/*#Ops*/, 2, 3,  // Results = #4
/* 11513*/            OPC_EmitInteger, MVT::i32, 1, 
/* 11516*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                          MVT::i32, 2/*#Ops*/, 4, 5, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETUO:{ *:[Other] }) - Complexity = 3
                      // Dst: (SLTIU:{ *:[i32] } (AND:{ *:[i32] } (FEQ_D:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs1), (FEQ_D:{ *:[i32] } FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs2)), 1:{ *:[i32] })
/* 11524*/          /*Scope*/ 37, /*->11562*/
/* 11525*/            OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 11527*/            OPC_EmitNode1, TARGET_VAL(RISCV::FEQ_D), 0,
                          MVT::i32, 2/*#Ops*/, 0, 0,  // Results = #2
/* 11535*/            OPC_EmitNode1, TARGET_VAL(RISCV::FEQ_D), 0,
                          MVT::i32, 2/*#Ops*/, 1, 1,  // Results = #3
/* 11543*/            OPC_EmitNode1, TARGET_VAL(RISCV::AND), 0,
                          MVT::i32, 2/*#Ops*/, 2, 3,  // Results = #4
/* 11551*/            OPC_EmitInteger, MVT::i32, 1, 
/* 11554*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                          MVT::i32, 2/*#Ops*/, 4, 5, 
                      // Src: (setcc:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETUO:{ *:[Other] }) - Complexity = 3
                      // Dst: (SLTIU:{ *:[i32] } (AND:{ *:[i32] } (FEQ_D:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs1), (FEQ_D:{ *:[i32] } FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs2)), 1:{ *:[i32] })
/* 11562*/          0, /*End of Scope*/
/* 11563*/        /*SwitchType*/ 37, MVT::i64,// ->11602
/* 11565*/          OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 11567*/          OPC_EmitNode1, TARGET_VAL(RISCV::FEQ_D), 0,
                        MVT::i64, 2/*#Ops*/, 0, 0,  // Results = #2
/* 11575*/          OPC_EmitNode1, TARGET_VAL(RISCV::FEQ_D), 0,
                        MVT::i64, 2/*#Ops*/, 1, 1,  // Results = #3
/* 11583*/          OPC_EmitNode1, TARGET_VAL(RISCV::AND), 0,
                        MVT::i64, 2/*#Ops*/, 2, 3,  // Results = #4
/* 11591*/          OPC_EmitInteger, MVT::i64, 1, 
/* 11594*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SLTIU), 0,
                        MVT::i64, 2/*#Ops*/, 4, 5, 
                    // Src: (setcc:{ *:[i64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, SETUO:{ *:[Other] }) - Complexity = 3
                    // Dst: (SLTIU:{ *:[i64] } (AND:{ *:[i64] } (FEQ_D:{ *:[i64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs1), (FEQ_D:{ *:[i64] } FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs2)), 1:{ *:[i64] })
/* 11602*/        0, // EndSwitchType
/* 11603*/      0, /*End of Scope*/
/* 11604*/    0, /*End of Scope*/
/* 11605*/  /*SwitchOpcode*/ 59|128,1/*187*/, TARGET_VAL(ISD::AND),// ->11796
/* 11609*/    OPC_Scope, 89, /*->11700*/ // 2 children in Scope
/* 11611*/      OPC_CheckAndImm, 127|128,127|128,127|128,127|128,15/*4294967295*/, 
/* 11617*/      OPC_RecordChild0, // #0 = $rs1
/* 11618*/      OPC_SwitchType /*2 cases */, 52, MVT::i32,// ->11673
/* 11621*/        OPC_Scope, 24, /*->11647*/ // 2 children in Scope
/* 11623*/          OPC_CheckPatternPredicate, 3, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 11625*/          OPC_EmitInteger, MVT::i32, 32, 
/* 11628*/          OPC_EmitNode1, TARGET_VAL(RISCV::SLLI), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1,  // Results = #2
/* 11636*/          OPC_EmitInteger, MVT::i32, 32, 
/* 11639*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRLI), 0,
                        MVT::i32, 2/*#Ops*/, 2, 3, 
                    // Src: (and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 4294967295:{ *:[i32] }) - Complexity = 8
                    // Dst: (SRLI:{ *:[i32] } (SLLI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 32:{ *:[i32] }), 32:{ *:[i32] })
/* 11647*/        /*Scope*/ 24, /*->11672*/
/* 11648*/          OPC_CheckPatternPredicate, 4, // (Subtarget->is64Bit())
/* 11650*/          OPC_EmitInteger, MVT::i32, 32, 
/* 11653*/          OPC_EmitNode1, TARGET_VAL(RISCV::SLLI), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1,  // Results = #2
/* 11661*/          OPC_EmitInteger, MVT::i32, 32, 
/* 11664*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRLI), 0,
                        MVT::i32, 2/*#Ops*/, 2, 3, 
                    // Src: (and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 4294967295:{ *:[i32] }) - Complexity = 8
                    // Dst: (SRLI:{ *:[i32] } (SLLI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, 32:{ *:[i32] }), 32:{ *:[i32] })
/* 11672*/        0, /*End of Scope*/
/* 11673*/      /*SwitchType*/ 24, MVT::i64,// ->11699
/* 11675*/        OPC_CheckPatternPredicate, 7, // (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 11677*/        OPC_EmitInteger, MVT::i64, 32, 
/* 11680*/        OPC_EmitNode1, TARGET_VAL(RISCV::SLLI), 0,
                      MVT::i64, 2/*#Ops*/, 0, 1,  // Results = #2
/* 11688*/        OPC_EmitInteger, MVT::i64, 32, 
/* 11691*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::SRLI), 0,
                      MVT::i64, 2/*#Ops*/, 2, 3, 
                  // Src: (and:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 4294967295:{ *:[i64] }) - Complexity = 8
                  // Dst: (SRLI:{ *:[i64] } (SLLI:{ *:[i64] } GPR:{ *:[i64] }:$rs1, 32:{ *:[i64] }), 32:{ *:[i64] })
/* 11699*/      0, // EndSwitchType
/* 11700*/    /*Scope*/ 94, /*->11795*/
/* 11701*/      OPC_RecordChild0, // #0 = $rs1
/* 11702*/      OPC_RecordChild1, // #1 = $imm12
/* 11703*/      OPC_Scope, 51, /*->11756*/ // 3 children in Scope
/* 11705*/        OPC_MoveChild1,
/* 11706*/        OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/* 11709*/        OPC_CheckPredicate, 0, // Predicate_simm12
/* 11711*/        OPC_MoveParent,
/* 11712*/        OPC_SwitchType /*2 cases */, 26, MVT::i32,// ->11741
/* 11715*/          OPC_Scope, 12, /*->11729*/ // 2 children in Scope
/* 11717*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 11719*/            OPC_EmitConvertToTarget, 1,
/* 11721*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::ANDI), 0,
                          MVT::i32, 2/*#Ops*/, 0, 2, 
                      // Src: (and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12) - Complexity = 7
                      // Dst: (ANDI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/* 11729*/          /*Scope*/ 10, /*->11740*/
/* 11730*/            OPC_EmitConvertToTarget, 1,
/* 11732*/            OPC_MorphNodeTo1, TARGET_VAL(RISCV::ANDI), 0,
                          MVT::i32, 2/*#Ops*/, 0, 2, 
                      // Src: (and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12) - Complexity = 7
                      // Dst: (ANDI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/* 11740*/          0, /*End of Scope*/
/* 11741*/        /*SwitchType*/ 12, MVT::i64,// ->11755
/* 11743*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 11745*/          OPC_EmitConvertToTarget, 1,
/* 11747*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::ANDI), 0,
                        MVT::i64, 2/*#Ops*/, 0, 2, 
                    // Src: (and:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12) - Complexity = 7
                    // Dst: (ANDI:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/* 11755*/        0, // EndSwitchType
/* 11756*/      /*Scope*/ 24, /*->11781*/
/* 11757*/        OPC_CheckType, MVT::i32,
/* 11759*/        OPC_Scope, 10, /*->11771*/ // 2 children in Scope
/* 11761*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 11763*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AND), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                    // Dst: (AND:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 11771*/        /*Scope*/ 8, /*->11780*/
/* 11772*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AND), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                    // Dst: (AND:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 11780*/        0, /*End of Scope*/
/* 11781*/      /*Scope*/ 12, /*->11794*/
/* 11782*/        OPC_CheckType, MVT::i64,
/* 11784*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 11786*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AND), 0,
                      MVT::i64, 2/*#Ops*/, 0, 1, 
                  // Src: (and:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                  // Dst: (AND:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 11794*/      0, /*End of Scope*/
/* 11795*/    0, /*End of Scope*/
/* 11796*/  /*SwitchOpcode*/ 94, TARGET_VAL(ISD::XOR),// ->11893
/* 11799*/    OPC_RecordChild0, // #0 = $rs1
/* 11800*/    OPC_RecordChild1, // #1 = $imm12
/* 11801*/    OPC_Scope, 51, /*->11854*/ // 3 children in Scope
/* 11803*/      OPC_MoveChild1,
/* 11804*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/* 11807*/      OPC_CheckPredicate, 0, // Predicate_simm12
/* 11809*/      OPC_MoveParent,
/* 11810*/      OPC_SwitchType /*2 cases */, 26, MVT::i32,// ->11839
/* 11813*/        OPC_Scope, 12, /*->11827*/ // 2 children in Scope
/* 11815*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 11817*/          OPC_EmitConvertToTarget, 1,
/* 11819*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                        MVT::i32, 2/*#Ops*/, 0, 2, 
                    // Src: (xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12) - Complexity = 7
                    // Dst: (XORI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/* 11827*/        /*Scope*/ 10, /*->11838*/
/* 11828*/          OPC_EmitConvertToTarget, 1,
/* 11830*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                        MVT::i32, 2/*#Ops*/, 0, 2, 
                    // Src: (xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12) - Complexity = 7
                    // Dst: (XORI:{ *:[i32] } GPR:{ *:[i32] }:$rs1, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm12)
/* 11838*/        0, /*End of Scope*/
/* 11839*/      /*SwitchType*/ 12, MVT::i64,// ->11853
/* 11841*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 11843*/        OPC_EmitConvertToTarget, 1,
/* 11845*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::XORI), 0,
                      MVT::i64, 2/*#Ops*/, 0, 2, 
                  // Src: (xor:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12) - Complexity = 7
                  // Dst: (XORI:{ *:[i64] } GPR:{ *:[i64] }:$rs1, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm12)
/* 11853*/      0, // EndSwitchType
/* 11854*/    /*Scope*/ 24, /*->11879*/
/* 11855*/      OPC_CheckType, MVT::i32,
/* 11857*/      OPC_Scope, 10, /*->11869*/ // 2 children in Scope
/* 11859*/        OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 11861*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::XOR), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (XOR:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 11869*/      /*Scope*/ 8, /*->11878*/
/* 11870*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::XOR), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (XOR:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 11878*/      0, /*End of Scope*/
/* 11879*/    /*Scope*/ 12, /*->11892*/
/* 11880*/      OPC_CheckType, MVT::i64,
/* 11882*/      OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 11884*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::XOR), 0,
                    MVT::i64, 2/*#Ops*/, 0, 1, 
                // Src: (xor:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                // Dst: (XOR:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 11892*/    0, /*End of Scope*/
/* 11893*/  /*SwitchOpcode*/ 124, TARGET_VAL(RISCVISD::CALL),// ->12020
/* 11896*/    OPC_RecordNode, // #0 = 'Call' chained node
/* 11897*/    OPC_CaptureGlueInput,
/* 11898*/    OPC_RecordChild1, // #1 = $func
/* 11899*/    OPC_Scope, 83, /*->11984*/ // 3 children in Scope
/* 11901*/      OPC_MoveChild1,
/* 11902*/      OPC_SwitchOpcode /*2 cases */, 37, TARGET_VAL(ISD::TargetGlobalAddress),// ->11943
/* 11906*/        OPC_SwitchType /*2 cases */, 21, MVT::i32,// ->11930
/* 11909*/          OPC_MoveParent,
/* 11910*/          OPC_Scope, 9, /*->11921*/ // 2 children in Scope
/* 11912*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 11914*/            OPC_EmitMergeInputChains1_0,
/* 11915*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoCALL), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                          1/*#Ops*/, 1, 
                      // Src: (Call (tglobaladdr:{ *:[i32] }):$func) - Complexity = 6
                      // Dst: (PseudoCALL (tglobaladdr:{ *:[i32] }):$func)
/* 11921*/          /*Scope*/ 7, /*->11929*/
/* 11922*/            OPC_EmitMergeInputChains1_0,
/* 11923*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoCALL), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                          1/*#Ops*/, 1, 
                      // Src: (Call (tglobaladdr:{ *:[i32] }):$func) - Complexity = 6
                      // Dst: (PseudoCALL (tglobaladdr:{ *:[i32] }):$func)
/* 11929*/          0, /*End of Scope*/
/* 11930*/        /*SwitchType*/ 10, MVT::i64,// ->11942
/* 11932*/          OPC_MoveParent,
/* 11933*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 11935*/          OPC_EmitMergeInputChains1_0,
/* 11936*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoCALL), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                        1/*#Ops*/, 1, 
                    // Src: (Call (tglobaladdr:{ *:[i64] }):$func) - Complexity = 6
                    // Dst: (PseudoCALL (tglobaladdr:{ *:[i64] }):$func)
/* 11942*/        0, // EndSwitchType
/* 11943*/      /*SwitchOpcode*/ 37, TARGET_VAL(ISD::TargetExternalSymbol),// ->11983
/* 11946*/        OPC_SwitchType /*2 cases */, 21, MVT::i32,// ->11970
/* 11949*/          OPC_MoveParent,
/* 11950*/          OPC_Scope, 9, /*->11961*/ // 2 children in Scope
/* 11952*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 11954*/            OPC_EmitMergeInputChains1_0,
/* 11955*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoCALL), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                          1/*#Ops*/, 1, 
                      // Src: (Call (texternalsym:{ *:[i32] }):$func) - Complexity = 6
                      // Dst: (PseudoCALL (texternalsym:{ *:[i32] }):$func)
/* 11961*/          /*Scope*/ 7, /*->11969*/
/* 11962*/            OPC_EmitMergeInputChains1_0,
/* 11963*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoCALL), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                          1/*#Ops*/, 1, 
                      // Src: (Call (texternalsym:{ *:[i32] }):$func) - Complexity = 6
                      // Dst: (PseudoCALL (texternalsym:{ *:[i32] }):$func)
/* 11969*/          0, /*End of Scope*/
/* 11970*/        /*SwitchType*/ 10, MVT::i64,// ->11982
/* 11972*/          OPC_MoveParent,
/* 11973*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 11975*/          OPC_EmitMergeInputChains1_0,
/* 11976*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoCALL), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                        1/*#Ops*/, 1, 
                    // Src: (Call (texternalsym:{ *:[i64] }):$func) - Complexity = 6
                    // Dst: (PseudoCALL (texternalsym:{ *:[i64] }):$func)
/* 11982*/        0, // EndSwitchType
/* 11983*/      0, // EndSwitchOpcode
/* 11984*/    /*Scope*/ 22, /*->12007*/
/* 11985*/      OPC_CheckChild1Type, MVT::i32,
/* 11987*/      OPC_Scope, 9, /*->11998*/ // 2 children in Scope
/* 11989*/        OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 11991*/        OPC_EmitMergeInputChains1_0,
/* 11992*/        OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoCALLIndirect), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                      1/*#Ops*/, 1, 
                  // Src: (Call GPR:{ *:[i32] }:$rs1) - Complexity = 3
                  // Dst: (PseudoCALLIndirect GPR:{ *:[i32] }:$rs1)
/* 11998*/      /*Scope*/ 7, /*->12006*/
/* 11999*/        OPC_EmitMergeInputChains1_0,
/* 12000*/        OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoCALLIndirect), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                      1/*#Ops*/, 1, 
                  // Src: (Call GPR:{ *:[i32] }:$rs1) - Complexity = 3
                  // Dst: (PseudoCALLIndirect GPR:{ *:[i32] }:$rs1)
/* 12006*/      0, /*End of Scope*/
/* 12007*/    /*Scope*/ 11, /*->12019*/
/* 12008*/      OPC_CheckChild1Type, MVT::i64,
/* 12010*/      OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12012*/      OPC_EmitMergeInputChains1_0,
/* 12013*/      OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoCALLIndirect), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                    1/*#Ops*/, 1, 
                // Src: (Call GPR:{ *:[i64] }:$rs1) - Complexity = 3
                // Dst: (PseudoCALLIndirect GPR:{ *:[i64] }:$rs1)
/* 12019*/    0, /*End of Scope*/
/* 12020*/  /*SwitchOpcode*/ 64|128,5/*704*/, TARGET_VAL(ISD::BRCOND),// ->12728
/* 12024*/    OPC_RecordNode, // #0 = 'brcond' chained node
/* 12025*/    OPC_Scope, 121|128,4/*633*/, /*->12661*/ // 2 children in Scope
/* 12028*/      OPC_MoveChild1,
/* 12029*/      OPC_CheckOpcode, TARGET_VAL(ISD::SETCC),
/* 12032*/      OPC_RecordChild0, // #1 = $rs1
/* 12033*/      OPC_Scope, 120|128,2/*376*/, /*->12412*/ // 2 children in Scope
/* 12036*/        OPC_CheckChild0Type, MVT::i32,
/* 12038*/        OPC_RecordChild1, // #2 = $rs2
/* 12039*/        OPC_MoveChild2,
/* 12040*/        OPC_Scope, 36, /*->12078*/ // 10 children in Scope
/* 12042*/          OPC_CheckCondCode, ISD::SETEQ,
/* 12044*/          OPC_MoveParent,
/* 12045*/          OPC_CheckType, MVT::i32,
/* 12047*/          OPC_MoveParent,
/* 12048*/          OPC_RecordChild2, // #3 = $imm12
/* 12049*/          OPC_MoveChild2,
/* 12050*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12053*/          OPC_MoveParent,
/* 12054*/          OPC_Scope, 11, /*->12067*/ // 2 children in Scope
/* 12056*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12058*/            OPC_EmitMergeInputChains1_0,
/* 12059*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BEQ), 0|OPFL_Chain,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETEQ:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BEQ GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12067*/          /*Scope*/ 9, /*->12077*/
/* 12068*/            OPC_EmitMergeInputChains1_0,
/* 12069*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BEQ), 0|OPFL_Chain,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETEQ:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BEQ GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12077*/          0, /*End of Scope*/
/* 12078*/        /*Scope*/ 36, /*->12115*/
/* 12079*/          OPC_CheckCondCode, ISD::SETNE,
/* 12081*/          OPC_MoveParent,
/* 12082*/          OPC_CheckType, MVT::i32,
/* 12084*/          OPC_MoveParent,
/* 12085*/          OPC_RecordChild2, // #3 = $imm12
/* 12086*/          OPC_MoveChild2,
/* 12087*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12090*/          OPC_MoveParent,
/* 12091*/          OPC_Scope, 11, /*->12104*/ // 2 children in Scope
/* 12093*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12095*/            OPC_EmitMergeInputChains1_0,
/* 12096*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BNE), 0|OPFL_Chain,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETNE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BNE GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12104*/          /*Scope*/ 9, /*->12114*/
/* 12105*/            OPC_EmitMergeInputChains1_0,
/* 12106*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BNE), 0|OPFL_Chain,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETNE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BNE GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12114*/          0, /*End of Scope*/
/* 12115*/        /*Scope*/ 36, /*->12152*/
/* 12116*/          OPC_CheckCondCode, ISD::SETLT,
/* 12118*/          OPC_MoveParent,
/* 12119*/          OPC_CheckType, MVT::i32,
/* 12121*/          OPC_MoveParent,
/* 12122*/          OPC_RecordChild2, // #3 = $imm12
/* 12123*/          OPC_MoveChild2,
/* 12124*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12127*/          OPC_MoveParent,
/* 12128*/          OPC_Scope, 11, /*->12141*/ // 2 children in Scope
/* 12130*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12132*/            OPC_EmitMergeInputChains1_0,
/* 12133*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BLT), 0|OPFL_Chain,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETLT:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BLT GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12141*/          /*Scope*/ 9, /*->12151*/
/* 12142*/            OPC_EmitMergeInputChains1_0,
/* 12143*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BLT), 0|OPFL_Chain,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETLT:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BLT GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12151*/          0, /*End of Scope*/
/* 12152*/        /*Scope*/ 36, /*->12189*/
/* 12153*/          OPC_CheckCondCode, ISD::SETGE,
/* 12155*/          OPC_MoveParent,
/* 12156*/          OPC_CheckType, MVT::i32,
/* 12158*/          OPC_MoveParent,
/* 12159*/          OPC_RecordChild2, // #3 = $imm12
/* 12160*/          OPC_MoveChild2,
/* 12161*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12164*/          OPC_MoveParent,
/* 12165*/          OPC_Scope, 11, /*->12178*/ // 2 children in Scope
/* 12167*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12169*/            OPC_EmitMergeInputChains1_0,
/* 12170*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BGE), 0|OPFL_Chain,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETGE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BGE GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12178*/          /*Scope*/ 9, /*->12188*/
/* 12179*/            OPC_EmitMergeInputChains1_0,
/* 12180*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BGE), 0|OPFL_Chain,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETGE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BGE GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12188*/          0, /*End of Scope*/
/* 12189*/        /*Scope*/ 36, /*->12226*/
/* 12190*/          OPC_CheckCondCode, ISD::SETULT,
/* 12192*/          OPC_MoveParent,
/* 12193*/          OPC_CheckType, MVT::i32,
/* 12195*/          OPC_MoveParent,
/* 12196*/          OPC_RecordChild2, // #3 = $imm12
/* 12197*/          OPC_MoveChild2,
/* 12198*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12201*/          OPC_MoveParent,
/* 12202*/          OPC_Scope, 11, /*->12215*/ // 2 children in Scope
/* 12204*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12206*/            OPC_EmitMergeInputChains1_0,
/* 12207*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BLTU), 0|OPFL_Chain,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETULT:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BLTU GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12215*/          /*Scope*/ 9, /*->12225*/
/* 12216*/            OPC_EmitMergeInputChains1_0,
/* 12217*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BLTU), 0|OPFL_Chain,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETULT:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BLTU GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12225*/          0, /*End of Scope*/
/* 12226*/        /*Scope*/ 36, /*->12263*/
/* 12227*/          OPC_CheckCondCode, ISD::SETUGE,
/* 12229*/          OPC_MoveParent,
/* 12230*/          OPC_CheckType, MVT::i32,
/* 12232*/          OPC_MoveParent,
/* 12233*/          OPC_RecordChild2, // #3 = $imm12
/* 12234*/          OPC_MoveChild2,
/* 12235*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12238*/          OPC_MoveParent,
/* 12239*/          OPC_Scope, 11, /*->12252*/ // 2 children in Scope
/* 12241*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12243*/            OPC_EmitMergeInputChains1_0,
/* 12244*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BGEU), 0|OPFL_Chain,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETUGE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BGEU GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12252*/          /*Scope*/ 9, /*->12262*/
/* 12253*/            OPC_EmitMergeInputChains1_0,
/* 12254*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BGEU), 0|OPFL_Chain,
                          3/*#Ops*/, 1, 2, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETUGE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BGEU GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12262*/          0, /*End of Scope*/
/* 12263*/        /*Scope*/ 36, /*->12300*/
/* 12264*/          OPC_CheckCondCode, ISD::SETGT,
/* 12266*/          OPC_MoveParent,
/* 12267*/          OPC_CheckType, MVT::i32,
/* 12269*/          OPC_MoveParent,
/* 12270*/          OPC_RecordChild2, // #3 = $imm12
/* 12271*/          OPC_MoveChild2,
/* 12272*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12275*/          OPC_MoveParent,
/* 12276*/          OPC_Scope, 11, /*->12289*/ // 2 children in Scope
/* 12278*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12280*/            OPC_EmitMergeInputChains1_0,
/* 12281*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BLT), 0|OPFL_Chain,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETGT:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BLT GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (bb:{ *:[Other] }):$imm12)
/* 12289*/          /*Scope*/ 9, /*->12299*/
/* 12290*/            OPC_EmitMergeInputChains1_0,
/* 12291*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BLT), 0|OPFL_Chain,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETGT:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BLT GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (bb:{ *:[Other] }):$imm12)
/* 12299*/          0, /*End of Scope*/
/* 12300*/        /*Scope*/ 36, /*->12337*/
/* 12301*/          OPC_CheckCondCode, ISD::SETLE,
/* 12303*/          OPC_MoveParent,
/* 12304*/          OPC_CheckType, MVT::i32,
/* 12306*/          OPC_MoveParent,
/* 12307*/          OPC_RecordChild2, // #3 = $imm12
/* 12308*/          OPC_MoveChild2,
/* 12309*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12312*/          OPC_MoveParent,
/* 12313*/          OPC_Scope, 11, /*->12326*/ // 2 children in Scope
/* 12315*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12317*/            OPC_EmitMergeInputChains1_0,
/* 12318*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BGE), 0|OPFL_Chain,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETLE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BGE GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (bb:{ *:[Other] }):$imm12)
/* 12326*/          /*Scope*/ 9, /*->12336*/
/* 12327*/            OPC_EmitMergeInputChains1_0,
/* 12328*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BGE), 0|OPFL_Chain,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETLE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BGE GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (bb:{ *:[Other] }):$imm12)
/* 12336*/          0, /*End of Scope*/
/* 12337*/        /*Scope*/ 36, /*->12374*/
/* 12338*/          OPC_CheckCondCode, ISD::SETUGT,
/* 12340*/          OPC_MoveParent,
/* 12341*/          OPC_CheckType, MVT::i32,
/* 12343*/          OPC_MoveParent,
/* 12344*/          OPC_RecordChild2, // #3 = $imm12
/* 12345*/          OPC_MoveChild2,
/* 12346*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12349*/          OPC_MoveParent,
/* 12350*/          OPC_Scope, 11, /*->12363*/ // 2 children in Scope
/* 12352*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12354*/            OPC_EmitMergeInputChains1_0,
/* 12355*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BLTU), 0|OPFL_Chain,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETUGT:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BLTU GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (bb:{ *:[Other] }):$imm12)
/* 12363*/          /*Scope*/ 9, /*->12373*/
/* 12364*/            OPC_EmitMergeInputChains1_0,
/* 12365*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BLTU), 0|OPFL_Chain,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETUGT:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BLTU GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (bb:{ *:[Other] }):$imm12)
/* 12373*/          0, /*End of Scope*/
/* 12374*/        /*Scope*/ 36, /*->12411*/
/* 12375*/          OPC_CheckCondCode, ISD::SETULE,
/* 12377*/          OPC_MoveParent,
/* 12378*/          OPC_CheckType, MVT::i32,
/* 12380*/          OPC_MoveParent,
/* 12381*/          OPC_RecordChild2, // #3 = $imm12
/* 12382*/          OPC_MoveChild2,
/* 12383*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12386*/          OPC_MoveParent,
/* 12387*/          OPC_Scope, 11, /*->12400*/ // 2 children in Scope
/* 12389*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12391*/            OPC_EmitMergeInputChains1_0,
/* 12392*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BGEU), 0|OPFL_Chain,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETULE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BGEU GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (bb:{ *:[Other] }):$imm12)
/* 12400*/          /*Scope*/ 9, /*->12410*/
/* 12401*/            OPC_EmitMergeInputChains1_0,
/* 12402*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::BGEU), 0|OPFL_Chain,
                          3/*#Ops*/, 2, 1, 3, 
                      // Src: (brcond (setcc:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2, SETULE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                      // Dst: (BGEU GPR:{ *:[i32] }:$rs2, GPR:{ *:[i32] }:$rs1, (bb:{ *:[Other] }):$imm12)
/* 12410*/          0, /*End of Scope*/
/* 12411*/        0, /*End of Scope*/
/* 12412*/      /*Scope*/ 118|128,1/*246*/, /*->12660*/
/* 12414*/        OPC_CheckChild0Type, MVT::i64,
/* 12416*/        OPC_RecordChild1, // #2 = $rs2
/* 12417*/        OPC_MoveChild2,
/* 12418*/        OPC_Scope, 23, /*->12443*/ // 10 children in Scope
/* 12420*/          OPC_CheckCondCode, ISD::SETEQ,
/* 12422*/          OPC_MoveParent,
/* 12423*/          OPC_CheckType, MVT::i64,
/* 12425*/          OPC_MoveParent,
/* 12426*/          OPC_RecordChild2, // #3 = $imm12
/* 12427*/          OPC_MoveChild2,
/* 12428*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12431*/          OPC_MoveParent,
/* 12432*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12434*/          OPC_EmitMergeInputChains1_0,
/* 12435*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::BEQ), 0|OPFL_Chain,
                        3/*#Ops*/, 1, 2, 3, 
                    // Src: (brcond (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETEQ:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                    // Dst: (BEQ GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12443*/        /*Scope*/ 23, /*->12467*/
/* 12444*/          OPC_CheckCondCode, ISD::SETNE,
/* 12446*/          OPC_MoveParent,
/* 12447*/          OPC_CheckType, MVT::i64,
/* 12449*/          OPC_MoveParent,
/* 12450*/          OPC_RecordChild2, // #3 = $imm12
/* 12451*/          OPC_MoveChild2,
/* 12452*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12455*/          OPC_MoveParent,
/* 12456*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12458*/          OPC_EmitMergeInputChains1_0,
/* 12459*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::BNE), 0|OPFL_Chain,
                        3/*#Ops*/, 1, 2, 3, 
                    // Src: (brcond (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETNE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                    // Dst: (BNE GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12467*/        /*Scope*/ 23, /*->12491*/
/* 12468*/          OPC_CheckCondCode, ISD::SETLT,
/* 12470*/          OPC_MoveParent,
/* 12471*/          OPC_CheckType, MVT::i64,
/* 12473*/          OPC_MoveParent,
/* 12474*/          OPC_RecordChild2, // #3 = $imm12
/* 12475*/          OPC_MoveChild2,
/* 12476*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12479*/          OPC_MoveParent,
/* 12480*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12482*/          OPC_EmitMergeInputChains1_0,
/* 12483*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::BLT), 0|OPFL_Chain,
                        3/*#Ops*/, 1, 2, 3, 
                    // Src: (brcond (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETLT:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                    // Dst: (BLT GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12491*/        /*Scope*/ 23, /*->12515*/
/* 12492*/          OPC_CheckCondCode, ISD::SETGE,
/* 12494*/          OPC_MoveParent,
/* 12495*/          OPC_CheckType, MVT::i64,
/* 12497*/          OPC_MoveParent,
/* 12498*/          OPC_RecordChild2, // #3 = $imm12
/* 12499*/          OPC_MoveChild2,
/* 12500*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12503*/          OPC_MoveParent,
/* 12504*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12506*/          OPC_EmitMergeInputChains1_0,
/* 12507*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::BGE), 0|OPFL_Chain,
                        3/*#Ops*/, 1, 2, 3, 
                    // Src: (brcond (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETGE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                    // Dst: (BGE GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12515*/        /*Scope*/ 23, /*->12539*/
/* 12516*/          OPC_CheckCondCode, ISD::SETULT,
/* 12518*/          OPC_MoveParent,
/* 12519*/          OPC_CheckType, MVT::i64,
/* 12521*/          OPC_MoveParent,
/* 12522*/          OPC_RecordChild2, // #3 = $imm12
/* 12523*/          OPC_MoveChild2,
/* 12524*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12527*/          OPC_MoveParent,
/* 12528*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12530*/          OPC_EmitMergeInputChains1_0,
/* 12531*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::BLTU), 0|OPFL_Chain,
                        3/*#Ops*/, 1, 2, 3, 
                    // Src: (brcond (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETULT:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                    // Dst: (BLTU GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12539*/        /*Scope*/ 23, /*->12563*/
/* 12540*/          OPC_CheckCondCode, ISD::SETUGE,
/* 12542*/          OPC_MoveParent,
/* 12543*/          OPC_CheckType, MVT::i64,
/* 12545*/          OPC_MoveParent,
/* 12546*/          OPC_RecordChild2, // #3 = $imm12
/* 12547*/          OPC_MoveChild2,
/* 12548*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12551*/          OPC_MoveParent,
/* 12552*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12554*/          OPC_EmitMergeInputChains1_0,
/* 12555*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::BGEU), 0|OPFL_Chain,
                        3/*#Ops*/, 1, 2, 3, 
                    // Src: (brcond (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETUGE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                    // Dst: (BGEU GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, simm13_lsb0:{ *:[Other] }:$imm12)
/* 12563*/        /*Scope*/ 23, /*->12587*/
/* 12564*/          OPC_CheckCondCode, ISD::SETGT,
/* 12566*/          OPC_MoveParent,
/* 12567*/          OPC_CheckType, MVT::i64,
/* 12569*/          OPC_MoveParent,
/* 12570*/          OPC_RecordChild2, // #3 = $imm12
/* 12571*/          OPC_MoveChild2,
/* 12572*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12575*/          OPC_MoveParent,
/* 12576*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12578*/          OPC_EmitMergeInputChains1_0,
/* 12579*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::BLT), 0|OPFL_Chain,
                        3/*#Ops*/, 2, 1, 3, 
                    // Src: (brcond (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETGT:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                    // Dst: (BLT GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, (bb:{ *:[Other] }):$imm12)
/* 12587*/        /*Scope*/ 23, /*->12611*/
/* 12588*/          OPC_CheckCondCode, ISD::SETLE,
/* 12590*/          OPC_MoveParent,
/* 12591*/          OPC_CheckType, MVT::i64,
/* 12593*/          OPC_MoveParent,
/* 12594*/          OPC_RecordChild2, // #3 = $imm12
/* 12595*/          OPC_MoveChild2,
/* 12596*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12599*/          OPC_MoveParent,
/* 12600*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12602*/          OPC_EmitMergeInputChains1_0,
/* 12603*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::BGE), 0|OPFL_Chain,
                        3/*#Ops*/, 2, 1, 3, 
                    // Src: (brcond (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETLE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                    // Dst: (BGE GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, (bb:{ *:[Other] }):$imm12)
/* 12611*/        /*Scope*/ 23, /*->12635*/
/* 12612*/          OPC_CheckCondCode, ISD::SETUGT,
/* 12614*/          OPC_MoveParent,
/* 12615*/          OPC_CheckType, MVT::i64,
/* 12617*/          OPC_MoveParent,
/* 12618*/          OPC_RecordChild2, // #3 = $imm12
/* 12619*/          OPC_MoveChild2,
/* 12620*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12623*/          OPC_MoveParent,
/* 12624*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12626*/          OPC_EmitMergeInputChains1_0,
/* 12627*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::BLTU), 0|OPFL_Chain,
                        3/*#Ops*/, 2, 1, 3, 
                    // Src: (brcond (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETUGT:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                    // Dst: (BLTU GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, (bb:{ *:[Other] }):$imm12)
/* 12635*/        /*Scope*/ 23, /*->12659*/
/* 12636*/          OPC_CheckCondCode, ISD::SETULE,
/* 12638*/          OPC_MoveParent,
/* 12639*/          OPC_CheckType, MVT::i64,
/* 12641*/          OPC_MoveParent,
/* 12642*/          OPC_RecordChild2, // #3 = $imm12
/* 12643*/          OPC_MoveChild2,
/* 12644*/          OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12647*/          OPC_MoveParent,
/* 12648*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12650*/          OPC_EmitMergeInputChains1_0,
/* 12651*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::BGEU), 0|OPFL_Chain,
                        3/*#Ops*/, 2, 1, 3, 
                    // Src: (brcond (setcc:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2, SETULE:{ *:[Other] }), (bb:{ *:[Other] }):$imm12) - Complexity = 6
                    // Dst: (BGEU GPR:{ *:[i64] }:$rs2, GPR:{ *:[i64] }:$rs1, (bb:{ *:[Other] }):$imm12)
/* 12659*/        0, /*End of Scope*/
/* 12660*/      0, /*End of Scope*/
/* 12661*/    /*Scope*/ 65, /*->12727*/
/* 12662*/      OPC_RecordChild1, // #1 = $cond
/* 12663*/      OPC_Scope, 38, /*->12703*/ // 2 children in Scope
/* 12665*/        OPC_CheckChild1Type, MVT::i32,
/* 12667*/        OPC_RecordChild2, // #2 = $imm12
/* 12668*/        OPC_MoveChild2,
/* 12669*/        OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12672*/        OPC_MoveParent,
/* 12673*/        OPC_Scope, 14, /*->12689*/ // 2 children in Scope
/* 12675*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12677*/          OPC_EmitMergeInputChains1_0,
/* 12678*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 12681*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::BNE), 0|OPFL_Chain,
                        3/*#Ops*/, 1, 3, 2, 
                    // Src: (brcond GPR:{ *:[i32] }:$cond, (bb:{ *:[Other] }):$imm12) - Complexity = 3
                    // Dst: (BNE GPR:{ *:[i32] }:$cond, X0:{ *:[i32] }, (bb:{ *:[Other] }):$imm12)
/* 12689*/        /*Scope*/ 12, /*->12702*/
/* 12690*/          OPC_EmitMergeInputChains1_0,
/* 12691*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 12694*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::BNE), 0|OPFL_Chain,
                        3/*#Ops*/, 1, 3, 2, 
                    // Src: (brcond GPR:{ *:[i32] }:$cond, (bb:{ *:[Other] }):$imm12) - Complexity = 3
                    // Dst: (BNE GPR:{ *:[i32] }:$cond, X0:{ *:[i32] }, (bb:{ *:[Other] }):$imm12)
/* 12702*/        0, /*End of Scope*/
/* 12703*/      /*Scope*/ 22, /*->12726*/
/* 12704*/        OPC_CheckChild1Type, MVT::i64,
/* 12706*/        OPC_RecordChild2, // #2 = $imm12
/* 12707*/        OPC_MoveChild2,
/* 12708*/        OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 12711*/        OPC_MoveParent,
/* 12712*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12714*/        OPC_EmitMergeInputChains1_0,
/* 12715*/        OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 12718*/        OPC_MorphNodeTo0, TARGET_VAL(RISCV::BNE), 0|OPFL_Chain,
                      3/*#Ops*/, 1, 3, 2, 
                  // Src: (brcond GPR:{ *:[i64] }:$cond, (bb:{ *:[Other] }):$imm12) - Complexity = 3
                  // Dst: (BNE GPR:{ *:[i64] }:$cond, X0:{ *:[i64] }, (bb:{ *:[Other] }):$imm12)
/* 12726*/      0, /*End of Scope*/
/* 12727*/    0, /*End of Scope*/
/* 12728*/  /*SwitchOpcode*/ 124, TARGET_VAL(RISCVISD::TAIL),// ->12855
/* 12731*/    OPC_RecordNode, // #0 = 'Tail' chained node
/* 12732*/    OPC_CaptureGlueInput,
/* 12733*/    OPC_RecordChild1, // #1 = $dst
/* 12734*/    OPC_Scope, 83, /*->12819*/ // 3 children in Scope
/* 12736*/      OPC_MoveChild1,
/* 12737*/      OPC_SwitchOpcode /*2 cases */, 37, TARGET_VAL(ISD::TargetGlobalAddress),// ->12778
/* 12741*/        OPC_SwitchType /*2 cases */, 21, MVT::i32,// ->12765
/* 12744*/          OPC_MoveParent,
/* 12745*/          OPC_Scope, 9, /*->12756*/ // 2 children in Scope
/* 12747*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12749*/            OPC_EmitMergeInputChains1_0,
/* 12750*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoTAIL), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                          1/*#Ops*/, 1, 
                      // Src: (Tail (tglobaladdr:{ *:[i32] }):$dst) - Complexity = 6
                      // Dst: (PseudoTAIL (texternalsym:{ *:[i32] }):$dst)
/* 12756*/          /*Scope*/ 7, /*->12764*/
/* 12757*/            OPC_EmitMergeInputChains1_0,
/* 12758*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoTAIL), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                          1/*#Ops*/, 1, 
                      // Src: (Tail (tglobaladdr:{ *:[i32] }):$dst) - Complexity = 6
                      // Dst: (PseudoTAIL (texternalsym:{ *:[i32] }):$dst)
/* 12764*/          0, /*End of Scope*/
/* 12765*/        /*SwitchType*/ 10, MVT::i64,// ->12777
/* 12767*/          OPC_MoveParent,
/* 12768*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12770*/          OPC_EmitMergeInputChains1_0,
/* 12771*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoTAIL), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                        1/*#Ops*/, 1, 
                    // Src: (Tail (tglobaladdr:{ *:[i64] }):$dst) - Complexity = 6
                    // Dst: (PseudoTAIL (texternalsym:{ *:[i64] }):$dst)
/* 12777*/        0, // EndSwitchType
/* 12778*/      /*SwitchOpcode*/ 37, TARGET_VAL(ISD::TargetExternalSymbol),// ->12818
/* 12781*/        OPC_SwitchType /*2 cases */, 21, MVT::i32,// ->12805
/* 12784*/          OPC_MoveParent,
/* 12785*/          OPC_Scope, 9, /*->12796*/ // 2 children in Scope
/* 12787*/            OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12789*/            OPC_EmitMergeInputChains1_0,
/* 12790*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoTAIL), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                          1/*#Ops*/, 1, 
                      // Src: (Tail (texternalsym:{ *:[i32] }):$dst) - Complexity = 6
                      // Dst: (PseudoTAIL (texternalsym:{ *:[i32] }):$dst)
/* 12796*/          /*Scope*/ 7, /*->12804*/
/* 12797*/            OPC_EmitMergeInputChains1_0,
/* 12798*/            OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoTAIL), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                          1/*#Ops*/, 1, 
                      // Src: (Tail (texternalsym:{ *:[i32] }):$dst) - Complexity = 6
                      // Dst: (PseudoTAIL (texternalsym:{ *:[i32] }):$dst)
/* 12804*/          0, /*End of Scope*/
/* 12805*/        /*SwitchType*/ 10, MVT::i64,// ->12817
/* 12807*/          OPC_MoveParent,
/* 12808*/          OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12810*/          OPC_EmitMergeInputChains1_0,
/* 12811*/          OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoTAIL), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                        1/*#Ops*/, 1, 
                    // Src: (Tail (texternalsym:{ *:[i64] }):$dst) - Complexity = 6
                    // Dst: (PseudoTAIL (texternalsym:{ *:[i64] }):$dst)
/* 12817*/        0, // EndSwitchType
/* 12818*/      0, // EndSwitchOpcode
/* 12819*/    /*Scope*/ 22, /*->12842*/
/* 12820*/      OPC_CheckChild1Type, MVT::i32,
/* 12822*/      OPC_Scope, 9, /*->12833*/ // 2 children in Scope
/* 12824*/        OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12826*/        OPC_EmitMergeInputChains1_0,
/* 12827*/        OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoTAILIndirect), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                      1/*#Ops*/, 1, 
                  // Src: (Tail GPRTC:{ *:[i32] }:$rs1) - Complexity = 3
                  // Dst: (PseudoTAILIndirect GPRTC:{ *:[i32] }:$rs1)
/* 12833*/      /*Scope*/ 7, /*->12841*/
/* 12834*/        OPC_EmitMergeInputChains1_0,
/* 12835*/        OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoTAILIndirect), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                      1/*#Ops*/, 1, 
                  // Src: (Tail GPRTC:{ *:[i32] }:$rs1) - Complexity = 3
                  // Dst: (PseudoTAILIndirect GPRTC:{ *:[i32] }:$rs1)
/* 12841*/      0, /*End of Scope*/
/* 12842*/    /*Scope*/ 11, /*->12854*/
/* 12843*/      OPC_CheckChild1Type, MVT::i64,
/* 12845*/      OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 12847*/      OPC_EmitMergeInputChains1_0,
/* 12848*/      OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoTAILIndirect), 0|OPFL_Chain|OPFL_GlueInput|OPFL_GlueOutput|OPFL_Variadic1,
                    1/*#Ops*/, 1, 
                // Src: (Tail GPRTC:{ *:[i64] }:$rs1) - Complexity = 3
                // Dst: (PseudoTAILIndirect GPRTC:{ *:[i64] }:$rs1)
/* 12854*/    0, /*End of Scope*/
/* 12855*/  /*SwitchOpcode*/ 65|128,1/*193*/, TARGET_VAL(RISCVISD::SELECT_CC),// ->13052
/* 12859*/    OPC_CaptureGlueInput,
/* 12860*/    OPC_RecordChild0, // #0 = $lhs
/* 12861*/    OPC_Scope, 121, /*->12984*/ // 2 children in Scope
/* 12863*/      OPC_CheckChild0Type, MVT::i32,
/* 12865*/      OPC_RecordChild1, // #1 = $rhs
/* 12866*/      OPC_RecordChild2, // #2 = $imm
/* 12867*/      OPC_MoveChild2,
/* 12868*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/* 12871*/      OPC_CheckType, MVT::i32,
/* 12873*/      OPC_MoveParent,
/* 12874*/      OPC_RecordChild3, // #3 = $truev
/* 12875*/      OPC_RecordChild4, // #4 = $falsev
/* 12876*/      OPC_SwitchType /*3 cases */, 32, MVT::i32,// ->12911
/* 12879*/        OPC_Scope, 15, /*->12896*/ // 2 children in Scope
/* 12881*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 12883*/          OPC_EmitConvertToTarget, 2,
/* 12885*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::Select_GPR_Using_CC_GPR), 0|OPFL_GlueInput,
                        MVT::i32, 5/*#Ops*/, 0, 1, 5, 3, 4, 
                    // Src: (SelectCC:{ *:[i32] } GPR:{ *:[i32] }:$lhs, GPR:{ *:[i32] }:$rhs, (imm:{ *:[i32] }):$imm, GPR:{ *:[i32] }:$truev, GPR:{ *:[i32] }:$falsev) - Complexity = 6
                    // Dst: (Select_GPR_Using_CC_GPR:{ *:[i32] } GPR:{ *:[i32] }:$lhs, GPR:{ *:[i32] }:$rhs, (imm:{ *:[i32] }):$imm, GPR:{ *:[i32] }:$truev, GPR:{ *:[i32] }:$falsev)
/* 12896*/        /*Scope*/ 13, /*->12910*/
/* 12897*/          OPC_EmitConvertToTarget, 2,
/* 12899*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::Select_GPR_Using_CC_GPR), 0|OPFL_GlueInput,
                        MVT::i32, 5/*#Ops*/, 0, 1, 5, 3, 4, 
                    // Src: (SelectCC:{ *:[i32] } GPR:{ *:[i32] }:$lhs, GPR:{ *:[i32] }:$rhs, (imm:{ *:[i32] }):$imm, GPR:{ *:[i32] }:$truev, GPR:{ *:[i32] }:$falsev) - Complexity = 6
                    // Dst: (Select_GPR_Using_CC_GPR:{ *:[i32] } GPR:{ *:[i32] }:$lhs, GPR:{ *:[i32] }:$rhs, (imm:{ *:[i32] }):$imm, GPR:{ *:[i32] }:$truev, GPR:{ *:[i32] }:$falsev)
/* 12910*/        0, /*End of Scope*/
/* 12911*/      /*SwitchType*/ 34, MVT::f32,// ->12947
/* 12913*/        OPC_Scope, 15, /*->12930*/ // 2 children in Scope
/* 12915*/          OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 12917*/          OPC_EmitConvertToTarget, 2,
/* 12919*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::Select_FPR32_Using_CC_GPR), 0|OPFL_GlueInput,
                        MVT::f32, 5/*#Ops*/, 0, 1, 5, 3, 4, 
                    // Src: (SelectCC:{ *:[f32] } GPR:{ *:[i32] }:$lhs, GPR:{ *:[i32] }:$rhs, (imm:{ *:[i32] }):$imm, FPR32:{ *:[f32] }:$truev, FPR32:{ *:[f32] }:$falsev) - Complexity = 6
                    // Dst: (Select_FPR32_Using_CC_GPR:{ *:[f32] } GPR:{ *:[i32] }:$lhs, GPR:{ *:[i32] }:$rhs, (imm:{ *:[i32] }):$imm, FPR32:{ *:[f32] }:$truev, FPR32:{ *:[f32] }:$falsev)
/* 12930*/        /*Scope*/ 15, /*->12946*/
/* 12931*/          OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 12933*/          OPC_EmitConvertToTarget, 2,
/* 12935*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::Select_FPR32_Using_CC_GPR), 0|OPFL_GlueInput,
                        MVT::f32, 5/*#Ops*/, 0, 1, 5, 3, 4, 
                    // Src: (SelectCC:{ *:[f32] } GPR:{ *:[i32] }:$lhs, GPR:{ *:[i32] }:$rhs, (imm:{ *:[i32] }):$imm, FPR32:{ *:[f32] }:$truev, FPR32:{ *:[f32] }:$falsev) - Complexity = 6
                    // Dst: (Select_FPR32_Using_CC_GPR:{ *:[f32] } GPR:{ *:[i32] }:$lhs, GPR:{ *:[i32] }:$rhs, (imm:{ *:[i32] }):$imm, FPR32:{ *:[f32] }:$truev, FPR32:{ *:[f32] }:$falsev)
/* 12946*/        0, /*End of Scope*/
/* 12947*/      /*SwitchType*/ 34, MVT::f64,// ->12983
/* 12949*/        OPC_Scope, 15, /*->12966*/ // 2 children in Scope
/* 12951*/          OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 12953*/          OPC_EmitConvertToTarget, 2,
/* 12955*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::Select_FPR64_Using_CC_GPR), 0|OPFL_GlueInput,
                        MVT::f64, 5/*#Ops*/, 0, 1, 5, 3, 4, 
                    // Src: (SelectCC:{ *:[f64] } GPR:{ *:[i32] }:$lhs, GPR:{ *:[i32] }:$rhs, (imm:{ *:[i32] }):$imm, FPR64:{ *:[f64] }:$truev, FPR64:{ *:[f64] }:$falsev) - Complexity = 6
                    // Dst: (Select_FPR64_Using_CC_GPR:{ *:[f64] } GPR:{ *:[i32] }:$lhs, GPR:{ *:[i32] }:$rhs, (imm:{ *:[i32] }):$imm, FPR64:{ *:[f64] }:$truev, FPR64:{ *:[f64] }:$falsev)
/* 12966*/        /*Scope*/ 15, /*->12982*/
/* 12967*/          OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 12969*/          OPC_EmitConvertToTarget, 2,
/* 12971*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::Select_FPR64_Using_CC_GPR), 0|OPFL_GlueInput,
                        MVT::f64, 5/*#Ops*/, 0, 1, 5, 3, 4, 
                    // Src: (SelectCC:{ *:[f64] } GPR:{ *:[i32] }:$lhs, GPR:{ *:[i32] }:$rhs, (imm:{ *:[i32] }):$imm, FPR64:{ *:[f64] }:$truev, FPR64:{ *:[f64] }:$falsev) - Complexity = 6
                    // Dst: (Select_FPR64_Using_CC_GPR:{ *:[f64] } GPR:{ *:[i32] }:$lhs, GPR:{ *:[i32] }:$rhs, (imm:{ *:[i32] }):$imm, FPR64:{ *:[f64] }:$truev, FPR64:{ *:[f64] }:$falsev)
/* 12982*/        0, /*End of Scope*/
/* 12983*/      0, // EndSwitchType
/* 12984*/    /*Scope*/ 66, /*->13051*/
/* 12985*/      OPC_CheckChild0Type, MVT::i64,
/* 12987*/      OPC_RecordChild1, // #1 = $rhs
/* 12988*/      OPC_RecordChild2, // #2 = $imm
/* 12989*/      OPC_MoveChild2,
/* 12990*/      OPC_CheckOpcode, TARGET_VAL(ISD::Constant),
/* 12993*/      OPC_CheckType, MVT::i64,
/* 12995*/      OPC_MoveParent,
/* 12996*/      OPC_RecordChild3, // #3 = $truev
/* 12997*/      OPC_RecordChild4, // #4 = $falsev
/* 12998*/      OPC_SwitchType /*3 cases */, 15, MVT::i64,// ->13016
/* 13001*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 13003*/        OPC_EmitConvertToTarget, 2,
/* 13005*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::Select_GPR_Using_CC_GPR), 0|OPFL_GlueInput,
                      MVT::i64, 5/*#Ops*/, 0, 1, 5, 3, 4, 
                  // Src: (SelectCC:{ *:[i64] } GPR:{ *:[i64] }:$lhs, GPR:{ *:[i64] }:$rhs, (imm:{ *:[i64] }):$imm, GPR:{ *:[i64] }:$truev, GPR:{ *:[i64] }:$falsev) - Complexity = 6
                  // Dst: (Select_GPR_Using_CC_GPR:{ *:[i64] } GPR:{ *:[i64] }:$lhs, GPR:{ *:[i64] }:$rhs, (imm:{ *:[i64] }):$imm, GPR:{ *:[i64] }:$truev, GPR:{ *:[i64] }:$falsev)
/* 13016*/      /*SwitchType*/ 15, MVT::f32,// ->13033
/* 13018*/        OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13020*/        OPC_EmitConvertToTarget, 2,
/* 13022*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::Select_FPR32_Using_CC_GPR), 0|OPFL_GlueInput,
                      MVT::f32, 5/*#Ops*/, 0, 1, 5, 3, 4, 
                  // Src: (SelectCC:{ *:[f32] } GPR:{ *:[i64] }:$lhs, GPR:{ *:[i64] }:$rhs, (imm:{ *:[i64] }):$imm, FPR32:{ *:[f32] }:$truev, FPR32:{ *:[f32] }:$falsev) - Complexity = 6
                  // Dst: (Select_FPR32_Using_CC_GPR:{ *:[f32] } GPR:{ *:[i64] }:$lhs, GPR:{ *:[i64] }:$rhs, (imm:{ *:[i64] }):$imm, FPR32:{ *:[f32] }:$truev, FPR32:{ *:[f32] }:$falsev)
/* 13033*/      /*SwitchType*/ 15, MVT::f64,// ->13050
/* 13035*/        OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13037*/        OPC_EmitConvertToTarget, 2,
/* 13039*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::Select_FPR64_Using_CC_GPR), 0|OPFL_GlueInput,
                      MVT::f64, 5/*#Ops*/, 0, 1, 5, 3, 4, 
                  // Src: (SelectCC:{ *:[f64] } GPR:{ *:[i64] }:$lhs, GPR:{ *:[i64] }:$rhs, (imm:{ *:[i64] }):$imm, FPR64:{ *:[f64] }:$truev, FPR64:{ *:[f64] }:$falsev) - Complexity = 6
                  // Dst: (Select_FPR64_Using_CC_GPR:{ *:[f64] } GPR:{ *:[i64] }:$lhs, GPR:{ *:[i64] }:$rhs, (imm:{ *:[i64] }):$imm, FPR64:{ *:[f64] }:$truev, FPR64:{ *:[f64] }:$falsev)
/* 13050*/      0, // EndSwitchType
/* 13051*/    0, /*End of Scope*/
/* 13052*/  /*SwitchOpcode*/ 78|128,1/*206*/, TARGET_VAL(ISD::Constant),// ->13262
/* 13056*/    OPC_RecordNode, // #0 = $imm
/* 13057*/    OPC_Scope, 55, /*->13114*/ // 3 children in Scope
/* 13059*/      OPC_CheckPredicate, 0, // Predicate_simm12
/* 13061*/      OPC_SwitchType /*2 cases */, 32, MVT::i32,// ->13096
/* 13064*/        OPC_Scope, 15, /*->13081*/ // 2 children in Scope
/* 13066*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 13068*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 13071*/          OPC_EmitConvertToTarget, 0,
/* 13073*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDI), 0,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm - Complexity = 4
                    // Dst: (ADDI:{ *:[i32] } X0:{ *:[i32] }, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm)
/* 13081*/        /*Scope*/ 13, /*->13095*/
/* 13082*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 13085*/          OPC_EmitConvertToTarget, 0,
/* 13087*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDI), 0,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm - Complexity = 4
                    // Dst: (ADDI:{ *:[i32] } X0:{ *:[i32] }, (imm:{ *:[i32] })<<P:Predicate_simm12>>:$imm)
/* 13095*/        0, /*End of Scope*/
/* 13096*/      /*SwitchType*/ 15, MVT::i64,// ->13113
/* 13098*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 13100*/        OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 13103*/        OPC_EmitConvertToTarget, 0,
/* 13105*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDI), 0,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm - Complexity = 4
                  // Dst: (ADDI:{ *:[i64] } X0:{ *:[i64] }, (imm:{ *:[i64] })<<P:Predicate_simm12>>:$imm)
/* 13113*/      0, // EndSwitchType
/* 13114*/    /*Scope*/ 52, /*->13167*/
/* 13115*/      OPC_CheckPredicate, 22, // Predicate_simm32hi20
/* 13117*/      OPC_SwitchType /*2 cases */, 30, MVT::i32,// ->13150
/* 13120*/        OPC_Scope, 14, /*->13136*/ // 2 children in Scope
/* 13122*/          OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 13124*/          OPC_EmitConvertToTarget, 0,
/* 13126*/          OPC_EmitNodeXForm, 0, 1, // HI20
/* 13129*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LUI), 0,
                        MVT::i32, 1/*#Ops*/, 2, 
                    // Src: (imm:{ *:[i32] })<<P:Predicate_simm32hi20>>:$imm - Complexity = 4
                    // Dst: (LUI:{ *:[i32] } (HI20:{ *:[i32] } (imm:{ *:[i32] }):$imm))
/* 13136*/        /*Scope*/ 12, /*->13149*/
/* 13137*/          OPC_EmitConvertToTarget, 0,
/* 13139*/          OPC_EmitNodeXForm, 0, 1, // HI20
/* 13142*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::LUI), 0,
                        MVT::i32, 1/*#Ops*/, 2, 
                    // Src: (imm:{ *:[i32] })<<P:Predicate_simm32hi20>>:$imm - Complexity = 4
                    // Dst: (LUI:{ *:[i32] } (HI20:{ *:[i32] } (imm:{ *:[i32] }):$imm))
/* 13149*/        0, /*End of Scope*/
/* 13150*/      /*SwitchType*/ 14, MVT::i64,// ->13166
/* 13152*/        OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 13154*/        OPC_EmitConvertToTarget, 0,
/* 13156*/        OPC_EmitNodeXForm, 0, 1, // HI20
/* 13159*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::LUI), 0,
                      MVT::i64, 1/*#Ops*/, 2, 
                  // Src: (imm:{ *:[i64] })<<P:Predicate_simm32hi20>>:$imm - Complexity = 4
                  // Dst: (LUI:{ *:[i64] } (HI20:{ *:[i64] } (imm:{ *:[i64] }):$imm))
/* 13166*/      0, // EndSwitchType
/* 13167*/    /*Scope*/ 93, /*->13261*/
/* 13168*/      OPC_CheckPredicate, 23, // Predicate_simm32
/* 13170*/      OPC_SwitchType /*2 cases */, 58, MVT::i32,// ->13231
/* 13173*/        OPC_Scope, 27, /*->13202*/ // 2 children in Scope
/* 13175*/          OPC_CheckPatternPredicate, 1, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13177*/          OPC_EmitConvertToTarget, 0,
/* 13179*/          OPC_EmitNodeXForm, 0, 1, // HI20
/* 13182*/          OPC_EmitNode1, TARGET_VAL(RISCV::LUI), 0,
                        MVT::i32, 1/*#Ops*/, 2,  // Results = #3
/* 13189*/          OPC_EmitConvertToTarget, 0,
/* 13191*/          OPC_EmitNodeXForm, 1, 4, // LO12Sext
/* 13194*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDI), 0,
                        MVT::i32, 2/*#Ops*/, 3, 5, 
                    // Src: (imm:{ *:[i32] })<<P:Predicate_simm32>>:$imm - Complexity = 4
                    // Dst: (ADDI:{ *:[i32] } (LUI:{ *:[i32] } (HI20:{ *:[i32] } (imm:{ *:[i32] }):$imm)), (LO12Sext:{ *:[i32] } (imm:{ *:[i32] }):$imm))
/* 13202*/        /*Scope*/ 27, /*->13230*/
/* 13203*/          OPC_CheckPatternPredicate, 2, // (!Subtarget->is64Bit())
/* 13205*/          OPC_EmitConvertToTarget, 0,
/* 13207*/          OPC_EmitNodeXForm, 0, 1, // HI20
/* 13210*/          OPC_EmitNode1, TARGET_VAL(RISCV::LUI), 0,
                        MVT::i32, 1/*#Ops*/, 2,  // Results = #3
/* 13217*/          OPC_EmitConvertToTarget, 0,
/* 13219*/          OPC_EmitNodeXForm, 1, 4, // LO12Sext
/* 13222*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDI), 0,
                        MVT::i32, 2/*#Ops*/, 3, 5, 
                    // Src: (imm:{ *:[i32] })<<P:Predicate_simm32>>:$imm - Complexity = 4
                    // Dst: (ADDI:{ *:[i32] } (LUI:{ *:[i32] } (HI20:{ *:[i32] } (imm:{ *:[i32] }):$imm)), (LO12Sext:{ *:[i32] } (imm:{ *:[i32] }):$imm))
/* 13230*/        0, /*End of Scope*/
/* 13231*/      /*SwitchType*/ 27, MVT::i64,// ->13260
/* 13233*/        OPC_CheckPatternPredicate, 6, // (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13235*/        OPC_EmitConvertToTarget, 0,
/* 13237*/        OPC_EmitNodeXForm, 0, 1, // HI20
/* 13240*/        OPC_EmitNode1, TARGET_VAL(RISCV::LUI), 0,
                      MVT::i64, 1/*#Ops*/, 2,  // Results = #3
/* 13247*/        OPC_EmitConvertToTarget, 0,
/* 13249*/        OPC_EmitNodeXForm, 1, 4, // LO12Sext
/* 13252*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::ADDI), 0,
                      MVT::i64, 2/*#Ops*/, 3, 5, 
                  // Src: (imm:{ *:[i64] })<<P:Predicate_simm32>>:$imm - Complexity = 4
                  // Dst: (ADDI:{ *:[i64] } (LUI:{ *:[i64] } (HI20:{ *:[i64] } (imm:{ *:[i64] }):$imm)), (LO12Sext:{ *:[i64] } (imm:{ *:[i64] }):$imm))
/* 13260*/      0, // EndSwitchType
/* 13261*/    0, /*End of Scope*/
/* 13262*/  /*SwitchOpcode*/ 111|128,1/*239*/, TARGET_VAL(ISD::ATOMIC_SWAP),// ->13505
/* 13266*/    OPC_RecordMemRef,
/* 13267*/    OPC_RecordNode, // #0 = 'atomic_swap' chained node
/* 13268*/    OPC_RecordChild1, // #1 = $rs1
/* 13269*/    OPC_SwitchType /*2 cases */, 24|128,1/*152*/, MVT::i32,// ->13425
/* 13273*/      OPC_CheckChild1Type, MVT::i32,
/* 13275*/      OPC_RecordChild2, // #2 = $rs2
/* 13276*/      OPC_CheckPredicate, 18, // Predicate_atomic_swap_32
/* 13278*/      OPC_Scope, 28, /*->13308*/ // 5 children in Scope
/* 13280*/        OPC_CheckPredicate, 24, // Predicate_atomic_swap_32_monotonic
/* 13282*/        OPC_Scope, 11, /*->13295*/ // 2 children in Scope
/* 13284*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13286*/          OPC_EmitMergeInputChains1_0,
/* 13287*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_swap:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_monotonic>> - Complexity = 4
                    // Dst: (AMOSWAP_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13295*/        /*Scope*/ 11, /*->13307*/
/* 13296*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13298*/          OPC_EmitMergeInputChains1_0,
/* 13299*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_swap:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_monotonic>> - Complexity = 4
                    // Dst: (AMOSWAP_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13307*/        0, /*End of Scope*/
/* 13308*/      /*Scope*/ 28, /*->13337*/
/* 13309*/        OPC_CheckPredicate, 25, // Predicate_atomic_swap_32_acquire
/* 13311*/        OPC_Scope, 11, /*->13324*/ // 2 children in Scope
/* 13313*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13315*/          OPC_EmitMergeInputChains1_0,
/* 13316*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_swap:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_acquire>> - Complexity = 4
                    // Dst: (AMOSWAP_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13324*/        /*Scope*/ 11, /*->13336*/
/* 13325*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13327*/          OPC_EmitMergeInputChains1_0,
/* 13328*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_swap:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_acquire>> - Complexity = 4
                    // Dst: (AMOSWAP_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13336*/        0, /*End of Scope*/
/* 13337*/      /*Scope*/ 28, /*->13366*/
/* 13338*/        OPC_CheckPredicate, 26, // Predicate_atomic_swap_32_release
/* 13340*/        OPC_Scope, 11, /*->13353*/ // 2 children in Scope
/* 13342*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13344*/          OPC_EmitMergeInputChains1_0,
/* 13345*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_swap:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_release>> - Complexity = 4
                    // Dst: (AMOSWAP_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13353*/        /*Scope*/ 11, /*->13365*/
/* 13354*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13356*/          OPC_EmitMergeInputChains1_0,
/* 13357*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_swap:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_release>> - Complexity = 4
                    // Dst: (AMOSWAP_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13365*/        0, /*End of Scope*/
/* 13366*/      /*Scope*/ 28, /*->13395*/
/* 13367*/        OPC_CheckPredicate, 27, // Predicate_atomic_swap_32_acq_rel
/* 13369*/        OPC_Scope, 11, /*->13382*/ // 2 children in Scope
/* 13371*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13373*/          OPC_EmitMergeInputChains1_0,
/* 13374*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_swap:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOSWAP_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13382*/        /*Scope*/ 11, /*->13394*/
/* 13383*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13385*/          OPC_EmitMergeInputChains1_0,
/* 13386*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_swap:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOSWAP_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13394*/        0, /*End of Scope*/
/* 13395*/      /*Scope*/ 28, /*->13424*/
/* 13396*/        OPC_CheckPredicate, 28, // Predicate_atomic_swap_32_seq_cst
/* 13398*/        OPC_Scope, 11, /*->13411*/ // 2 children in Scope
/* 13400*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13402*/          OPC_EmitMergeInputChains1_0,
/* 13403*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_swap:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOSWAP_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13411*/        /*Scope*/ 11, /*->13423*/
/* 13412*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13414*/          OPC_EmitMergeInputChains1_0,
/* 13415*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_swap:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOSWAP_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13423*/        0, /*End of Scope*/
/* 13424*/      0, /*End of Scope*/
/* 13425*/    /*SwitchType*/ 77, MVT::i64,// ->13504
/* 13427*/      OPC_CheckChild1Type, MVT::i64,
/* 13429*/      OPC_RecordChild2, // #2 = $rs2
/* 13430*/      OPC_CheckPredicate, 18, // Predicate_atomic_swap_32
/* 13432*/      OPC_Scope, 13, /*->13447*/ // 5 children in Scope
/* 13434*/        OPC_CheckPredicate, 24, // Predicate_atomic_swap_32_monotonic
/* 13436*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13438*/        OPC_EmitMergeInputChains1_0,
/* 13439*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_swap:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_monotonic>> - Complexity = 4
                  // Dst: (AMOSWAP_W:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13447*/      /*Scope*/ 13, /*->13461*/
/* 13448*/        OPC_CheckPredicate, 25, // Predicate_atomic_swap_32_acquire
/* 13450*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13452*/        OPC_EmitMergeInputChains1_0,
/* 13453*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_swap:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_acquire>> - Complexity = 4
                  // Dst: (AMOSWAP_W_AQ:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13461*/      /*Scope*/ 13, /*->13475*/
/* 13462*/        OPC_CheckPredicate, 26, // Predicate_atomic_swap_32_release
/* 13464*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13466*/        OPC_EmitMergeInputChains1_0,
/* 13467*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_swap:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_release>> - Complexity = 4
                  // Dst: (AMOSWAP_W_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13475*/      /*Scope*/ 13, /*->13489*/
/* 13476*/        OPC_CheckPredicate, 27, // Predicate_atomic_swap_32_acq_rel
/* 13478*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13480*/        OPC_EmitMergeInputChains1_0,
/* 13481*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_swap:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_acq_rel>> - Complexity = 4
                  // Dst: (AMOSWAP_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13489*/      /*Scope*/ 13, /*->13503*/
/* 13490*/        OPC_CheckPredicate, 28, // Predicate_atomic_swap_32_seq_cst
/* 13492*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13494*/        OPC_EmitMergeInputChains1_0,
/* 13495*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOSWAP_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_swap:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_swap_32>><<P:Predicate_atomic_swap_32_seq_cst>> - Complexity = 4
                  // Dst: (AMOSWAP_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13503*/      0, /*End of Scope*/
/* 13504*/    0, // EndSwitchType
/* 13505*/  /*SwitchOpcode*/ 111|128,1/*239*/, TARGET_VAL(ISD::ATOMIC_LOAD_ADD),// ->13748
/* 13509*/    OPC_RecordMemRef,
/* 13510*/    OPC_RecordNode, // #0 = 'atomic_load_add' chained node
/* 13511*/    OPC_RecordChild1, // #1 = $rs1
/* 13512*/    OPC_SwitchType /*2 cases */, 24|128,1/*152*/, MVT::i32,// ->13668
/* 13516*/      OPC_CheckChild1Type, MVT::i32,
/* 13518*/      OPC_RecordChild2, // #2 = $rs2
/* 13519*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_add_32
/* 13521*/      OPC_Scope, 28, /*->13551*/ // 5 children in Scope
/* 13523*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_add_32_monotonic
/* 13525*/        OPC_Scope, 11, /*->13538*/ // 2 children in Scope
/* 13527*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13529*/          OPC_EmitMergeInputChains1_0,
/* 13530*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_monotonic>> - Complexity = 4
                    // Dst: (AMOADD_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13538*/        /*Scope*/ 11, /*->13550*/
/* 13539*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13541*/          OPC_EmitMergeInputChains1_0,
/* 13542*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_monotonic>> - Complexity = 4
                    // Dst: (AMOADD_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13550*/        0, /*End of Scope*/
/* 13551*/      /*Scope*/ 28, /*->13580*/
/* 13552*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_add_32_acquire
/* 13554*/        OPC_Scope, 11, /*->13567*/ // 2 children in Scope
/* 13556*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13558*/          OPC_EmitMergeInputChains1_0,
/* 13559*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_acquire>> - Complexity = 4
                    // Dst: (AMOADD_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13567*/        /*Scope*/ 11, /*->13579*/
/* 13568*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13570*/          OPC_EmitMergeInputChains1_0,
/* 13571*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_acquire>> - Complexity = 4
                    // Dst: (AMOADD_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13579*/        0, /*End of Scope*/
/* 13580*/      /*Scope*/ 28, /*->13609*/
/* 13581*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_add_32_release
/* 13583*/        OPC_Scope, 11, /*->13596*/ // 2 children in Scope
/* 13585*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13587*/          OPC_EmitMergeInputChains1_0,
/* 13588*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_release>> - Complexity = 4
                    // Dst: (AMOADD_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13596*/        /*Scope*/ 11, /*->13608*/
/* 13597*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13599*/          OPC_EmitMergeInputChains1_0,
/* 13600*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_release>> - Complexity = 4
                    // Dst: (AMOADD_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13608*/        0, /*End of Scope*/
/* 13609*/      /*Scope*/ 28, /*->13638*/
/* 13610*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_add_32_acq_rel
/* 13612*/        OPC_Scope, 11, /*->13625*/ // 2 children in Scope
/* 13614*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13616*/          OPC_EmitMergeInputChains1_0,
/* 13617*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOADD_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13625*/        /*Scope*/ 11, /*->13637*/
/* 13626*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13628*/          OPC_EmitMergeInputChains1_0,
/* 13629*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOADD_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13637*/        0, /*End of Scope*/
/* 13638*/      /*Scope*/ 28, /*->13667*/
/* 13639*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_add_32_seq_cst
/* 13641*/        OPC_Scope, 11, /*->13654*/ // 2 children in Scope
/* 13643*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13645*/          OPC_EmitMergeInputChains1_0,
/* 13646*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOADD_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13654*/        /*Scope*/ 11, /*->13666*/
/* 13655*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13657*/          OPC_EmitMergeInputChains1_0,
/* 13658*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_add:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOADD_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13666*/        0, /*End of Scope*/
/* 13667*/      0, /*End of Scope*/
/* 13668*/    /*SwitchType*/ 77, MVT::i64,// ->13747
/* 13670*/      OPC_CheckChild1Type, MVT::i64,
/* 13672*/      OPC_RecordChild2, // #2 = $rs2
/* 13673*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_add_32
/* 13675*/      OPC_Scope, 13, /*->13690*/ // 5 children in Scope
/* 13677*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_add_32_monotonic
/* 13679*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13681*/        OPC_EmitMergeInputChains1_0,
/* 13682*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_monotonic>> - Complexity = 4
                  // Dst: (AMOADD_W:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13690*/      /*Scope*/ 13, /*->13704*/
/* 13691*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_add_32_acquire
/* 13693*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13695*/        OPC_EmitMergeInputChains1_0,
/* 13696*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_acquire>> - Complexity = 4
                  // Dst: (AMOADD_W_AQ:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13704*/      /*Scope*/ 13, /*->13718*/
/* 13705*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_add_32_release
/* 13707*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13709*/        OPC_EmitMergeInputChains1_0,
/* 13710*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_release>> - Complexity = 4
                  // Dst: (AMOADD_W_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13718*/      /*Scope*/ 13, /*->13732*/
/* 13719*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_add_32_acq_rel
/* 13721*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13723*/        OPC_EmitMergeInputChains1_0,
/* 13724*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_acq_rel>> - Complexity = 4
                  // Dst: (AMOADD_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13732*/      /*Scope*/ 13, /*->13746*/
/* 13733*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_add_32_seq_cst
/* 13735*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13737*/        OPC_EmitMergeInputChains1_0,
/* 13738*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_add:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_add_32>><<P:Predicate_atomic_load_add_32_seq_cst>> - Complexity = 4
                  // Dst: (AMOADD_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13746*/      0, /*End of Scope*/
/* 13747*/    0, // EndSwitchType
/* 13748*/  /*SwitchOpcode*/ 111|128,1/*239*/, TARGET_VAL(ISD::ATOMIC_LOAD_AND),// ->13991
/* 13752*/    OPC_RecordMemRef,
/* 13753*/    OPC_RecordNode, // #0 = 'atomic_load_and' chained node
/* 13754*/    OPC_RecordChild1, // #1 = $rs1
/* 13755*/    OPC_SwitchType /*2 cases */, 24|128,1/*152*/, MVT::i32,// ->13911
/* 13759*/      OPC_CheckChild1Type, MVT::i32,
/* 13761*/      OPC_RecordChild2, // #2 = $rs2
/* 13762*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_and_32
/* 13764*/      OPC_Scope, 28, /*->13794*/ // 5 children in Scope
/* 13766*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_and_32_monotonic
/* 13768*/        OPC_Scope, 11, /*->13781*/ // 2 children in Scope
/* 13770*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13772*/          OPC_EmitMergeInputChains1_0,
/* 13773*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_monotonic>> - Complexity = 4
                    // Dst: (AMOAND_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13781*/        /*Scope*/ 11, /*->13793*/
/* 13782*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13784*/          OPC_EmitMergeInputChains1_0,
/* 13785*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_monotonic>> - Complexity = 4
                    // Dst: (AMOAND_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13793*/        0, /*End of Scope*/
/* 13794*/      /*Scope*/ 28, /*->13823*/
/* 13795*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_and_32_acquire
/* 13797*/        OPC_Scope, 11, /*->13810*/ // 2 children in Scope
/* 13799*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13801*/          OPC_EmitMergeInputChains1_0,
/* 13802*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_acquire>> - Complexity = 4
                    // Dst: (AMOAND_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13810*/        /*Scope*/ 11, /*->13822*/
/* 13811*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13813*/          OPC_EmitMergeInputChains1_0,
/* 13814*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_acquire>> - Complexity = 4
                    // Dst: (AMOAND_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13822*/        0, /*End of Scope*/
/* 13823*/      /*Scope*/ 28, /*->13852*/
/* 13824*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_and_32_release
/* 13826*/        OPC_Scope, 11, /*->13839*/ // 2 children in Scope
/* 13828*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13830*/          OPC_EmitMergeInputChains1_0,
/* 13831*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_release>> - Complexity = 4
                    // Dst: (AMOAND_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13839*/        /*Scope*/ 11, /*->13851*/
/* 13840*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13842*/          OPC_EmitMergeInputChains1_0,
/* 13843*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_release>> - Complexity = 4
                    // Dst: (AMOAND_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13851*/        0, /*End of Scope*/
/* 13852*/      /*Scope*/ 28, /*->13881*/
/* 13853*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_and_32_acq_rel
/* 13855*/        OPC_Scope, 11, /*->13868*/ // 2 children in Scope
/* 13857*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13859*/          OPC_EmitMergeInputChains1_0,
/* 13860*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOAND_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13868*/        /*Scope*/ 11, /*->13880*/
/* 13869*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13871*/          OPC_EmitMergeInputChains1_0,
/* 13872*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOAND_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13880*/        0, /*End of Scope*/
/* 13881*/      /*Scope*/ 28, /*->13910*/
/* 13882*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_and_32_seq_cst
/* 13884*/        OPC_Scope, 11, /*->13897*/ // 2 children in Scope
/* 13886*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 13888*/          OPC_EmitMergeInputChains1_0,
/* 13889*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOAND_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13897*/        /*Scope*/ 11, /*->13909*/
/* 13898*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 13900*/          OPC_EmitMergeInputChains1_0,
/* 13901*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_and:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOAND_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 13909*/        0, /*End of Scope*/
/* 13910*/      0, /*End of Scope*/
/* 13911*/    /*SwitchType*/ 77, MVT::i64,// ->13990
/* 13913*/      OPC_CheckChild1Type, MVT::i64,
/* 13915*/      OPC_RecordChild2, // #2 = $rs2
/* 13916*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_and_32
/* 13918*/      OPC_Scope, 13, /*->13933*/ // 5 children in Scope
/* 13920*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_and_32_monotonic
/* 13922*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13924*/        OPC_EmitMergeInputChains1_0,
/* 13925*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_and:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_monotonic>> - Complexity = 4
                  // Dst: (AMOAND_W:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13933*/      /*Scope*/ 13, /*->13947*/
/* 13934*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_and_32_acquire
/* 13936*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13938*/        OPC_EmitMergeInputChains1_0,
/* 13939*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_and:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_acquire>> - Complexity = 4
                  // Dst: (AMOAND_W_AQ:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13947*/      /*Scope*/ 13, /*->13961*/
/* 13948*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_and_32_release
/* 13950*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13952*/        OPC_EmitMergeInputChains1_0,
/* 13953*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_and:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_release>> - Complexity = 4
                  // Dst: (AMOAND_W_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13961*/      /*Scope*/ 13, /*->13975*/
/* 13962*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_and_32_acq_rel
/* 13964*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13966*/        OPC_EmitMergeInputChains1_0,
/* 13967*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_and:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_acq_rel>> - Complexity = 4
                  // Dst: (AMOAND_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13975*/      /*Scope*/ 13, /*->13989*/
/* 13976*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_and_32_seq_cst
/* 13978*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 13980*/        OPC_EmitMergeInputChains1_0,
/* 13981*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOAND_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_and:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_and_32>><<P:Predicate_atomic_load_and_32_seq_cst>> - Complexity = 4
                  // Dst: (AMOAND_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 13989*/      0, /*End of Scope*/
/* 13990*/    0, // EndSwitchType
/* 13991*/  /*SwitchOpcode*/ 111|128,1/*239*/, TARGET_VAL(ISD::ATOMIC_LOAD_OR),// ->14234
/* 13995*/    OPC_RecordMemRef,
/* 13996*/    OPC_RecordNode, // #0 = 'atomic_load_or' chained node
/* 13997*/    OPC_RecordChild1, // #1 = $rs1
/* 13998*/    OPC_SwitchType /*2 cases */, 24|128,1/*152*/, MVT::i32,// ->14154
/* 14002*/      OPC_CheckChild1Type, MVT::i32,
/* 14004*/      OPC_RecordChild2, // #2 = $rs2
/* 14005*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_or_32
/* 14007*/      OPC_Scope, 28, /*->14037*/ // 5 children in Scope
/* 14009*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_or_32_monotonic
/* 14011*/        OPC_Scope, 11, /*->14024*/ // 2 children in Scope
/* 14013*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14015*/          OPC_EmitMergeInputChains1_0,
/* 14016*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_monotonic>> - Complexity = 4
                    // Dst: (AMOOR_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14024*/        /*Scope*/ 11, /*->14036*/
/* 14025*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14027*/          OPC_EmitMergeInputChains1_0,
/* 14028*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_monotonic>> - Complexity = 4
                    // Dst: (AMOOR_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14036*/        0, /*End of Scope*/
/* 14037*/      /*Scope*/ 28, /*->14066*/
/* 14038*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_or_32_acquire
/* 14040*/        OPC_Scope, 11, /*->14053*/ // 2 children in Scope
/* 14042*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14044*/          OPC_EmitMergeInputChains1_0,
/* 14045*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_acquire>> - Complexity = 4
                    // Dst: (AMOOR_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14053*/        /*Scope*/ 11, /*->14065*/
/* 14054*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14056*/          OPC_EmitMergeInputChains1_0,
/* 14057*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_acquire>> - Complexity = 4
                    // Dst: (AMOOR_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14065*/        0, /*End of Scope*/
/* 14066*/      /*Scope*/ 28, /*->14095*/
/* 14067*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_or_32_release
/* 14069*/        OPC_Scope, 11, /*->14082*/ // 2 children in Scope
/* 14071*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14073*/          OPC_EmitMergeInputChains1_0,
/* 14074*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_release>> - Complexity = 4
                    // Dst: (AMOOR_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14082*/        /*Scope*/ 11, /*->14094*/
/* 14083*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14085*/          OPC_EmitMergeInputChains1_0,
/* 14086*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_release>> - Complexity = 4
                    // Dst: (AMOOR_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14094*/        0, /*End of Scope*/
/* 14095*/      /*Scope*/ 28, /*->14124*/
/* 14096*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_or_32_acq_rel
/* 14098*/        OPC_Scope, 11, /*->14111*/ // 2 children in Scope
/* 14100*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14102*/          OPC_EmitMergeInputChains1_0,
/* 14103*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOOR_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14111*/        /*Scope*/ 11, /*->14123*/
/* 14112*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14114*/          OPC_EmitMergeInputChains1_0,
/* 14115*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOOR_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14123*/        0, /*End of Scope*/
/* 14124*/      /*Scope*/ 28, /*->14153*/
/* 14125*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_or_32_seq_cst
/* 14127*/        OPC_Scope, 11, /*->14140*/ // 2 children in Scope
/* 14129*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14131*/          OPC_EmitMergeInputChains1_0,
/* 14132*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOOR_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14140*/        /*Scope*/ 11, /*->14152*/
/* 14141*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14143*/          OPC_EmitMergeInputChains1_0,
/* 14144*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_or:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOOR_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14152*/        0, /*End of Scope*/
/* 14153*/      0, /*End of Scope*/
/* 14154*/    /*SwitchType*/ 77, MVT::i64,// ->14233
/* 14156*/      OPC_CheckChild1Type, MVT::i64,
/* 14158*/      OPC_RecordChild2, // #2 = $rs2
/* 14159*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_or_32
/* 14161*/      OPC_Scope, 13, /*->14176*/ // 5 children in Scope
/* 14163*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_or_32_monotonic
/* 14165*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14167*/        OPC_EmitMergeInputChains1_0,
/* 14168*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_or:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_monotonic>> - Complexity = 4
                  // Dst: (AMOOR_W:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14176*/      /*Scope*/ 13, /*->14190*/
/* 14177*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_or_32_acquire
/* 14179*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14181*/        OPC_EmitMergeInputChains1_0,
/* 14182*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_or:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_acquire>> - Complexity = 4
                  // Dst: (AMOOR_W_AQ:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14190*/      /*Scope*/ 13, /*->14204*/
/* 14191*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_or_32_release
/* 14193*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14195*/        OPC_EmitMergeInputChains1_0,
/* 14196*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_or:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_release>> - Complexity = 4
                  // Dst: (AMOOR_W_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14204*/      /*Scope*/ 13, /*->14218*/
/* 14205*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_or_32_acq_rel
/* 14207*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14209*/        OPC_EmitMergeInputChains1_0,
/* 14210*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_or:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_acq_rel>> - Complexity = 4
                  // Dst: (AMOOR_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14218*/      /*Scope*/ 13, /*->14232*/
/* 14219*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_or_32_seq_cst
/* 14221*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14223*/        OPC_EmitMergeInputChains1_0,
/* 14224*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOOR_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_or:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_or_32>><<P:Predicate_atomic_load_or_32_seq_cst>> - Complexity = 4
                  // Dst: (AMOOR_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14232*/      0, /*End of Scope*/
/* 14233*/    0, // EndSwitchType
/* 14234*/  /*SwitchOpcode*/ 111|128,1/*239*/, TARGET_VAL(ISD::ATOMIC_LOAD_XOR),// ->14477
/* 14238*/    OPC_RecordMemRef,
/* 14239*/    OPC_RecordNode, // #0 = 'atomic_load_xor' chained node
/* 14240*/    OPC_RecordChild1, // #1 = $rs1
/* 14241*/    OPC_SwitchType /*2 cases */, 24|128,1/*152*/, MVT::i32,// ->14397
/* 14245*/      OPC_CheckChild1Type, MVT::i32,
/* 14247*/      OPC_RecordChild2, // #2 = $rs2
/* 14248*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_xor_32
/* 14250*/      OPC_Scope, 28, /*->14280*/ // 5 children in Scope
/* 14252*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_xor_32_monotonic
/* 14254*/        OPC_Scope, 11, /*->14267*/ // 2 children in Scope
/* 14256*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14258*/          OPC_EmitMergeInputChains1_0,
/* 14259*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_monotonic>> - Complexity = 4
                    // Dst: (AMOXOR_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14267*/        /*Scope*/ 11, /*->14279*/
/* 14268*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14270*/          OPC_EmitMergeInputChains1_0,
/* 14271*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_monotonic>> - Complexity = 4
                    // Dst: (AMOXOR_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14279*/        0, /*End of Scope*/
/* 14280*/      /*Scope*/ 28, /*->14309*/
/* 14281*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_xor_32_acquire
/* 14283*/        OPC_Scope, 11, /*->14296*/ // 2 children in Scope
/* 14285*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14287*/          OPC_EmitMergeInputChains1_0,
/* 14288*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_acquire>> - Complexity = 4
                    // Dst: (AMOXOR_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14296*/        /*Scope*/ 11, /*->14308*/
/* 14297*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14299*/          OPC_EmitMergeInputChains1_0,
/* 14300*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_acquire>> - Complexity = 4
                    // Dst: (AMOXOR_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14308*/        0, /*End of Scope*/
/* 14309*/      /*Scope*/ 28, /*->14338*/
/* 14310*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_xor_32_release
/* 14312*/        OPC_Scope, 11, /*->14325*/ // 2 children in Scope
/* 14314*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14316*/          OPC_EmitMergeInputChains1_0,
/* 14317*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_release>> - Complexity = 4
                    // Dst: (AMOXOR_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14325*/        /*Scope*/ 11, /*->14337*/
/* 14326*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14328*/          OPC_EmitMergeInputChains1_0,
/* 14329*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_release>> - Complexity = 4
                    // Dst: (AMOXOR_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14337*/        0, /*End of Scope*/
/* 14338*/      /*Scope*/ 28, /*->14367*/
/* 14339*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_xor_32_acq_rel
/* 14341*/        OPC_Scope, 11, /*->14354*/ // 2 children in Scope
/* 14343*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14345*/          OPC_EmitMergeInputChains1_0,
/* 14346*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOXOR_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14354*/        /*Scope*/ 11, /*->14366*/
/* 14355*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14357*/          OPC_EmitMergeInputChains1_0,
/* 14358*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOXOR_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14366*/        0, /*End of Scope*/
/* 14367*/      /*Scope*/ 28, /*->14396*/
/* 14368*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_xor_32_seq_cst
/* 14370*/        OPC_Scope, 11, /*->14383*/ // 2 children in Scope
/* 14372*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14374*/          OPC_EmitMergeInputChains1_0,
/* 14375*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOXOR_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14383*/        /*Scope*/ 11, /*->14395*/
/* 14384*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14386*/          OPC_EmitMergeInputChains1_0,
/* 14387*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_xor:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOXOR_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14395*/        0, /*End of Scope*/
/* 14396*/      0, /*End of Scope*/
/* 14397*/    /*SwitchType*/ 77, MVT::i64,// ->14476
/* 14399*/      OPC_CheckChild1Type, MVT::i64,
/* 14401*/      OPC_RecordChild2, // #2 = $rs2
/* 14402*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_xor_32
/* 14404*/      OPC_Scope, 13, /*->14419*/ // 5 children in Scope
/* 14406*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_xor_32_monotonic
/* 14408*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14410*/        OPC_EmitMergeInputChains1_0,
/* 14411*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_xor:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_monotonic>> - Complexity = 4
                  // Dst: (AMOXOR_W:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14419*/      /*Scope*/ 13, /*->14433*/
/* 14420*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_xor_32_acquire
/* 14422*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14424*/        OPC_EmitMergeInputChains1_0,
/* 14425*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_xor:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_acquire>> - Complexity = 4
                  // Dst: (AMOXOR_W_AQ:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14433*/      /*Scope*/ 13, /*->14447*/
/* 14434*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_xor_32_release
/* 14436*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14438*/        OPC_EmitMergeInputChains1_0,
/* 14439*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_xor:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_release>> - Complexity = 4
                  // Dst: (AMOXOR_W_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14447*/      /*Scope*/ 13, /*->14461*/
/* 14448*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_xor_32_acq_rel
/* 14450*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14452*/        OPC_EmitMergeInputChains1_0,
/* 14453*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_xor:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_acq_rel>> - Complexity = 4
                  // Dst: (AMOXOR_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14461*/      /*Scope*/ 13, /*->14475*/
/* 14462*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_xor_32_seq_cst
/* 14464*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14466*/        OPC_EmitMergeInputChains1_0,
/* 14467*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOXOR_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_xor:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_xor_32>><<P:Predicate_atomic_load_xor_32_seq_cst>> - Complexity = 4
                  // Dst: (AMOXOR_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14475*/      0, /*End of Scope*/
/* 14476*/    0, // EndSwitchType
/* 14477*/  /*SwitchOpcode*/ 111|128,1/*239*/, TARGET_VAL(ISD::ATOMIC_LOAD_MAX),// ->14720
/* 14481*/    OPC_RecordMemRef,
/* 14482*/    OPC_RecordNode, // #0 = 'atomic_load_max' chained node
/* 14483*/    OPC_RecordChild1, // #1 = $rs1
/* 14484*/    OPC_SwitchType /*2 cases */, 24|128,1/*152*/, MVT::i32,// ->14640
/* 14488*/      OPC_CheckChild1Type, MVT::i32,
/* 14490*/      OPC_RecordChild2, // #2 = $rs2
/* 14491*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_max_32
/* 14493*/      OPC_Scope, 28, /*->14523*/ // 5 children in Scope
/* 14495*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_max_32_monotonic
/* 14497*/        OPC_Scope, 11, /*->14510*/ // 2 children in Scope
/* 14499*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14501*/          OPC_EmitMergeInputChains1_0,
/* 14502*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_max:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_monotonic>> - Complexity = 4
                    // Dst: (AMOMAX_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14510*/        /*Scope*/ 11, /*->14522*/
/* 14511*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14513*/          OPC_EmitMergeInputChains1_0,
/* 14514*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_max:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_monotonic>> - Complexity = 4
                    // Dst: (AMOMAX_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14522*/        0, /*End of Scope*/
/* 14523*/      /*Scope*/ 28, /*->14552*/
/* 14524*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_max_32_acquire
/* 14526*/        OPC_Scope, 11, /*->14539*/ // 2 children in Scope
/* 14528*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14530*/          OPC_EmitMergeInputChains1_0,
/* 14531*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_max:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_acquire>> - Complexity = 4
                    // Dst: (AMOMAX_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14539*/        /*Scope*/ 11, /*->14551*/
/* 14540*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14542*/          OPC_EmitMergeInputChains1_0,
/* 14543*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_max:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_acquire>> - Complexity = 4
                    // Dst: (AMOMAX_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14551*/        0, /*End of Scope*/
/* 14552*/      /*Scope*/ 28, /*->14581*/
/* 14553*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_max_32_release
/* 14555*/        OPC_Scope, 11, /*->14568*/ // 2 children in Scope
/* 14557*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14559*/          OPC_EmitMergeInputChains1_0,
/* 14560*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_max:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_release>> - Complexity = 4
                    // Dst: (AMOMAX_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14568*/        /*Scope*/ 11, /*->14580*/
/* 14569*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14571*/          OPC_EmitMergeInputChains1_0,
/* 14572*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_max:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_release>> - Complexity = 4
                    // Dst: (AMOMAX_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14580*/        0, /*End of Scope*/
/* 14581*/      /*Scope*/ 28, /*->14610*/
/* 14582*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_max_32_acq_rel
/* 14584*/        OPC_Scope, 11, /*->14597*/ // 2 children in Scope
/* 14586*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14588*/          OPC_EmitMergeInputChains1_0,
/* 14589*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_max:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOMAX_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14597*/        /*Scope*/ 11, /*->14609*/
/* 14598*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14600*/          OPC_EmitMergeInputChains1_0,
/* 14601*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_max:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOMAX_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14609*/        0, /*End of Scope*/
/* 14610*/      /*Scope*/ 28, /*->14639*/
/* 14611*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_max_32_seq_cst
/* 14613*/        OPC_Scope, 11, /*->14626*/ // 2 children in Scope
/* 14615*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14617*/          OPC_EmitMergeInputChains1_0,
/* 14618*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_max:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOMAX_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14626*/        /*Scope*/ 11, /*->14638*/
/* 14627*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14629*/          OPC_EmitMergeInputChains1_0,
/* 14630*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_max:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOMAX_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14638*/        0, /*End of Scope*/
/* 14639*/      0, /*End of Scope*/
/* 14640*/    /*SwitchType*/ 77, MVT::i64,// ->14719
/* 14642*/      OPC_CheckChild1Type, MVT::i64,
/* 14644*/      OPC_RecordChild2, // #2 = $rs2
/* 14645*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_max_32
/* 14647*/      OPC_Scope, 13, /*->14662*/ // 5 children in Scope
/* 14649*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_max_32_monotonic
/* 14651*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14653*/        OPC_EmitMergeInputChains1_0,
/* 14654*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_max:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_monotonic>> - Complexity = 4
                  // Dst: (AMOMAX_W:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14662*/      /*Scope*/ 13, /*->14676*/
/* 14663*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_max_32_acquire
/* 14665*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14667*/        OPC_EmitMergeInputChains1_0,
/* 14668*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_max:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_acquire>> - Complexity = 4
                  // Dst: (AMOMAX_W_AQ:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14676*/      /*Scope*/ 13, /*->14690*/
/* 14677*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_max_32_release
/* 14679*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14681*/        OPC_EmitMergeInputChains1_0,
/* 14682*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_max:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_release>> - Complexity = 4
                  // Dst: (AMOMAX_W_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14690*/      /*Scope*/ 13, /*->14704*/
/* 14691*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_max_32_acq_rel
/* 14693*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14695*/        OPC_EmitMergeInputChains1_0,
/* 14696*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_max:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_acq_rel>> - Complexity = 4
                  // Dst: (AMOMAX_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14704*/      /*Scope*/ 13, /*->14718*/
/* 14705*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_max_32_seq_cst
/* 14707*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14709*/        OPC_EmitMergeInputChains1_0,
/* 14710*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAX_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_max:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_max_32>><<P:Predicate_atomic_load_max_32_seq_cst>> - Complexity = 4
                  // Dst: (AMOMAX_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14718*/      0, /*End of Scope*/
/* 14719*/    0, // EndSwitchType
/* 14720*/  /*SwitchOpcode*/ 111|128,1/*239*/, TARGET_VAL(ISD::ATOMIC_LOAD_MIN),// ->14963
/* 14724*/    OPC_RecordMemRef,
/* 14725*/    OPC_RecordNode, // #0 = 'atomic_load_min' chained node
/* 14726*/    OPC_RecordChild1, // #1 = $rs1
/* 14727*/    OPC_SwitchType /*2 cases */, 24|128,1/*152*/, MVT::i32,// ->14883
/* 14731*/      OPC_CheckChild1Type, MVT::i32,
/* 14733*/      OPC_RecordChild2, // #2 = $rs2
/* 14734*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_min_32
/* 14736*/      OPC_Scope, 28, /*->14766*/ // 5 children in Scope
/* 14738*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_min_32_monotonic
/* 14740*/        OPC_Scope, 11, /*->14753*/ // 2 children in Scope
/* 14742*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14744*/          OPC_EmitMergeInputChains1_0,
/* 14745*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_min:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_monotonic>> - Complexity = 4
                    // Dst: (AMOMIN_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14753*/        /*Scope*/ 11, /*->14765*/
/* 14754*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14756*/          OPC_EmitMergeInputChains1_0,
/* 14757*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_min:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_monotonic>> - Complexity = 4
                    // Dst: (AMOMIN_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14765*/        0, /*End of Scope*/
/* 14766*/      /*Scope*/ 28, /*->14795*/
/* 14767*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_min_32_acquire
/* 14769*/        OPC_Scope, 11, /*->14782*/ // 2 children in Scope
/* 14771*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14773*/          OPC_EmitMergeInputChains1_0,
/* 14774*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_min:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_acquire>> - Complexity = 4
                    // Dst: (AMOMIN_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14782*/        /*Scope*/ 11, /*->14794*/
/* 14783*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14785*/          OPC_EmitMergeInputChains1_0,
/* 14786*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_min:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_acquire>> - Complexity = 4
                    // Dst: (AMOMIN_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14794*/        0, /*End of Scope*/
/* 14795*/      /*Scope*/ 28, /*->14824*/
/* 14796*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_min_32_release
/* 14798*/        OPC_Scope, 11, /*->14811*/ // 2 children in Scope
/* 14800*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14802*/          OPC_EmitMergeInputChains1_0,
/* 14803*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_min:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_release>> - Complexity = 4
                    // Dst: (AMOMIN_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14811*/        /*Scope*/ 11, /*->14823*/
/* 14812*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14814*/          OPC_EmitMergeInputChains1_0,
/* 14815*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_min:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_release>> - Complexity = 4
                    // Dst: (AMOMIN_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14823*/        0, /*End of Scope*/
/* 14824*/      /*Scope*/ 28, /*->14853*/
/* 14825*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_min_32_acq_rel
/* 14827*/        OPC_Scope, 11, /*->14840*/ // 2 children in Scope
/* 14829*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14831*/          OPC_EmitMergeInputChains1_0,
/* 14832*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_min:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOMIN_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14840*/        /*Scope*/ 11, /*->14852*/
/* 14841*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14843*/          OPC_EmitMergeInputChains1_0,
/* 14844*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_min:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOMIN_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14852*/        0, /*End of Scope*/
/* 14853*/      /*Scope*/ 28, /*->14882*/
/* 14854*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_min_32_seq_cst
/* 14856*/        OPC_Scope, 11, /*->14869*/ // 2 children in Scope
/* 14858*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14860*/          OPC_EmitMergeInputChains1_0,
/* 14861*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_min:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOMIN_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14869*/        /*Scope*/ 11, /*->14881*/
/* 14870*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14872*/          OPC_EmitMergeInputChains1_0,
/* 14873*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_min:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOMIN_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14881*/        0, /*End of Scope*/
/* 14882*/      0, /*End of Scope*/
/* 14883*/    /*SwitchType*/ 77, MVT::i64,// ->14962
/* 14885*/      OPC_CheckChild1Type, MVT::i64,
/* 14887*/      OPC_RecordChild2, // #2 = $rs2
/* 14888*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_min_32
/* 14890*/      OPC_Scope, 13, /*->14905*/ // 5 children in Scope
/* 14892*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_min_32_monotonic
/* 14894*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14896*/        OPC_EmitMergeInputChains1_0,
/* 14897*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_min:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_monotonic>> - Complexity = 4
                  // Dst: (AMOMIN_W:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14905*/      /*Scope*/ 13, /*->14919*/
/* 14906*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_min_32_acquire
/* 14908*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14910*/        OPC_EmitMergeInputChains1_0,
/* 14911*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_min:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_acquire>> - Complexity = 4
                  // Dst: (AMOMIN_W_AQ:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14919*/      /*Scope*/ 13, /*->14933*/
/* 14920*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_min_32_release
/* 14922*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14924*/        OPC_EmitMergeInputChains1_0,
/* 14925*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_min:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_release>> - Complexity = 4
                  // Dst: (AMOMIN_W_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14933*/      /*Scope*/ 13, /*->14947*/
/* 14934*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_min_32_acq_rel
/* 14936*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14938*/        OPC_EmitMergeInputChains1_0,
/* 14939*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_min:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_acq_rel>> - Complexity = 4
                  // Dst: (AMOMIN_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14947*/      /*Scope*/ 13, /*->14961*/
/* 14948*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_min_32_seq_cst
/* 14950*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 14952*/        OPC_EmitMergeInputChains1_0,
/* 14953*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMIN_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_min:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_min_32>><<P:Predicate_atomic_load_min_32_seq_cst>> - Complexity = 4
                  // Dst: (AMOMIN_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 14961*/      0, /*End of Scope*/
/* 14962*/    0, // EndSwitchType
/* 14963*/  /*SwitchOpcode*/ 111|128,1/*239*/, TARGET_VAL(ISD::ATOMIC_LOAD_UMAX),// ->15206
/* 14967*/    OPC_RecordMemRef,
/* 14968*/    OPC_RecordNode, // #0 = 'atomic_load_umax' chained node
/* 14969*/    OPC_RecordChild1, // #1 = $rs1
/* 14970*/    OPC_SwitchType /*2 cases */, 24|128,1/*152*/, MVT::i32,// ->15126
/* 14974*/      OPC_CheckChild1Type, MVT::i32,
/* 14976*/      OPC_RecordChild2, // #2 = $rs2
/* 14977*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_umax_32
/* 14979*/      OPC_Scope, 28, /*->15009*/ // 5 children in Scope
/* 14981*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_umax_32_monotonic
/* 14983*/        OPC_Scope, 11, /*->14996*/ // 2 children in Scope
/* 14985*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 14987*/          OPC_EmitMergeInputChains1_0,
/* 14988*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umax:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_monotonic>> - Complexity = 4
                    // Dst: (AMOMAXU_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 14996*/        /*Scope*/ 11, /*->15008*/
/* 14997*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 14999*/          OPC_EmitMergeInputChains1_0,
/* 15000*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umax:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_monotonic>> - Complexity = 4
                    // Dst: (AMOMAXU_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15008*/        0, /*End of Scope*/
/* 15009*/      /*Scope*/ 28, /*->15038*/
/* 15010*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_umax_32_acquire
/* 15012*/        OPC_Scope, 11, /*->15025*/ // 2 children in Scope
/* 15014*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15016*/          OPC_EmitMergeInputChains1_0,
/* 15017*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umax:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_acquire>> - Complexity = 4
                    // Dst: (AMOMAXU_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15025*/        /*Scope*/ 11, /*->15037*/
/* 15026*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15028*/          OPC_EmitMergeInputChains1_0,
/* 15029*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umax:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_acquire>> - Complexity = 4
                    // Dst: (AMOMAXU_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15037*/        0, /*End of Scope*/
/* 15038*/      /*Scope*/ 28, /*->15067*/
/* 15039*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_umax_32_release
/* 15041*/        OPC_Scope, 11, /*->15054*/ // 2 children in Scope
/* 15043*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15045*/          OPC_EmitMergeInputChains1_0,
/* 15046*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umax:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_release>> - Complexity = 4
                    // Dst: (AMOMAXU_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15054*/        /*Scope*/ 11, /*->15066*/
/* 15055*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15057*/          OPC_EmitMergeInputChains1_0,
/* 15058*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umax:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_release>> - Complexity = 4
                    // Dst: (AMOMAXU_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15066*/        0, /*End of Scope*/
/* 15067*/      /*Scope*/ 28, /*->15096*/
/* 15068*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_umax_32_acq_rel
/* 15070*/        OPC_Scope, 11, /*->15083*/ // 2 children in Scope
/* 15072*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15074*/          OPC_EmitMergeInputChains1_0,
/* 15075*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umax:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOMAXU_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15083*/        /*Scope*/ 11, /*->15095*/
/* 15084*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15086*/          OPC_EmitMergeInputChains1_0,
/* 15087*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umax:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOMAXU_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15095*/        0, /*End of Scope*/
/* 15096*/      /*Scope*/ 28, /*->15125*/
/* 15097*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_umax_32_seq_cst
/* 15099*/        OPC_Scope, 11, /*->15112*/ // 2 children in Scope
/* 15101*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15103*/          OPC_EmitMergeInputChains1_0,
/* 15104*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umax:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOMAXU_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15112*/        /*Scope*/ 11, /*->15124*/
/* 15113*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15115*/          OPC_EmitMergeInputChains1_0,
/* 15116*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umax:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOMAXU_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15124*/        0, /*End of Scope*/
/* 15125*/      0, /*End of Scope*/
/* 15126*/    /*SwitchType*/ 77, MVT::i64,// ->15205
/* 15128*/      OPC_CheckChild1Type, MVT::i64,
/* 15130*/      OPC_RecordChild2, // #2 = $rs2
/* 15131*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_umax_32
/* 15133*/      OPC_Scope, 13, /*->15148*/ // 5 children in Scope
/* 15135*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_umax_32_monotonic
/* 15137*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15139*/        OPC_EmitMergeInputChains1_0,
/* 15140*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_umax:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_monotonic>> - Complexity = 4
                  // Dst: (AMOMAXU_W:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 15148*/      /*Scope*/ 13, /*->15162*/
/* 15149*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_umax_32_acquire
/* 15151*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15153*/        OPC_EmitMergeInputChains1_0,
/* 15154*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_umax:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_acquire>> - Complexity = 4
                  // Dst: (AMOMAXU_W_AQ:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 15162*/      /*Scope*/ 13, /*->15176*/
/* 15163*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_umax_32_release
/* 15165*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15167*/        OPC_EmitMergeInputChains1_0,
/* 15168*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_umax:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_release>> - Complexity = 4
                  // Dst: (AMOMAXU_W_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 15176*/      /*Scope*/ 13, /*->15190*/
/* 15177*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_umax_32_acq_rel
/* 15179*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15181*/        OPC_EmitMergeInputChains1_0,
/* 15182*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_umax:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_acq_rel>> - Complexity = 4
                  // Dst: (AMOMAXU_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 15190*/      /*Scope*/ 13, /*->15204*/
/* 15191*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_umax_32_seq_cst
/* 15193*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15195*/        OPC_EmitMergeInputChains1_0,
/* 15196*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMAXU_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_umax:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_umax_32>><<P:Predicate_atomic_load_umax_32_seq_cst>> - Complexity = 4
                  // Dst: (AMOMAXU_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 15204*/      0, /*End of Scope*/
/* 15205*/    0, // EndSwitchType
/* 15206*/  /*SwitchOpcode*/ 111|128,1/*239*/, TARGET_VAL(ISD::ATOMIC_LOAD_UMIN),// ->15449
/* 15210*/    OPC_RecordMemRef,
/* 15211*/    OPC_RecordNode, // #0 = 'atomic_load_umin' chained node
/* 15212*/    OPC_RecordChild1, // #1 = $rs1
/* 15213*/    OPC_SwitchType /*2 cases */, 24|128,1/*152*/, MVT::i32,// ->15369
/* 15217*/      OPC_CheckChild1Type, MVT::i32,
/* 15219*/      OPC_RecordChild2, // #2 = $rs2
/* 15220*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_umin_32
/* 15222*/      OPC_Scope, 28, /*->15252*/ // 5 children in Scope
/* 15224*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_umin_32_monotonic
/* 15226*/        OPC_Scope, 11, /*->15239*/ // 2 children in Scope
/* 15228*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15230*/          OPC_EmitMergeInputChains1_0,
/* 15231*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umin:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_monotonic>> - Complexity = 4
                    // Dst: (AMOMINU_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15239*/        /*Scope*/ 11, /*->15251*/
/* 15240*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15242*/          OPC_EmitMergeInputChains1_0,
/* 15243*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umin:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_monotonic>> - Complexity = 4
                    // Dst: (AMOMINU_W:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15251*/        0, /*End of Scope*/
/* 15252*/      /*Scope*/ 28, /*->15281*/
/* 15253*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_umin_32_acquire
/* 15255*/        OPC_Scope, 11, /*->15268*/ // 2 children in Scope
/* 15257*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15259*/          OPC_EmitMergeInputChains1_0,
/* 15260*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umin:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_acquire>> - Complexity = 4
                    // Dst: (AMOMINU_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15268*/        /*Scope*/ 11, /*->15280*/
/* 15269*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15271*/          OPC_EmitMergeInputChains1_0,
/* 15272*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umin:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_acquire>> - Complexity = 4
                    // Dst: (AMOMINU_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15280*/        0, /*End of Scope*/
/* 15281*/      /*Scope*/ 28, /*->15310*/
/* 15282*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_umin_32_release
/* 15284*/        OPC_Scope, 11, /*->15297*/ // 2 children in Scope
/* 15286*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15288*/          OPC_EmitMergeInputChains1_0,
/* 15289*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umin:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_release>> - Complexity = 4
                    // Dst: (AMOMINU_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15297*/        /*Scope*/ 11, /*->15309*/
/* 15298*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15300*/          OPC_EmitMergeInputChains1_0,
/* 15301*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umin:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_release>> - Complexity = 4
                    // Dst: (AMOMINU_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15309*/        0, /*End of Scope*/
/* 15310*/      /*Scope*/ 28, /*->15339*/
/* 15311*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_umin_32_acq_rel
/* 15313*/        OPC_Scope, 11, /*->15326*/ // 2 children in Scope
/* 15315*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15317*/          OPC_EmitMergeInputChains1_0,
/* 15318*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umin:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOMINU_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15326*/        /*Scope*/ 11, /*->15338*/
/* 15327*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15329*/          OPC_EmitMergeInputChains1_0,
/* 15330*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umin:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOMINU_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15338*/        0, /*End of Scope*/
/* 15339*/      /*Scope*/ 28, /*->15368*/
/* 15340*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_umin_32_seq_cst
/* 15342*/        OPC_Scope, 11, /*->15355*/ // 2 children in Scope
/* 15344*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15346*/          OPC_EmitMergeInputChains1_0,
/* 15347*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umin:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOMINU_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15355*/        /*Scope*/ 11, /*->15367*/
/* 15356*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15358*/          OPC_EmitMergeInputChains1_0,
/* 15359*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 2, 
                    // Src: (atomic_load_umin:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOMINU_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 15367*/        0, /*End of Scope*/
/* 15368*/      0, /*End of Scope*/
/* 15369*/    /*SwitchType*/ 77, MVT::i64,// ->15448
/* 15371*/      OPC_CheckChild1Type, MVT::i64,
/* 15373*/      OPC_RecordChild2, // #2 = $rs2
/* 15374*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_umin_32
/* 15376*/      OPC_Scope, 13, /*->15391*/ // 5 children in Scope
/* 15378*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_umin_32_monotonic
/* 15380*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15382*/        OPC_EmitMergeInputChains1_0,
/* 15383*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_umin:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_monotonic>> - Complexity = 4
                  // Dst: (AMOMINU_W:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 15391*/      /*Scope*/ 13, /*->15405*/
/* 15392*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_umin_32_acquire
/* 15394*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15396*/        OPC_EmitMergeInputChains1_0,
/* 15397*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_umin:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_acquire>> - Complexity = 4
                  // Dst: (AMOMINU_W_AQ:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 15405*/      /*Scope*/ 13, /*->15419*/
/* 15406*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_umin_32_release
/* 15408*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15410*/        OPC_EmitMergeInputChains1_0,
/* 15411*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_umin:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_release>> - Complexity = 4
                  // Dst: (AMOMINU_W_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 15419*/      /*Scope*/ 13, /*->15433*/
/* 15420*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_umin_32_acq_rel
/* 15422*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15424*/        OPC_EmitMergeInputChains1_0,
/* 15425*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_umin:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_acq_rel>> - Complexity = 4
                  // Dst: (AMOMINU_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 15433*/      /*Scope*/ 13, /*->15447*/
/* 15434*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_umin_32_seq_cst
/* 15436*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15438*/        OPC_EmitMergeInputChains1_0,
/* 15439*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOMINU_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 2, 
                  // Src: (atomic_load_umin:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)<<P:Predicate_atomic_load_umin_32>><<P:Predicate_atomic_load_umin_32_seq_cst>> - Complexity = 4
                  // Dst: (AMOMINU_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 15447*/      0, /*End of Scope*/
/* 15448*/    0, // EndSwitchType
/* 15449*/  /*SwitchOpcode*/ 58|128,2/*314*/, TARGET_VAL(ISD::ATOMIC_LOAD_NAND),// ->15767
/* 15453*/    OPC_RecordMemRef,
/* 15454*/    OPC_RecordNode, // #0 = 'atomic_load_nand' chained node
/* 15455*/    OPC_RecordChild1, // #1 = $addr
/* 15456*/    OPC_SwitchType /*2 cases */, 74|128,1/*202*/, MVT::i32,// ->15662
/* 15460*/      OPC_CheckChild1Type, MVT::i32,
/* 15462*/      OPC_RecordChild2, // #2 = $incr
/* 15463*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_nand_32
/* 15465*/      OPC_Scope, 38, /*->15505*/ // 5 children in Scope
/* 15467*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_nand_32_monotonic
/* 15469*/        OPC_Scope, 16, /*->15487*/ // 2 children in Scope
/* 15471*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15473*/          OPC_EmitMergeInputChains1_0,
/* 15474*/          OPC_EmitInteger, MVT::i32, 2, 
/* 15477*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 3/*#Ops*/, 1, 2, 3, 
                    // Src: (atomic_load_nand:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_monotonic>> - Complexity = 4
                    // Dst: (PseudoAtomicLoadNand32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, 2:{ *:[i32] })
/* 15487*/        /*Scope*/ 16, /*->15504*/
/* 15488*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15490*/          OPC_EmitMergeInputChains1_0,
/* 15491*/          OPC_EmitInteger, MVT::i32, 2, 
/* 15494*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 3/*#Ops*/, 1, 2, 3, 
                    // Src: (atomic_load_nand:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_monotonic>> - Complexity = 4
                    // Dst: (PseudoAtomicLoadNand32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, 2:{ *:[i32] })
/* 15504*/        0, /*End of Scope*/
/* 15505*/      /*Scope*/ 38, /*->15544*/
/* 15506*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_nand_32_acquire
/* 15508*/        OPC_Scope, 16, /*->15526*/ // 2 children in Scope
/* 15510*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15512*/          OPC_EmitMergeInputChains1_0,
/* 15513*/          OPC_EmitInteger, MVT::i32, 4, 
/* 15516*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 3/*#Ops*/, 1, 2, 3, 
                    // Src: (atomic_load_nand:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_acquire>> - Complexity = 4
                    // Dst: (PseudoAtomicLoadNand32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, 4:{ *:[i32] })
/* 15526*/        /*Scope*/ 16, /*->15543*/
/* 15527*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15529*/          OPC_EmitMergeInputChains1_0,
/* 15530*/          OPC_EmitInteger, MVT::i32, 4, 
/* 15533*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 3/*#Ops*/, 1, 2, 3, 
                    // Src: (atomic_load_nand:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_acquire>> - Complexity = 4
                    // Dst: (PseudoAtomicLoadNand32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, 4:{ *:[i32] })
/* 15543*/        0, /*End of Scope*/
/* 15544*/      /*Scope*/ 38, /*->15583*/
/* 15545*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_nand_32_release
/* 15547*/        OPC_Scope, 16, /*->15565*/ // 2 children in Scope
/* 15549*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15551*/          OPC_EmitMergeInputChains1_0,
/* 15552*/          OPC_EmitInteger, MVT::i32, 5, 
/* 15555*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 3/*#Ops*/, 1, 2, 3, 
                    // Src: (atomic_load_nand:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_release>> - Complexity = 4
                    // Dst: (PseudoAtomicLoadNand32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, 5:{ *:[i32] })
/* 15565*/        /*Scope*/ 16, /*->15582*/
/* 15566*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15568*/          OPC_EmitMergeInputChains1_0,
/* 15569*/          OPC_EmitInteger, MVT::i32, 5, 
/* 15572*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 3/*#Ops*/, 1, 2, 3, 
                    // Src: (atomic_load_nand:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_release>> - Complexity = 4
                    // Dst: (PseudoAtomicLoadNand32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, 5:{ *:[i32] })
/* 15582*/        0, /*End of Scope*/
/* 15583*/      /*Scope*/ 38, /*->15622*/
/* 15584*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_nand_32_acq_rel
/* 15586*/        OPC_Scope, 16, /*->15604*/ // 2 children in Scope
/* 15588*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15590*/          OPC_EmitMergeInputChains1_0,
/* 15591*/          OPC_EmitInteger, MVT::i32, 6, 
/* 15594*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 3/*#Ops*/, 1, 2, 3, 
                    // Src: (atomic_load_nand:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_acq_rel>> - Complexity = 4
                    // Dst: (PseudoAtomicLoadNand32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, 6:{ *:[i32] })
/* 15604*/        /*Scope*/ 16, /*->15621*/
/* 15605*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15607*/          OPC_EmitMergeInputChains1_0,
/* 15608*/          OPC_EmitInteger, MVT::i32, 6, 
/* 15611*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 3/*#Ops*/, 1, 2, 3, 
                    // Src: (atomic_load_nand:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_acq_rel>> - Complexity = 4
                    // Dst: (PseudoAtomicLoadNand32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, 6:{ *:[i32] })
/* 15621*/        0, /*End of Scope*/
/* 15622*/      /*Scope*/ 38, /*->15661*/
/* 15623*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_nand_32_seq_cst
/* 15625*/        OPC_Scope, 16, /*->15643*/ // 2 children in Scope
/* 15627*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15629*/          OPC_EmitMergeInputChains1_0,
/* 15630*/          OPC_EmitInteger, MVT::i32, 7, 
/* 15633*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 3/*#Ops*/, 1, 2, 3, 
                    // Src: (atomic_load_nand:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_seq_cst>> - Complexity = 4
                    // Dst: (PseudoAtomicLoadNand32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, 7:{ *:[i32] })
/* 15643*/        /*Scope*/ 16, /*->15660*/
/* 15644*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15646*/          OPC_EmitMergeInputChains1_0,
/* 15647*/          OPC_EmitInteger, MVT::i32, 7, 
/* 15650*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 3/*#Ops*/, 1, 2, 3, 
                    // Src: (atomic_load_nand:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_seq_cst>> - Complexity = 4
                    // Dst: (PseudoAtomicLoadNand32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr, 7:{ *:[i32] })
/* 15660*/        0, /*End of Scope*/
/* 15661*/      0, /*End of Scope*/
/* 15662*/    /*SwitchType*/ 102, MVT::i64,// ->15766
/* 15664*/      OPC_CheckChild1Type, MVT::i64,
/* 15666*/      OPC_RecordChild2, // #2 = $incr
/* 15667*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_nand_32
/* 15669*/      OPC_Scope, 18, /*->15689*/ // 5 children in Scope
/* 15671*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_nand_32_monotonic
/* 15673*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15675*/        OPC_EmitMergeInputChains1_0,
/* 15676*/        OPC_EmitInteger, MVT::i64, 2, 
/* 15679*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, MVT::i64, 3/*#Ops*/, 1, 2, 3, 
                  // Src: (atomic_load_nand:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_monotonic>> - Complexity = 4
                  // Dst: (PseudoAtomicLoadNand32:{ *:[i64] }:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr, 2:{ *:[i64] })
/* 15689*/      /*Scope*/ 18, /*->15708*/
/* 15690*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_nand_32_acquire
/* 15692*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15694*/        OPC_EmitMergeInputChains1_0,
/* 15695*/        OPC_EmitInteger, MVT::i64, 4, 
/* 15698*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, MVT::i64, 3/*#Ops*/, 1, 2, 3, 
                  // Src: (atomic_load_nand:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_acquire>> - Complexity = 4
                  // Dst: (PseudoAtomicLoadNand32:{ *:[i64] }:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr, 4:{ *:[i64] })
/* 15708*/      /*Scope*/ 18, /*->15727*/
/* 15709*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_nand_32_release
/* 15711*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15713*/        OPC_EmitMergeInputChains1_0,
/* 15714*/        OPC_EmitInteger, MVT::i64, 5, 
/* 15717*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, MVT::i64, 3/*#Ops*/, 1, 2, 3, 
                  // Src: (atomic_load_nand:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_release>> - Complexity = 4
                  // Dst: (PseudoAtomicLoadNand32:{ *:[i64] }:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr, 5:{ *:[i64] })
/* 15727*/      /*Scope*/ 18, /*->15746*/
/* 15728*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_nand_32_acq_rel
/* 15730*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15732*/        OPC_EmitMergeInputChains1_0,
/* 15733*/        OPC_EmitInteger, MVT::i64, 6, 
/* 15736*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, MVT::i64, 3/*#Ops*/, 1, 2, 3, 
                  // Src: (atomic_load_nand:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_acq_rel>> - Complexity = 4
                  // Dst: (PseudoAtomicLoadNand32:{ *:[i64] }:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr, 6:{ *:[i64] })
/* 15746*/      /*Scope*/ 18, /*->15765*/
/* 15747*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_nand_32_seq_cst
/* 15749*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 15751*/        OPC_EmitMergeInputChains1_0,
/* 15752*/        OPC_EmitInteger, MVT::i64, 7, 
/* 15755*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoAtomicLoadNand32), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, MVT::i64, 3/*#Ops*/, 1, 2, 3, 
                  // Src: (atomic_load_nand:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr)<<P:Predicate_atomic_load_nand_32>><<P:Predicate_atomic_load_nand_32_seq_cst>> - Complexity = 4
                  // Dst: (PseudoAtomicLoadNand32:{ *:[i64] }:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr, 7:{ *:[i64] })
/* 15765*/      0, /*End of Scope*/
/* 15766*/    0, // EndSwitchType
/* 15767*/  /*SwitchOpcode*/ 75|128,2/*331*/, TARGET_VAL(ISD::ATOMIC_CMP_SWAP),// ->16102
/* 15771*/    OPC_RecordMemRef,
/* 15772*/    OPC_RecordNode, // #0 = 'atomic_cmp_swap' chained node
/* 15773*/    OPC_RecordChild1, // #1 = $addr
/* 15774*/    OPC_SwitchType /*2 cases */, 85|128,1/*213*/, MVT::i32,// ->15991
/* 15778*/      OPC_CheckChild1Type, MVT::i32,
/* 15780*/      OPC_RecordChild2, // #2 = $cmp
/* 15781*/      OPC_RecordChild3, // #3 = $new
/* 15782*/      OPC_CheckPredicate, 18, // Predicate_atomic_cmp_swap_32
/* 15784*/      OPC_Scope, 40, /*->15826*/ // 5 children in Scope
/* 15786*/        OPC_CheckPredicate, 24, // Predicate_atomic_cmp_swap_32_monotonic
/* 15788*/        OPC_Scope, 17, /*->15807*/ // 2 children in Scope
/* 15790*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15792*/          OPC_EmitMergeInputChains1_0,
/* 15793*/          OPC_EmitInteger, MVT::i32, 2, 
/* 15796*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 4, 
                    // Src: (atomic_cmp_swap:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_monotonic>> - Complexity = 4
                    // Dst: (PseudoCmpXchg32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new, 2:{ *:[i32] })
/* 15807*/        /*Scope*/ 17, /*->15825*/
/* 15808*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15810*/          OPC_EmitMergeInputChains1_0,
/* 15811*/          OPC_EmitInteger, MVT::i32, 2, 
/* 15814*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 4, 
                    // Src: (atomic_cmp_swap:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_monotonic>> - Complexity = 4
                    // Dst: (PseudoCmpXchg32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new, 2:{ *:[i32] })
/* 15825*/        0, /*End of Scope*/
/* 15826*/      /*Scope*/ 40, /*->15867*/
/* 15827*/        OPC_CheckPredicate, 25, // Predicate_atomic_cmp_swap_32_acquire
/* 15829*/        OPC_Scope, 17, /*->15848*/ // 2 children in Scope
/* 15831*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15833*/          OPC_EmitMergeInputChains1_0,
/* 15834*/          OPC_EmitInteger, MVT::i32, 4, 
/* 15837*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 4, 
                    // Src: (atomic_cmp_swap:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_acquire>> - Complexity = 4
                    // Dst: (PseudoCmpXchg32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new, 4:{ *:[i32] })
/* 15848*/        /*Scope*/ 17, /*->15866*/
/* 15849*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15851*/          OPC_EmitMergeInputChains1_0,
/* 15852*/          OPC_EmitInteger, MVT::i32, 4, 
/* 15855*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 4, 
                    // Src: (atomic_cmp_swap:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_acquire>> - Complexity = 4
                    // Dst: (PseudoCmpXchg32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new, 4:{ *:[i32] })
/* 15866*/        0, /*End of Scope*/
/* 15867*/      /*Scope*/ 40, /*->15908*/
/* 15868*/        OPC_CheckPredicate, 26, // Predicate_atomic_cmp_swap_32_release
/* 15870*/        OPC_Scope, 17, /*->15889*/ // 2 children in Scope
/* 15872*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15874*/          OPC_EmitMergeInputChains1_0,
/* 15875*/          OPC_EmitInteger, MVT::i32, 5, 
/* 15878*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 4, 
                    // Src: (atomic_cmp_swap:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_release>> - Complexity = 4
                    // Dst: (PseudoCmpXchg32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new, 5:{ *:[i32] })
/* 15889*/        /*Scope*/ 17, /*->15907*/
/* 15890*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15892*/          OPC_EmitMergeInputChains1_0,
/* 15893*/          OPC_EmitInteger, MVT::i32, 5, 
/* 15896*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 4, 
                    // Src: (atomic_cmp_swap:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_release>> - Complexity = 4
                    // Dst: (PseudoCmpXchg32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new, 5:{ *:[i32] })
/* 15907*/        0, /*End of Scope*/
/* 15908*/      /*Scope*/ 40, /*->15949*/
/* 15909*/        OPC_CheckPredicate, 27, // Predicate_atomic_cmp_swap_32_acq_rel
/* 15911*/        OPC_Scope, 17, /*->15930*/ // 2 children in Scope
/* 15913*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15915*/          OPC_EmitMergeInputChains1_0,
/* 15916*/          OPC_EmitInteger, MVT::i32, 6, 
/* 15919*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 4, 
                    // Src: (atomic_cmp_swap:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_acq_rel>> - Complexity = 4
                    // Dst: (PseudoCmpXchg32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new, 6:{ *:[i32] })
/* 15930*/        /*Scope*/ 17, /*->15948*/
/* 15931*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15933*/          OPC_EmitMergeInputChains1_0,
/* 15934*/          OPC_EmitInteger, MVT::i32, 6, 
/* 15937*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 4, 
                    // Src: (atomic_cmp_swap:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_acq_rel>> - Complexity = 4
                    // Dst: (PseudoCmpXchg32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new, 6:{ *:[i32] })
/* 15948*/        0, /*End of Scope*/
/* 15949*/      /*Scope*/ 40, /*->15990*/
/* 15950*/        OPC_CheckPredicate, 28, // Predicate_atomic_cmp_swap_32_seq_cst
/* 15952*/        OPC_Scope, 17, /*->15971*/ // 2 children in Scope
/* 15954*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 15956*/          OPC_EmitMergeInputChains1_0,
/* 15957*/          OPC_EmitInteger, MVT::i32, 7, 
/* 15960*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 4, 
                    // Src: (atomic_cmp_swap:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_seq_cst>> - Complexity = 4
                    // Dst: (PseudoCmpXchg32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new, 7:{ *:[i32] })
/* 15971*/        /*Scope*/ 17, /*->15989*/
/* 15972*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 15974*/          OPC_EmitMergeInputChains1_0,
/* 15975*/          OPC_EmitInteger, MVT::i32, 7, 
/* 15978*/          OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, MVT::i32, 4/*#Ops*/, 1, 2, 3, 4, 
                    // Src: (atomic_cmp_swap:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_seq_cst>> - Complexity = 4
                    // Dst: (PseudoCmpXchg32:{ *:[i32] }:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$cmp, GPR:{ *:[i32] }:$new, 7:{ *:[i32] })
/* 15989*/        0, /*End of Scope*/
/* 15990*/      0, /*End of Scope*/
/* 15991*/    /*SwitchType*/ 108, MVT::i64,// ->16101
/* 15993*/      OPC_CheckChild1Type, MVT::i64,
/* 15995*/      OPC_RecordChild2, // #2 = $cmp
/* 15996*/      OPC_RecordChild3, // #3 = $new
/* 15997*/      OPC_CheckPredicate, 18, // Predicate_atomic_cmp_swap_32
/* 15999*/      OPC_Scope, 19, /*->16020*/ // 5 children in Scope
/* 16001*/        OPC_CheckPredicate, 24, // Predicate_atomic_cmp_swap_32_monotonic
/* 16003*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16005*/        OPC_EmitMergeInputChains1_0,
/* 16006*/        OPC_EmitInteger, MVT::i32, 2, 
/* 16009*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, MVT::i64, 4/*#Ops*/, 1, 2, 3, 4, 
                  // Src: (atomic_cmp_swap:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$cmp, GPR:{ *:[i64] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_monotonic>> - Complexity = 4
                  // Dst: (PseudoCmpXchg32:{ *:[i64] }:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$cmp, GPR:{ *:[i64] }:$new, 2:{ *:[i32] })
/* 16020*/      /*Scope*/ 19, /*->16040*/
/* 16021*/        OPC_CheckPredicate, 25, // Predicate_atomic_cmp_swap_32_acquire
/* 16023*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16025*/        OPC_EmitMergeInputChains1_0,
/* 16026*/        OPC_EmitInteger, MVT::i32, 4, 
/* 16029*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, MVT::i64, 4/*#Ops*/, 1, 2, 3, 4, 
                  // Src: (atomic_cmp_swap:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$cmp, GPR:{ *:[i64] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_acquire>> - Complexity = 4
                  // Dst: (PseudoCmpXchg32:{ *:[i64] }:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$cmp, GPR:{ *:[i64] }:$new, 4:{ *:[i32] })
/* 16040*/      /*Scope*/ 19, /*->16060*/
/* 16041*/        OPC_CheckPredicate, 26, // Predicate_atomic_cmp_swap_32_release
/* 16043*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16045*/        OPC_EmitMergeInputChains1_0,
/* 16046*/        OPC_EmitInteger, MVT::i32, 5, 
/* 16049*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, MVT::i64, 4/*#Ops*/, 1, 2, 3, 4, 
                  // Src: (atomic_cmp_swap:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$cmp, GPR:{ *:[i64] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_release>> - Complexity = 4
                  // Dst: (PseudoCmpXchg32:{ *:[i64] }:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$cmp, GPR:{ *:[i64] }:$new, 5:{ *:[i32] })
/* 16060*/      /*Scope*/ 19, /*->16080*/
/* 16061*/        OPC_CheckPredicate, 27, // Predicate_atomic_cmp_swap_32_acq_rel
/* 16063*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16065*/        OPC_EmitMergeInputChains1_0,
/* 16066*/        OPC_EmitInteger, MVT::i32, 6, 
/* 16069*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, MVT::i64, 4/*#Ops*/, 1, 2, 3, 4, 
                  // Src: (atomic_cmp_swap:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$cmp, GPR:{ *:[i64] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_acq_rel>> - Complexity = 4
                  // Dst: (PseudoCmpXchg32:{ *:[i64] }:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$cmp, GPR:{ *:[i64] }:$new, 6:{ *:[i32] })
/* 16080*/      /*Scope*/ 19, /*->16100*/
/* 16081*/        OPC_CheckPredicate, 28, // Predicate_atomic_cmp_swap_32_seq_cst
/* 16083*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16085*/        OPC_EmitMergeInputChains1_0,
/* 16086*/        OPC_EmitInteger, MVT::i32, 7, 
/* 16089*/        OPC_MorphNodeTo2, TARGET_VAL(RISCV::PseudoCmpXchg32), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, MVT::i64, 4/*#Ops*/, 1, 2, 3, 4, 
                  // Src: (atomic_cmp_swap:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$cmp, GPR:{ *:[i64] }:$new)<<P:Predicate_atomic_cmp_swap_32>><<P:Predicate_atomic_cmp_swap_32_seq_cst>> - Complexity = 4
                  // Dst: (PseudoCmpXchg32:{ *:[i64] }:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$cmp, GPR:{ *:[i64] }:$new, 7:{ *:[i32] })
/* 16100*/      0, /*End of Scope*/
/* 16101*/    0, // EndSwitchType
/* 16102*/  /*SwitchOpcode*/ 21|128,3/*405*/, TARGET_VAL(ISD::ATOMIC_LOAD_SUB),// ->16511
/* 16106*/    OPC_RecordMemRef,
/* 16107*/    OPC_RecordNode, // #0 = 'atomic_load_sub' chained node
/* 16108*/    OPC_RecordChild1, // #1 = $addr
/* 16109*/    OPC_SwitchType /*2 cases */, 6|128,2/*262*/, MVT::i32,// ->16375
/* 16113*/      OPC_CheckChild1Type, MVT::i32,
/* 16115*/      OPC_RecordChild2, // #2 = $incr
/* 16116*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_sub_32
/* 16118*/      OPC_Scope, 50, /*->16170*/ // 5 children in Scope
/* 16120*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_sub_32_monotonic
/* 16122*/        OPC_Scope, 22, /*->16146*/ // 2 children in Scope
/* 16124*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 16126*/          OPC_EmitMergeInputChains1_0,
/* 16127*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16130*/          OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                        MVT::i32, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16138*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 4, 
                    // Src: (atomic_load_sub:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_monotonic>> - Complexity = 4
                    // Dst: (AMOADD_W:{ *:[i32] } GPR:{ *:[i32] }:$addr, (SUB:{ *:[i32] } X0:{ *:[i32] }, GPR:{ *:[i32] }:$incr))
/* 16146*/        /*Scope*/ 22, /*->16169*/
/* 16147*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 16149*/          OPC_EmitMergeInputChains1_0,
/* 16150*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16153*/          OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                        MVT::i32, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16161*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 4, 
                    // Src: (atomic_load_sub:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_monotonic>> - Complexity = 4
                    // Dst: (AMOADD_W:{ *:[i32] } GPR:{ *:[i32] }:$addr, (SUB:{ *:[i32] } X0:{ *:[i32] }, GPR:{ *:[i32] }:$incr))
/* 16169*/        0, /*End of Scope*/
/* 16170*/      /*Scope*/ 50, /*->16221*/
/* 16171*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_sub_32_acquire
/* 16173*/        OPC_Scope, 22, /*->16197*/ // 2 children in Scope
/* 16175*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 16177*/          OPC_EmitMergeInputChains1_0,
/* 16178*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16181*/          OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                        MVT::i32, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16189*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 4, 
                    // Src: (atomic_load_sub:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_acquire>> - Complexity = 4
                    // Dst: (AMOADD_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$addr, (SUB:{ *:[i32] } X0:{ *:[i32] }, GPR:{ *:[i32] }:$incr))
/* 16197*/        /*Scope*/ 22, /*->16220*/
/* 16198*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 16200*/          OPC_EmitMergeInputChains1_0,
/* 16201*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16204*/          OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                        MVT::i32, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16212*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 4, 
                    // Src: (atomic_load_sub:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_acquire>> - Complexity = 4
                    // Dst: (AMOADD_W_AQ:{ *:[i32] } GPR:{ *:[i32] }:$addr, (SUB:{ *:[i32] } X0:{ *:[i32] }, GPR:{ *:[i32] }:$incr))
/* 16220*/        0, /*End of Scope*/
/* 16221*/      /*Scope*/ 50, /*->16272*/
/* 16222*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_sub_32_release
/* 16224*/        OPC_Scope, 22, /*->16248*/ // 2 children in Scope
/* 16226*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 16228*/          OPC_EmitMergeInputChains1_0,
/* 16229*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16232*/          OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                        MVT::i32, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16240*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 4, 
                    // Src: (atomic_load_sub:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_release>> - Complexity = 4
                    // Dst: (AMOADD_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$addr, (SUB:{ *:[i32] } X0:{ *:[i32] }, GPR:{ *:[i32] }:$incr))
/* 16248*/        /*Scope*/ 22, /*->16271*/
/* 16249*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 16251*/          OPC_EmitMergeInputChains1_0,
/* 16252*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16255*/          OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                        MVT::i32, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16263*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 4, 
                    // Src: (atomic_load_sub:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_release>> - Complexity = 4
                    // Dst: (AMOADD_W_RL:{ *:[i32] } GPR:{ *:[i32] }:$addr, (SUB:{ *:[i32] } X0:{ *:[i32] }, GPR:{ *:[i32] }:$incr))
/* 16271*/        0, /*End of Scope*/
/* 16272*/      /*Scope*/ 50, /*->16323*/
/* 16273*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_sub_32_acq_rel
/* 16275*/        OPC_Scope, 22, /*->16299*/ // 2 children in Scope
/* 16277*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 16279*/          OPC_EmitMergeInputChains1_0,
/* 16280*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16283*/          OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                        MVT::i32, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16291*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 4, 
                    // Src: (atomic_load_sub:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOADD_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$addr, (SUB:{ *:[i32] } X0:{ *:[i32] }, GPR:{ *:[i32] }:$incr))
/* 16299*/        /*Scope*/ 22, /*->16322*/
/* 16300*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 16302*/          OPC_EmitMergeInputChains1_0,
/* 16303*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16306*/          OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                        MVT::i32, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16314*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 4, 
                    // Src: (atomic_load_sub:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_acq_rel>> - Complexity = 4
                    // Dst: (AMOADD_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$addr, (SUB:{ *:[i32] } X0:{ *:[i32] }, GPR:{ *:[i32] }:$incr))
/* 16322*/        0, /*End of Scope*/
/* 16323*/      /*Scope*/ 50, /*->16374*/
/* 16324*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_sub_32_seq_cst
/* 16326*/        OPC_Scope, 22, /*->16350*/ // 2 children in Scope
/* 16328*/          OPC_CheckPatternPredicate, 14, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 16330*/          OPC_EmitMergeInputChains1_0,
/* 16331*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16334*/          OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                        MVT::i32, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16342*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 4, 
                    // Src: (atomic_load_sub:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOADD_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$addr, (SUB:{ *:[i32] } X0:{ *:[i32] }, GPR:{ *:[i32] }:$incr))
/* 16350*/        /*Scope*/ 22, /*->16373*/
/* 16351*/          OPC_CheckPatternPredicate, 15, // (Subtarget->hasStdExtA())
/* 16353*/          OPC_EmitMergeInputChains1_0,
/* 16354*/          OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16357*/          OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                        MVT::i32, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16365*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                        MVT::i32, 2/*#Ops*/, 1, 4, 
                    // Src: (atomic_load_sub:{ *:[i32] } GPR:{ *:[i32] }:$addr, GPR:{ *:[i32] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_seq_cst>> - Complexity = 4
                    // Dst: (AMOADD_W_AQ_RL:{ *:[i32] } GPR:{ *:[i32] }:$addr, (SUB:{ *:[i32] } X0:{ *:[i32] }, GPR:{ *:[i32] }:$incr))
/* 16373*/        0, /*End of Scope*/
/* 16374*/      0, /*End of Scope*/
/* 16375*/    /*SwitchType*/ 4|128,1/*132*/, MVT::i64,// ->16510
/* 16378*/      OPC_CheckChild1Type, MVT::i64,
/* 16380*/      OPC_RecordChild2, // #2 = $incr
/* 16381*/      OPC_CheckPredicate, 18, // Predicate_atomic_load_sub_32
/* 16383*/      OPC_Scope, 24, /*->16409*/ // 5 children in Scope
/* 16385*/        OPC_CheckPredicate, 24, // Predicate_atomic_load_sub_32_monotonic
/* 16387*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16389*/        OPC_EmitMergeInputChains1_0,
/* 16390*/        OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 16393*/        OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                      MVT::i64, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16401*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 4, 
                  // Src: (atomic_load_sub:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_monotonic>> - Complexity = 4
                  // Dst: (AMOADD_W:{ *:[i64] } GPR:{ *:[i64] }:$addr, (SUB:{ *:[i64] } X0:{ *:[i64] }, GPR:{ *:[i64] }:$incr))
/* 16409*/      /*Scope*/ 24, /*->16434*/
/* 16410*/        OPC_CheckPredicate, 25, // Predicate_atomic_load_sub_32_acquire
/* 16412*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16414*/        OPC_EmitMergeInputChains1_0,
/* 16415*/        OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 16418*/        OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                      MVT::i64, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16426*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 4, 
                  // Src: (atomic_load_sub:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_acquire>> - Complexity = 4
                  // Dst: (AMOADD_W_AQ:{ *:[i64] } GPR:{ *:[i64] }:$addr, (SUB:{ *:[i64] } X0:{ *:[i64] }, GPR:{ *:[i64] }:$incr))
/* 16434*/      /*Scope*/ 24, /*->16459*/
/* 16435*/        OPC_CheckPredicate, 26, // Predicate_atomic_load_sub_32_release
/* 16437*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16439*/        OPC_EmitMergeInputChains1_0,
/* 16440*/        OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 16443*/        OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                      MVT::i64, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16451*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 4, 
                  // Src: (atomic_load_sub:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_release>> - Complexity = 4
                  // Dst: (AMOADD_W_RL:{ *:[i64] } GPR:{ *:[i64] }:$addr, (SUB:{ *:[i64] } X0:{ *:[i64] }, GPR:{ *:[i64] }:$incr))
/* 16459*/      /*Scope*/ 24, /*->16484*/
/* 16460*/        OPC_CheckPredicate, 27, // Predicate_atomic_load_sub_32_acq_rel
/* 16462*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16464*/        OPC_EmitMergeInputChains1_0,
/* 16465*/        OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 16468*/        OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                      MVT::i64, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16476*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 4, 
                  // Src: (atomic_load_sub:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_acq_rel>> - Complexity = 4
                  // Dst: (AMOADD_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$addr, (SUB:{ *:[i64] } X0:{ *:[i64] }, GPR:{ *:[i64] }:$incr))
/* 16484*/      /*Scope*/ 24, /*->16509*/
/* 16485*/        OPC_CheckPredicate, 28, // Predicate_atomic_load_sub_32_seq_cst
/* 16487*/        OPC_CheckPatternPredicate, 16, // (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16489*/        OPC_EmitMergeInputChains1_0,
/* 16490*/        OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 16493*/        OPC_EmitNode1, TARGET_VAL(RISCV::SUB), 0,
                      MVT::i64, 2/*#Ops*/, 3, 2,  // Results = #4
/* 16501*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::AMOADD_W_AQ_RL), 0|OPFL_Chain|OPFL_MemRefs,
                      MVT::i64, 2/*#Ops*/, 1, 4, 
                  // Src: (atomic_load_sub:{ *:[i64] } GPR:{ *:[i64] }:$addr, GPR:{ *:[i64] }:$incr)<<P:Predicate_atomic_load_sub_32>><<P:Predicate_atomic_load_sub_32_seq_cst>> - Complexity = 4
                  // Dst: (AMOADD_W_AQ_RL:{ *:[i64] } GPR:{ *:[i64] }:$addr, (SUB:{ *:[i64] } X0:{ *:[i64] }, GPR:{ *:[i64] }:$incr))
/* 16509*/      0, /*End of Scope*/
/* 16510*/    0, // EndSwitchType
/* 16511*/  /*SwitchOpcode*/ 14, TARGET_VAL(ISD::BR),// ->16528
/* 16514*/    OPC_RecordNode, // #0 = 'br' chained node
/* 16515*/    OPC_RecordChild1, // #1 = $imm20
/* 16516*/    OPC_MoveChild1,
/* 16517*/    OPC_CheckOpcode, TARGET_VAL(ISD::BasicBlock),
/* 16520*/    OPC_MoveParent,
/* 16521*/    OPC_EmitMergeInputChains1_0,
/* 16522*/    OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoBR), 0|OPFL_Chain,
                  1/*#Ops*/, 1, 
              // Src: (br (bb:{ *:[Other] }):$imm20) - Complexity = 3
              // Dst: (PseudoBR (bb:{ *:[Other] }):$imm20)
/* 16528*/  /*SwitchOpcode*/ 8, TARGET_VAL(RISCVISD::RET_FLAG),// ->16539
/* 16531*/    OPC_RecordNode, // #0 = 'RetFlag' chained node
/* 16532*/    OPC_CaptureGlueInput,
/* 16533*/    OPC_EmitMergeInputChains1_0,
/* 16534*/    OPC_MorphNodeTo0, TARGET_VAL(RISCV::PseudoRET), 0|OPFL_Chain|OPFL_GlueInput|OPFL_Variadic0,
                  0/*#Ops*/, 
              // Src: (RetFlag) - Complexity = 3
              // Dst: (PseudoRET)
/* 16539*/  /*SwitchOpcode*/ 40, TARGET_VAL(ISD::SUB),// ->16582
/* 16542*/    OPC_RecordChild0, // #0 = $rs1
/* 16543*/    OPC_RecordChild1, // #1 = $rs2
/* 16544*/    OPC_SwitchType /*2 cases */, 22, MVT::i32,// ->16569
/* 16547*/      OPC_Scope, 10, /*->16559*/ // 2 children in Scope
/* 16549*/        OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 16551*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::SUB), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (sub:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (SUB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 16559*/      /*Scope*/ 8, /*->16568*/
/* 16560*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::SUB), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (sub:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (SUB:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 16568*/      0, /*End of Scope*/
/* 16569*/    /*SwitchType*/ 10, MVT::i64,// ->16581
/* 16571*/      OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 16573*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::SUB), 0,
                    MVT::i64, 2/*#Ops*/, 0, 1, 
                // Src: (sub:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                // Dst: (SUB:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 16581*/    0, // EndSwitchType
/* 16582*/  /*SwitchOpcode*/ 53, TARGET_VAL(RISCVISD::URET_FLAG),// ->16638
/* 16585*/    OPC_RecordNode, // #0 = 'URetFlag' chained node
/* 16586*/    OPC_CaptureGlueInput,
/* 16587*/    OPC_Scope, 16, /*->16605*/ // 3 children in Scope
/* 16589*/      OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 16591*/      OPC_EmitMergeInputChains1_0,
/* 16592*/      OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16595*/      OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16598*/      OPC_MorphNodeTo0, TARGET_VAL(RISCV::URET), 0|OPFL_Chain|OPFL_GlueInput,
                    2/*#Ops*/, 1, 2, 
                // Src: (URetFlag) - Complexity = 3
                // Dst: (URET X0:{ *:[i32] }, X0:{ *:[i32] })
/* 16605*/    /*Scope*/ 16, /*->16622*/
/* 16606*/      OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 16608*/      OPC_EmitMergeInputChains1_0,
/* 16609*/      OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 16612*/      OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 16615*/      OPC_MorphNodeTo0, TARGET_VAL(RISCV::URET), 0|OPFL_Chain|OPFL_GlueInput,
                    2/*#Ops*/, 1, 2, 
                // Src: (URetFlag) - Complexity = 3
                // Dst: (URET X0:{ *:[i64] }, X0:{ *:[i64] })
/* 16622*/    /*Scope*/ 14, /*->16637*/
/* 16623*/      OPC_EmitMergeInputChains1_0,
/* 16624*/      OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16627*/      OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16630*/      OPC_MorphNodeTo0, TARGET_VAL(RISCV::URET), 0|OPFL_Chain|OPFL_GlueInput,
                    2/*#Ops*/, 1, 2, 
                // Src: (URetFlag) - Complexity = 3
                // Dst: (URET X0:{ *:[i32] }, X0:{ *:[i32] })
/* 16637*/    0, /*End of Scope*/
/* 16638*/  /*SwitchOpcode*/ 53, TARGET_VAL(RISCVISD::SRET_FLAG),// ->16694
/* 16641*/    OPC_RecordNode, // #0 = 'SRetFlag' chained node
/* 16642*/    OPC_CaptureGlueInput,
/* 16643*/    OPC_Scope, 16, /*->16661*/ // 3 children in Scope
/* 16645*/      OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 16647*/      OPC_EmitMergeInputChains1_0,
/* 16648*/      OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16651*/      OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16654*/      OPC_MorphNodeTo0, TARGET_VAL(RISCV::SRET), 0|OPFL_Chain|OPFL_GlueInput,
                    2/*#Ops*/, 1, 2, 
                // Src: (SRetFlag) - Complexity = 3
                // Dst: (SRET X0:{ *:[i32] }, X0:{ *:[i32] })
/* 16661*/    /*Scope*/ 16, /*->16678*/
/* 16662*/      OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 16664*/      OPC_EmitMergeInputChains1_0,
/* 16665*/      OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 16668*/      OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 16671*/      OPC_MorphNodeTo0, TARGET_VAL(RISCV::SRET), 0|OPFL_Chain|OPFL_GlueInput,
                    2/*#Ops*/, 1, 2, 
                // Src: (SRetFlag) - Complexity = 3
                // Dst: (SRET X0:{ *:[i64] }, X0:{ *:[i64] })
/* 16678*/    /*Scope*/ 14, /*->16693*/
/* 16679*/      OPC_EmitMergeInputChains1_0,
/* 16680*/      OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16683*/      OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16686*/      OPC_MorphNodeTo0, TARGET_VAL(RISCV::SRET), 0|OPFL_Chain|OPFL_GlueInput,
                    2/*#Ops*/, 1, 2, 
                // Src: (SRetFlag) - Complexity = 3
                // Dst: (SRET X0:{ *:[i32] }, X0:{ *:[i32] })
/* 16693*/    0, /*End of Scope*/
/* 16694*/  /*SwitchOpcode*/ 53, TARGET_VAL(RISCVISD::MRET_FLAG),// ->16750
/* 16697*/    OPC_RecordNode, // #0 = 'MRetFlag' chained node
/* 16698*/    OPC_CaptureGlueInput,
/* 16699*/    OPC_Scope, 16, /*->16717*/ // 3 children in Scope
/* 16701*/      OPC_CheckPatternPredicate, 0, // (MF->getSubtarget().checkFeatures("-64bit"))
/* 16703*/      OPC_EmitMergeInputChains1_0,
/* 16704*/      OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16707*/      OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16710*/      OPC_MorphNodeTo0, TARGET_VAL(RISCV::MRET), 0|OPFL_Chain|OPFL_GlueInput,
                    2/*#Ops*/, 1, 2, 
                // Src: (MRetFlag) - Complexity = 3
                // Dst: (MRET X0:{ *:[i32] }, X0:{ *:[i32] })
/* 16717*/    /*Scope*/ 16, /*->16734*/
/* 16718*/      OPC_CheckPatternPredicate, 5, // (MF->getSubtarget().checkFeatures("+64bit"))
/* 16720*/      OPC_EmitMergeInputChains1_0,
/* 16721*/      OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 16724*/      OPC_EmitRegister, MVT::i64, RISCV::X0,
/* 16727*/      OPC_MorphNodeTo0, TARGET_VAL(RISCV::MRET), 0|OPFL_Chain|OPFL_GlueInput,
                    2/*#Ops*/, 1, 2, 
                // Src: (MRetFlag) - Complexity = 3
                // Dst: (MRET X0:{ *:[i64] }, X0:{ *:[i64] })
/* 16734*/    /*Scope*/ 14, /*->16749*/
/* 16735*/      OPC_EmitMergeInputChains1_0,
/* 16736*/      OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16739*/      OPC_EmitRegister, MVT::i32, RISCV::X0,
/* 16742*/      OPC_MorphNodeTo0, TARGET_VAL(RISCV::MRET), 0|OPFL_Chain|OPFL_GlueInput,
                    2/*#Ops*/, 1, 2, 
                // Src: (MRetFlag) - Complexity = 3
                // Dst: (MRET X0:{ *:[i32] }, X0:{ *:[i32] })
/* 16749*/    0, /*End of Scope*/
/* 16750*/  /*SwitchOpcode*/ 42, TARGET_VAL(ISD::MUL),// ->16795
/* 16753*/    OPC_RecordChild0, // #0 = $rs1
/* 16754*/    OPC_RecordChild1, // #1 = $rs2
/* 16755*/    OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->16782
/* 16758*/      OPC_Scope, 10, /*->16770*/ // 2 children in Scope
/* 16760*/        OPC_CheckPatternPredicate, 17, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 16762*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::MUL), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (mul:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (MUL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 16770*/      /*Scope*/ 10, /*->16781*/
/* 16771*/        OPC_CheckPatternPredicate, 18, // (Subtarget->hasStdExtM())
/* 16773*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::MUL), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (mul:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (MUL:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 16781*/      0, /*End of Scope*/
/* 16782*/    /*SwitchType*/ 10, MVT::i64,// ->16794
/* 16784*/      OPC_CheckPatternPredicate, 19, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16786*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::MUL), 0,
                    MVT::i64, 2/*#Ops*/, 0, 1, 
                // Src: (mul:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                // Dst: (MUL:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 16794*/    0, // EndSwitchType
/* 16795*/  /*SwitchOpcode*/ 42, TARGET_VAL(ISD::MULHS),// ->16840
/* 16798*/    OPC_RecordChild0, // #0 = $rs1
/* 16799*/    OPC_RecordChild1, // #1 = $rs2
/* 16800*/    OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->16827
/* 16803*/      OPC_Scope, 10, /*->16815*/ // 2 children in Scope
/* 16805*/        OPC_CheckPatternPredicate, 17, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 16807*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::MULH), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (mulhs:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (MULH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 16815*/      /*Scope*/ 10, /*->16826*/
/* 16816*/        OPC_CheckPatternPredicate, 18, // (Subtarget->hasStdExtM())
/* 16818*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::MULH), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (mulhs:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (MULH:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 16826*/      0, /*End of Scope*/
/* 16827*/    /*SwitchType*/ 10, MVT::i64,// ->16839
/* 16829*/      OPC_CheckPatternPredicate, 19, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16831*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::MULH), 0,
                    MVT::i64, 2/*#Ops*/, 0, 1, 
                // Src: (mulhs:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                // Dst: (MULH:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 16839*/    0, // EndSwitchType
/* 16840*/  /*SwitchOpcode*/ 42, TARGET_VAL(ISD::MULHU),// ->16885
/* 16843*/    OPC_RecordChild0, // #0 = $rs1
/* 16844*/    OPC_RecordChild1, // #1 = $rs2
/* 16845*/    OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->16872
/* 16848*/      OPC_Scope, 10, /*->16860*/ // 2 children in Scope
/* 16850*/        OPC_CheckPatternPredicate, 17, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 16852*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::MULHU), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (mulhu:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (MULHU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 16860*/      /*Scope*/ 10, /*->16871*/
/* 16861*/        OPC_CheckPatternPredicate, 18, // (Subtarget->hasStdExtM())
/* 16863*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::MULHU), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (mulhu:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (MULHU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 16871*/      0, /*End of Scope*/
/* 16872*/    /*SwitchType*/ 10, MVT::i64,// ->16884
/* 16874*/      OPC_CheckPatternPredicate, 19, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16876*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::MULHU), 0,
                    MVT::i64, 2/*#Ops*/, 0, 1, 
                // Src: (mulhu:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                // Dst: (MULHU:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 16884*/    0, // EndSwitchType
/* 16885*/  /*SwitchOpcode*/ 42, TARGET_VAL(ISD::SDIV),// ->16930
/* 16888*/    OPC_RecordChild0, // #0 = $rs1
/* 16889*/    OPC_RecordChild1, // #1 = $rs2
/* 16890*/    OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->16917
/* 16893*/      OPC_Scope, 10, /*->16905*/ // 2 children in Scope
/* 16895*/        OPC_CheckPatternPredicate, 17, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 16897*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::DIV), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (sdiv:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (DIV:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 16905*/      /*Scope*/ 10, /*->16916*/
/* 16906*/        OPC_CheckPatternPredicate, 18, // (Subtarget->hasStdExtM())
/* 16908*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::DIV), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (sdiv:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (DIV:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 16916*/      0, /*End of Scope*/
/* 16917*/    /*SwitchType*/ 10, MVT::i64,// ->16929
/* 16919*/      OPC_CheckPatternPredicate, 19, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16921*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::DIV), 0,
                    MVT::i64, 2/*#Ops*/, 0, 1, 
                // Src: (sdiv:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                // Dst: (DIV:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 16929*/    0, // EndSwitchType
/* 16930*/  /*SwitchOpcode*/ 42, TARGET_VAL(ISD::UDIV),// ->16975
/* 16933*/    OPC_RecordChild0, // #0 = $rs1
/* 16934*/    OPC_RecordChild1, // #1 = $rs2
/* 16935*/    OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->16962
/* 16938*/      OPC_Scope, 10, /*->16950*/ // 2 children in Scope
/* 16940*/        OPC_CheckPatternPredicate, 17, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 16942*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::DIVU), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (udiv:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (DIVU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 16950*/      /*Scope*/ 10, /*->16961*/
/* 16951*/        OPC_CheckPatternPredicate, 18, // (Subtarget->hasStdExtM())
/* 16953*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::DIVU), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (udiv:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (DIVU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 16961*/      0, /*End of Scope*/
/* 16962*/    /*SwitchType*/ 10, MVT::i64,// ->16974
/* 16964*/      OPC_CheckPatternPredicate, 19, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 16966*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::DIVU), 0,
                    MVT::i64, 2/*#Ops*/, 0, 1, 
                // Src: (udiv:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                // Dst: (DIVU:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 16974*/    0, // EndSwitchType
/* 16975*/  /*SwitchOpcode*/ 42, TARGET_VAL(ISD::SREM),// ->17020
/* 16978*/    OPC_RecordChild0, // #0 = $rs1
/* 16979*/    OPC_RecordChild1, // #1 = $rs2
/* 16980*/    OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->17007
/* 16983*/      OPC_Scope, 10, /*->16995*/ // 2 children in Scope
/* 16985*/        OPC_CheckPatternPredicate, 17, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 16987*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::REM), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (srem:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (REM:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 16995*/      /*Scope*/ 10, /*->17006*/
/* 16996*/        OPC_CheckPatternPredicate, 18, // (Subtarget->hasStdExtM())
/* 16998*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::REM), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (srem:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (REM:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 17006*/      0, /*End of Scope*/
/* 17007*/    /*SwitchType*/ 10, MVT::i64,// ->17019
/* 17009*/      OPC_CheckPatternPredicate, 19, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17011*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::REM), 0,
                    MVT::i64, 2/*#Ops*/, 0, 1, 
                // Src: (srem:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                // Dst: (REM:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 17019*/    0, // EndSwitchType
/* 17020*/  /*SwitchOpcode*/ 42, TARGET_VAL(ISD::UREM),// ->17065
/* 17023*/    OPC_RecordChild0, // #0 = $rs1
/* 17024*/    OPC_RecordChild1, // #1 = $rs2
/* 17025*/    OPC_SwitchType /*2 cases */, 24, MVT::i32,// ->17052
/* 17028*/      OPC_Scope, 10, /*->17040*/ // 2 children in Scope
/* 17030*/        OPC_CheckPatternPredicate, 17, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17032*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::REMU), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (urem:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (REMU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 17040*/      /*Scope*/ 10, /*->17051*/
/* 17041*/        OPC_CheckPatternPredicate, 18, // (Subtarget->hasStdExtM())
/* 17043*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::REMU), 0,
                      MVT::i32, 2/*#Ops*/, 0, 1, 
                  // Src: (urem:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2) - Complexity = 3
                  // Dst: (REMU:{ *:[i32] } GPR:{ *:[i32] }:$rs1, GPR:{ *:[i32] }:$rs2)
/* 17051*/      0, /*End of Scope*/
/* 17052*/    /*SwitchType*/ 10, MVT::i64,// ->17064
/* 17054*/      OPC_CheckPatternPredicate, 19, // (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17056*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::REMU), 0,
                    MVT::i64, 2/*#Ops*/, 0, 1, 
                // Src: (urem:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2) - Complexity = 3
                // Dst: (REMU:{ *:[i64] } GPR:{ *:[i64] }:$rs1, GPR:{ *:[i64] }:$rs2)
/* 17064*/    0, // EndSwitchType
/* 17065*/  /*SwitchOpcode*/ 84, TARGET_VAL(ISD::BITCAST),// ->17152
/* 17068*/    OPC_RecordChild0, // #0 = $rs1
/* 17069*/    OPC_Scope, 39, /*->17110*/ // 3 children in Scope
/* 17071*/      OPC_CheckChild0Type, MVT::f32,
/* 17073*/      OPC_SwitchType /*2 cases */, 22, MVT::i32,// ->17098
/* 17076*/        OPC_Scope, 9, /*->17087*/ // 2 children in Scope
/* 17078*/          OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17080*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMV_X_W), 0,
                        MVT::i32, 1/*#Ops*/, 0, 
                    // Src: (bitconvert:{ *:[i32] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                    // Dst: (FMV_X_W:{ *:[i32] } FPR32:{ *:[f32] }:$rs1)
/* 17087*/        /*Scope*/ 9, /*->17097*/
/* 17088*/          OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 17090*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMV_X_W), 0,
                        MVT::i32, 1/*#Ops*/, 0, 
                    // Src: (bitconvert:{ *:[i32] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                    // Dst: (FMV_X_W:{ *:[i32] } FPR32:{ *:[f32] }:$rs1)
/* 17097*/        0, /*End of Scope*/
/* 17098*/      /*SwitchType*/ 9, MVT::i64,// ->17109
/* 17100*/        OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17102*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMV_X_W), 0,
                      MVT::i64, 1/*#Ops*/, 0, 
                  // Src: (bitconvert:{ *:[i64] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                  // Dst: (FMV_X_W:{ *:[i64] } FPR32:{ *:[f32] }:$rs1)
/* 17109*/      0, // EndSwitchType
/* 17110*/    /*Scope*/ 26, /*->17137*/
/* 17111*/      OPC_CheckChild0Type, MVT::i32,
/* 17113*/      OPC_CheckType, MVT::f32,
/* 17115*/      OPC_Scope, 9, /*->17126*/ // 2 children in Scope
/* 17117*/        OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17119*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMV_W_X), 0,
                      MVT::f32, 1/*#Ops*/, 0, 
                  // Src: (bitconvert:{ *:[f32] } GPR:{ *:[i32] }:$rs1) - Complexity = 3
                  // Dst: (FMV_W_X:{ *:[f32] } GPR:{ *:[i32] }:$rs1)
/* 17126*/      /*Scope*/ 9, /*->17136*/
/* 17127*/        OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 17129*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMV_W_X), 0,
                      MVT::f32, 1/*#Ops*/, 0, 
                  // Src: (bitconvert:{ *:[f32] } GPR:{ *:[i32] }:$rs1) - Complexity = 3
                  // Dst: (FMV_W_X:{ *:[f32] } GPR:{ *:[i32] }:$rs1)
/* 17136*/      0, /*End of Scope*/
/* 17137*/    /*Scope*/ 13, /*->17151*/
/* 17138*/      OPC_CheckChild0Type, MVT::i64,
/* 17140*/      OPC_CheckType, MVT::f32,
/* 17142*/      OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17144*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMV_W_X), 0,
                    MVT::f32, 1/*#Ops*/, 0, 
                // Src: (bitconvert:{ *:[f32] } GPR:{ *:[i64] }:$rs1) - Complexity = 3
                // Dst: (FMV_W_X:{ *:[f32] } GPR:{ *:[i64] }:$rs1)
/* 17151*/    0, /*End of Scope*/
/* 17152*/  /*SwitchOpcode*/ 107, TARGET_VAL(ISD::FP_TO_SINT),// ->17262
/* 17155*/    OPC_RecordChild0, // #0 = $rs1
/* 17156*/    OPC_Scope, 51, /*->17209*/ // 2 children in Scope
/* 17158*/      OPC_CheckChild0Type, MVT::f32,
/* 17160*/      OPC_SwitchType /*2 cases */, 30, MVT::i32,// ->17193
/* 17163*/        OPC_Scope, 13, /*->17178*/ // 2 children in Scope
/* 17165*/          OPC_CheckPatternPredicate, 20, // (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17167*/          OPC_EmitInteger, MVT::i32, 1, 
/* 17170*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_W_S), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (fp_to_sint:{ *:[i32] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_W_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, 1:{ *:[i32] })
/* 17178*/        /*Scope*/ 13, /*->17192*/
/* 17179*/          OPC_CheckPatternPredicate, 21, // (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit())
/* 17181*/          OPC_EmitInteger, MVT::i32, 1, 
/* 17184*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_W_S), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (fp_to_sint:{ *:[i32] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_W_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, 1:{ *:[i32] })
/* 17192*/        0, /*End of Scope*/
/* 17193*/      /*SwitchType*/ 13, MVT::i64,// ->17208
/* 17195*/        OPC_CheckPatternPredicate, 22, // (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17197*/        OPC_EmitInteger, MVT::i64, 1, 
/* 17200*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_W_S), 0,
                      MVT::i64, 2/*#Ops*/, 0, 1, 
                  // Src: (fp_to_sint:{ *:[i64] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                  // Dst: (FCVT_W_S:{ *:[i64] } ?:{ *:[f32] }:$rs1, 1:{ *:[i64] })
/* 17208*/      0, // EndSwitchType
/* 17209*/    /*Scope*/ 51, /*->17261*/
/* 17210*/      OPC_CheckChild0Type, MVT::f64,
/* 17212*/      OPC_SwitchType /*2 cases */, 30, MVT::i32,// ->17245
/* 17215*/        OPC_Scope, 13, /*->17230*/ // 2 children in Scope
/* 17217*/          OPC_CheckPatternPredicate, 23, // (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17219*/          OPC_EmitInteger, MVT::i32, 1, 
/* 17222*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_W_D), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (fp_to_sint:{ *:[i32] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_W_D:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, 1:{ *:[i32] })
/* 17230*/        /*Scope*/ 13, /*->17244*/
/* 17231*/          OPC_CheckPatternPredicate, 24, // (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit())
/* 17233*/          OPC_EmitInteger, MVT::i32, 1, 
/* 17236*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_W_D), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (fp_to_sint:{ *:[i32] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_W_D:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, 1:{ *:[i32] })
/* 17244*/        0, /*End of Scope*/
/* 17245*/      /*SwitchType*/ 13, MVT::i64,// ->17260
/* 17247*/        OPC_CheckPatternPredicate, 25, // (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17249*/        OPC_EmitInteger, MVT::i64, 1, 
/* 17252*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_W_D), 0,
                      MVT::i64, 2/*#Ops*/, 0, 1, 
                  // Src: (fp_to_sint:{ *:[i64] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                  // Dst: (FCVT_W_D:{ *:[i64] } FPR64:{ *:[f64] }:$rs1, 1:{ *:[i64] })
/* 17260*/      0, // EndSwitchType
/* 17261*/    0, /*End of Scope*/
/* 17262*/  /*SwitchOpcode*/ 107, TARGET_VAL(ISD::FP_TO_UINT),// ->17372
/* 17265*/    OPC_RecordChild0, // #0 = $rs1
/* 17266*/    OPC_Scope, 51, /*->17319*/ // 2 children in Scope
/* 17268*/      OPC_CheckChild0Type, MVT::f32,
/* 17270*/      OPC_SwitchType /*2 cases */, 30, MVT::i32,// ->17303
/* 17273*/        OPC_Scope, 13, /*->17288*/ // 2 children in Scope
/* 17275*/          OPC_CheckPatternPredicate, 20, // (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17277*/          OPC_EmitInteger, MVT::i32, 1, 
/* 17280*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_WU_S), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (fp_to_uint:{ *:[i32] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_WU_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, 1:{ *:[i32] })
/* 17288*/        /*Scope*/ 13, /*->17302*/
/* 17289*/          OPC_CheckPatternPredicate, 21, // (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit())
/* 17291*/          OPC_EmitInteger, MVT::i32, 1, 
/* 17294*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_WU_S), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (fp_to_uint:{ *:[i32] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_WU_S:{ *:[i32] } ?:{ *:[f32] }:$rs1, 1:{ *:[i32] })
/* 17302*/        0, /*End of Scope*/
/* 17303*/      /*SwitchType*/ 13, MVT::i64,// ->17318
/* 17305*/        OPC_CheckPatternPredicate, 22, // (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17307*/        OPC_EmitInteger, MVT::i64, 1, 
/* 17310*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_WU_S), 0,
                      MVT::i64, 2/*#Ops*/, 0, 1, 
                  // Src: (fp_to_uint:{ *:[i64] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                  // Dst: (FCVT_WU_S:{ *:[i64] } ?:{ *:[f32] }:$rs1, 1:{ *:[i64] })
/* 17318*/      0, // EndSwitchType
/* 17319*/    /*Scope*/ 51, /*->17371*/
/* 17320*/      OPC_CheckChild0Type, MVT::f64,
/* 17322*/      OPC_SwitchType /*2 cases */, 30, MVT::i32,// ->17355
/* 17325*/        OPC_Scope, 13, /*->17340*/ // 2 children in Scope
/* 17327*/          OPC_CheckPatternPredicate, 23, // (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17329*/          OPC_EmitInteger, MVT::i32, 1, 
/* 17332*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_WU_D), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (fp_to_uint:{ *:[i32] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_WU_D:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, 1:{ *:[i32] })
/* 17340*/        /*Scope*/ 13, /*->17354*/
/* 17341*/          OPC_CheckPatternPredicate, 24, // (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit())
/* 17343*/          OPC_EmitInteger, MVT::i32, 1, 
/* 17346*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_WU_D), 0,
                        MVT::i32, 2/*#Ops*/, 0, 1, 
                    // Src: (fp_to_uint:{ *:[i32] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_WU_D:{ *:[i32] } FPR64:{ *:[f64] }:$rs1, 1:{ *:[i32] })
/* 17354*/        0, /*End of Scope*/
/* 17355*/      /*SwitchType*/ 13, MVT::i64,// ->17370
/* 17357*/        OPC_CheckPatternPredicate, 25, // (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17359*/        OPC_EmitInteger, MVT::i64, 1, 
/* 17362*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_WU_D), 0,
                      MVT::i64, 2/*#Ops*/, 0, 1, 
                  // Src: (fp_to_uint:{ *:[i64] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                  // Dst: (FCVT_WU_D:{ *:[i64] } FPR64:{ *:[f64] }:$rs1, 1:{ *:[i64] })
/* 17370*/      0, // EndSwitchType
/* 17371*/    0, /*End of Scope*/
/* 17372*/  /*SwitchOpcode*/ 25, TARGET_VAL(RISCVISD::SplitF64),// ->17400
/* 17375*/    OPC_RecordChild0, // #0 = $src
/* 17376*/    OPC_Scope, 10, /*->17388*/ // 2 children in Scope
/* 17378*/      OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17380*/      OPC_MorphNodeTo2, TARGET_VAL(RISCV::SplitF64Pseudo), 0,
                    MVT::i32, MVT::i32, 1/*#Ops*/, 0, 
                // Src: (RISCVSplitF64:{ *:[i32] }:{ *:[i32] } FPR64:{ *:[f64] }:$src) - Complexity = 3
                // Dst: (SplitF64Pseudo:{ *:[i32] }:{ *:[i32] } FPR64:{ *:[f64] }:$src)
/* 17388*/    /*Scope*/ 10, /*->17399*/
/* 17389*/      OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 17391*/      OPC_MorphNodeTo2, TARGET_VAL(RISCV::SplitF64Pseudo), 0,
                    MVT::i32, MVT::i32, 1/*#Ops*/, 0, 
                // Src: (RISCVSplitF64:{ *:[i32] }:{ *:[i32] } FPR64:{ *:[f64] }:$src) - Complexity = 3
                // Dst: (SplitF64Pseudo:{ *:[i32] }:{ *:[i32] } FPR64:{ *:[f64] }:$src)
/* 17399*/    0, /*End of Scope*/
/* 17400*/  /*SwitchOpcode*/ 92|128,3/*476*/, TARGET_VAL(ISD::FMA),// ->17880
/* 17404*/    OPC_Scope, 119, /*->17525*/ // 6 children in Scope
/* 17406*/      OPC_MoveChild0,
/* 17407*/      OPC_CheckOpcode, TARGET_VAL(ISD::FNEG),
/* 17410*/      OPC_RecordChild0, // #0 = $rs1
/* 17411*/      OPC_MoveParent,
/* 17412*/      OPC_RecordChild1, // #1 = $rs2
/* 17413*/      OPC_MoveChild2,
/* 17414*/      OPC_CheckOpcode, TARGET_VAL(ISD::FNEG),
/* 17417*/      OPC_RecordChild0, // #2 = $rs3
/* 17418*/      OPC_MoveParent,
/* 17419*/      OPC_SwitchType /*2 cases */, 50, MVT::f32,// ->17472
/* 17422*/        OPC_Scope, 15, /*->17439*/ // 3 children in Scope
/* 17424*/          OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17426*/          OPC_EmitInteger, MVT::i32, 7, 
/* 17429*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FNMADD_S), 0,
                        MVT::f32, 4/*#Ops*/, 0, 1, 2, 3, 
                    // Src: (fma:{ *:[f32] } (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs1), FPR32:{ *:[f32] }:$rs2, (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs3)) - Complexity = 9
                    // Dst: (FNMADD_S:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3, 7:{ *:[i32] })
/* 17439*/        /*Scope*/ 15, /*->17455*/
/* 17440*/          OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17442*/          OPC_EmitInteger, MVT::i64, 7, 
/* 17445*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FNMADD_S), 0,
                        MVT::f32, 4/*#Ops*/, 0, 1, 2, 3, 
                    // Src: (fma:{ *:[f32] } (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs1), FPR32:{ *:[f32] }:$rs2, (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs3)) - Complexity = 9
                    // Dst: (FNMADD_S:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3, 7:{ *:[i64] })
/* 17455*/        /*Scope*/ 15, /*->17471*/
/* 17456*/          OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 17458*/          OPC_EmitInteger, MVT::i32, 7, 
/* 17461*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FNMADD_S), 0,
                        MVT::f32, 4/*#Ops*/, 0, 1, 2, 3, 
                    // Src: (fma:{ *:[f32] } (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs1), FPR32:{ *:[f32] }:$rs2, (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs3)) - Complexity = 9
                    // Dst: (FNMADD_S:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3, 7:{ *:[i32] })
/* 17471*/        0, /*End of Scope*/
/* 17472*/      /*SwitchType*/ 50, MVT::f64,// ->17524
/* 17474*/        OPC_Scope, 15, /*->17491*/ // 3 children in Scope
/* 17476*/          OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17478*/          OPC_EmitInteger, MVT::i32, 7, 
/* 17481*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FNMADD_D), 0,
                        MVT::f64, 4/*#Ops*/, 0, 1, 2, 3, 
                    // Src: (fma:{ *:[f64] } (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs1), FPR64:{ *:[f64] }:$rs2, (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs3)) - Complexity = 9
                    // Dst: (FNMADD_D:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3, 7:{ *:[i32] })
/* 17491*/        /*Scope*/ 15, /*->17507*/
/* 17492*/          OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17494*/          OPC_EmitInteger, MVT::i64, 7, 
/* 17497*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FNMADD_D), 0,
                        MVT::f64, 4/*#Ops*/, 0, 1, 2, 3, 
                    // Src: (fma:{ *:[f64] } (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs1), FPR64:{ *:[f64] }:$rs2, (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs3)) - Complexity = 9
                    // Dst: (FNMADD_D:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3, 7:{ *:[i64] })
/* 17507*/        /*Scope*/ 15, /*->17523*/
/* 17508*/          OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 17510*/          OPC_EmitInteger, MVT::i32, 7, 
/* 17513*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FNMADD_D), 0,
                        MVT::f64, 4/*#Ops*/, 0, 1, 2, 3, 
                    // Src: (fma:{ *:[f64] } (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs1), FPR64:{ *:[f64] }:$rs2, (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs3)) - Complexity = 9
                    // Dst: (FNMADD_D:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3, 7:{ *:[i32] })
/* 17523*/        0, /*End of Scope*/
/* 17524*/      0, // EndSwitchType
/* 17525*/    /*Scope*/ 60, /*->17586*/
/* 17526*/      OPC_RecordChild0, // #0 = $rs1
/* 17527*/      OPC_RecordChild1, // #1 = $rs2
/* 17528*/      OPC_MoveChild2,
/* 17529*/      OPC_CheckOpcode, TARGET_VAL(ISD::FNEG),
/* 17532*/      OPC_RecordChild0, // #2 = $rs3
/* 17533*/      OPC_MoveParent,
/* 17534*/      OPC_CheckType, MVT::f32,
/* 17536*/      OPC_Scope, 15, /*->17553*/ // 3 children in Scope
/* 17538*/        OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17540*/        OPC_EmitInteger, MVT::i32, 7, 
/* 17543*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMSUB_S), 0,
                      MVT::f32, 4/*#Ops*/, 0, 1, 2, 3, 
                  // Src: (fma:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs3)) - Complexity = 6
                  // Dst: (FMSUB_S:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3, 7:{ *:[i32] })
/* 17553*/      /*Scope*/ 15, /*->17569*/
/* 17554*/        OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17556*/        OPC_EmitInteger, MVT::i64, 7, 
/* 17559*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMSUB_S), 0,
                      MVT::f32, 4/*#Ops*/, 0, 1, 2, 3, 
                  // Src: (fma:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs3)) - Complexity = 6
                  // Dst: (FMSUB_S:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3, 7:{ *:[i64] })
/* 17569*/      /*Scope*/ 15, /*->17585*/
/* 17570*/        OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 17572*/        OPC_EmitInteger, MVT::i32, 7, 
/* 17575*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMSUB_S), 0,
                      MVT::f32, 4/*#Ops*/, 0, 1, 2, 3, 
                  // Src: (fma:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs3)) - Complexity = 6
                  // Dst: (FMSUB_S:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3, 7:{ *:[i32] })
/* 17585*/      0, /*End of Scope*/
/* 17586*/    /*Scope*/ 60, /*->17647*/
/* 17587*/      OPC_MoveChild0,
/* 17588*/      OPC_CheckOpcode, TARGET_VAL(ISD::FNEG),
/* 17591*/      OPC_RecordChild0, // #0 = $rs1
/* 17592*/      OPC_MoveParent,
/* 17593*/      OPC_RecordChild1, // #1 = $rs2
/* 17594*/      OPC_RecordChild2, // #2 = $rs3
/* 17595*/      OPC_CheckType, MVT::f32,
/* 17597*/      OPC_Scope, 15, /*->17614*/ // 3 children in Scope
/* 17599*/        OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17601*/        OPC_EmitInteger, MVT::i32, 7, 
/* 17604*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FNMSUB_S), 0,
                      MVT::f32, 4/*#Ops*/, 0, 1, 2, 3, 
                  // Src: (fma:{ *:[f32] } (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs1), FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3) - Complexity = 6
                  // Dst: (FNMSUB_S:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3, 7:{ *:[i32] })
/* 17614*/      /*Scope*/ 15, /*->17630*/
/* 17615*/        OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17617*/        OPC_EmitInteger, MVT::i64, 7, 
/* 17620*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FNMSUB_S), 0,
                      MVT::f32, 4/*#Ops*/, 0, 1, 2, 3, 
                  // Src: (fma:{ *:[f32] } (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs1), FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3) - Complexity = 6
                  // Dst: (FNMSUB_S:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3, 7:{ *:[i64] })
/* 17630*/      /*Scope*/ 15, /*->17646*/
/* 17631*/        OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 17633*/        OPC_EmitInteger, MVT::i32, 7, 
/* 17636*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FNMSUB_S), 0,
                      MVT::f32, 4/*#Ops*/, 0, 1, 2, 3, 
                  // Src: (fma:{ *:[f32] } (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs1), FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3) - Complexity = 6
                  // Dst: (FNMSUB_S:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3, 7:{ *:[i32] })
/* 17646*/      0, /*End of Scope*/
/* 17647*/    /*Scope*/ 60, /*->17708*/
/* 17648*/      OPC_RecordChild0, // #0 = $rs1
/* 17649*/      OPC_RecordChild1, // #1 = $rs2
/* 17650*/      OPC_MoveChild2,
/* 17651*/      OPC_CheckOpcode, TARGET_VAL(ISD::FNEG),
/* 17654*/      OPC_RecordChild0, // #2 = $rs3
/* 17655*/      OPC_MoveParent,
/* 17656*/      OPC_CheckType, MVT::f64,
/* 17658*/      OPC_Scope, 15, /*->17675*/ // 3 children in Scope
/* 17660*/        OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17662*/        OPC_EmitInteger, MVT::i32, 7, 
/* 17665*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMSUB_D), 0,
                      MVT::f64, 4/*#Ops*/, 0, 1, 2, 3, 
                  // Src: (fma:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs3)) - Complexity = 6
                  // Dst: (FMSUB_D:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3, 7:{ *:[i32] })
/* 17675*/      /*Scope*/ 15, /*->17691*/
/* 17676*/        OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17678*/        OPC_EmitInteger, MVT::i64, 7, 
/* 17681*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMSUB_D), 0,
                      MVT::f64, 4/*#Ops*/, 0, 1, 2, 3, 
                  // Src: (fma:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs3)) - Complexity = 6
                  // Dst: (FMSUB_D:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3, 7:{ *:[i64] })
/* 17691*/      /*Scope*/ 15, /*->17707*/
/* 17692*/        OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 17694*/        OPC_EmitInteger, MVT::i32, 7, 
/* 17697*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMSUB_D), 0,
                      MVT::f64, 4/*#Ops*/, 0, 1, 2, 3, 
                  // Src: (fma:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs3)) - Complexity = 6
                  // Dst: (FMSUB_D:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3, 7:{ *:[i32] })
/* 17707*/      0, /*End of Scope*/
/* 17708*/    /*Scope*/ 60, /*->17769*/
/* 17709*/      OPC_MoveChild0,
/* 17710*/      OPC_CheckOpcode, TARGET_VAL(ISD::FNEG),
/* 17713*/      OPC_RecordChild0, // #0 = $rs1
/* 17714*/      OPC_MoveParent,
/* 17715*/      OPC_RecordChild1, // #1 = $rs2
/* 17716*/      OPC_RecordChild2, // #2 = $rs3
/* 17717*/      OPC_CheckType, MVT::f64,
/* 17719*/      OPC_Scope, 15, /*->17736*/ // 3 children in Scope
/* 17721*/        OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17723*/        OPC_EmitInteger, MVT::i32, 7, 
/* 17726*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FNMSUB_D), 0,
                      MVT::f64, 4/*#Ops*/, 0, 1, 2, 3, 
                  // Src: (fma:{ *:[f64] } (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs1), FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3) - Complexity = 6
                  // Dst: (FNMSUB_D:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3, 7:{ *:[i32] })
/* 17736*/      /*Scope*/ 15, /*->17752*/
/* 17737*/        OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17739*/        OPC_EmitInteger, MVT::i64, 7, 
/* 17742*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FNMSUB_D), 0,
                      MVT::f64, 4/*#Ops*/, 0, 1, 2, 3, 
                  // Src: (fma:{ *:[f64] } (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs1), FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3) - Complexity = 6
                  // Dst: (FNMSUB_D:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3, 7:{ *:[i64] })
/* 17752*/      /*Scope*/ 15, /*->17768*/
/* 17753*/        OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 17755*/        OPC_EmitInteger, MVT::i32, 7, 
/* 17758*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FNMSUB_D), 0,
                      MVT::f64, 4/*#Ops*/, 0, 1, 2, 3, 
                  // Src: (fma:{ *:[f64] } (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs1), FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3) - Complexity = 6
                  // Dst: (FNMSUB_D:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3, 7:{ *:[i32] })
/* 17768*/      0, /*End of Scope*/
/* 17769*/    /*Scope*/ 109, /*->17879*/
/* 17770*/      OPC_RecordChild0, // #0 = $rs1
/* 17771*/      OPC_RecordChild1, // #1 = $rs2
/* 17772*/      OPC_RecordChild2, // #2 = $rs3
/* 17773*/      OPC_SwitchType /*2 cases */, 50, MVT::f32,// ->17826
/* 17776*/        OPC_Scope, 15, /*->17793*/ // 3 children in Scope
/* 17778*/          OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17780*/          OPC_EmitInteger, MVT::i32, 7, 
/* 17783*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMADD_S), 0,
                        MVT::f32, 4/*#Ops*/, 0, 1, 2, 3, 
                    // Src: (fma:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3) - Complexity = 3
                    // Dst: (FMADD_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, ?:{ *:[f32] }:$rs3, 7:{ *:[i32] })
/* 17793*/        /*Scope*/ 15, /*->17809*/
/* 17794*/          OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17796*/          OPC_EmitInteger, MVT::i64, 7, 
/* 17799*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMADD_S), 0,
                        MVT::f32, 4/*#Ops*/, 0, 1, 2, 3, 
                    // Src: (fma:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3) - Complexity = 3
                    // Dst: (FMADD_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, ?:{ *:[f32] }:$rs3, 7:{ *:[i64] })
/* 17809*/        /*Scope*/ 15, /*->17825*/
/* 17810*/          OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 17812*/          OPC_EmitInteger, MVT::i32, 7, 
/* 17815*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMADD_S), 0,
                        MVT::f32, 4/*#Ops*/, 0, 1, 2, 3, 
                    // Src: (fma:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2, FPR32:{ *:[f32] }:$rs3) - Complexity = 3
                    // Dst: (FMADD_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, ?:{ *:[f32] }:$rs3, 7:{ *:[i32] })
/* 17825*/        0, /*End of Scope*/
/* 17826*/      /*SwitchType*/ 50, MVT::f64,// ->17878
/* 17828*/        OPC_Scope, 15, /*->17845*/ // 3 children in Scope
/* 17830*/          OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 17832*/          OPC_EmitInteger, MVT::i32, 7, 
/* 17835*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMADD_D), 0,
                        MVT::f64, 4/*#Ops*/, 0, 1, 2, 3, 
                    // Src: (fma:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3) - Complexity = 3
                    // Dst: (FMADD_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, ?:{ *:[f64] }:$rs3, 7:{ *:[i32] })
/* 17845*/        /*Scope*/ 15, /*->17861*/
/* 17846*/          OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 17848*/          OPC_EmitInteger, MVT::i64, 7, 
/* 17851*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMADD_D), 0,
                        MVT::f64, 4/*#Ops*/, 0, 1, 2, 3, 
                    // Src: (fma:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3) - Complexity = 3
                    // Dst: (FMADD_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, ?:{ *:[f64] }:$rs3, 7:{ *:[i64] })
/* 17861*/        /*Scope*/ 15, /*->17877*/
/* 17862*/          OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 17864*/          OPC_EmitInteger, MVT::i32, 7, 
/* 17867*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMADD_D), 0,
                        MVT::f64, 4/*#Ops*/, 0, 1, 2, 3, 
                    // Src: (fma:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2, FPR64:{ *:[f64] }:$rs3) - Complexity = 3
                    // Dst: (FMADD_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, ?:{ *:[f64] }:$rs3, 7:{ *:[i32] })
/* 17877*/        0, /*End of Scope*/
/* 17878*/      0, // EndSwitchType
/* 17879*/    0, /*End of Scope*/
/* 17880*/  /*SwitchOpcode*/ 73, TARGET_VAL(ISD::FCOPYSIGN),// ->17956
/* 17883*/    OPC_RecordChild0, // #0 = $rs1
/* 17884*/    OPC_Scope, 37, /*->17923*/ // 2 children in Scope
/* 17886*/      OPC_MoveChild1,
/* 17887*/      OPC_CheckOpcode, TARGET_VAL(ISD::FNEG),
/* 17890*/      OPC_RecordChild0, // #1 = $rs2
/* 17891*/      OPC_SwitchType /*2 cases */, 13, MVT::f32,// ->17907
/* 17894*/        OPC_MoveParent,
/* 17895*/        OPC_CheckType, MVT::f32,
/* 17897*/        OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 17899*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSGNJN_S), 0,
                      MVT::f32, 2/*#Ops*/, 0, 1, 
                  // Src: (fcopysign:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs2)) - Complexity = 6
                  // Dst: (FSGNJN_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 17907*/      /*SwitchType*/ 13, MVT::f64,// ->17922
/* 17909*/        OPC_MoveParent,
/* 17910*/        OPC_CheckType, MVT::f64,
/* 17912*/        OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 17914*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSGNJN_D), 0,
                      MVT::f64, 2/*#Ops*/, 0, 1, 
                  // Src: (fcopysign:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs2)) - Complexity = 6
                  // Dst: (FSGNJN_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 17922*/      0, // EndSwitchType
/* 17923*/    /*Scope*/ 31, /*->17955*/
/* 17924*/      OPC_RecordChild1, // #1 = $rs2
/* 17925*/      OPC_SwitchType /*2 cases */, 12, MVT::f32,// ->17940
/* 17928*/        OPC_CheckChild1Type, MVT::f32,
/* 17930*/        OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 17932*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSGNJ_S), 0,
                      MVT::f32, 2/*#Ops*/, 0, 1, 
                  // Src: (fcopysign:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                  // Dst: (FSGNJ_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 17940*/      /*SwitchType*/ 12, MVT::f64,// ->17954
/* 17942*/        OPC_CheckChild1Type, MVT::f64,
/* 17944*/        OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 17946*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSGNJ_D), 0,
                      MVT::f64, 2/*#Ops*/, 0, 1, 
                  // Src: (fcopysign:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                  // Dst: (FSGNJ_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 17954*/      0, // EndSwitchType
/* 17955*/    0, /*End of Scope*/
/* 17956*/  /*SwitchOpcode*/ 27, TARGET_VAL(ISD::FNEG),// ->17986
/* 17959*/    OPC_RecordChild0, // #0 = $rs1
/* 17960*/    OPC_SwitchType /*2 cases */, 10, MVT::f32,// ->17973
/* 17963*/      OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 17965*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSGNJN_S), 0,
                    MVT::f32, 2/*#Ops*/, 0, 0, 
                // Src: (fneg:{ *:[f32] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                // Dst: (FSGNJN_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs1)
/* 17973*/    /*SwitchType*/ 10, MVT::f64,// ->17985
/* 17975*/      OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 17977*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSGNJN_D), 0,
                    MVT::f64, 2/*#Ops*/, 0, 0, 
                // Src: (fneg:{ *:[f64] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                // Dst: (FSGNJN_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs1)
/* 17985*/    0, // EndSwitchType
/* 17986*/  /*SwitchOpcode*/ 27, TARGET_VAL(ISD::FABS),// ->18016
/* 17989*/    OPC_RecordChild0, // #0 = $rs1
/* 17990*/    OPC_SwitchType /*2 cases */, 10, MVT::f32,// ->18003
/* 17993*/      OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 17995*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSGNJX_S), 0,
                    MVT::f32, 2/*#Ops*/, 0, 0, 
                // Src: (fabs:{ *:[f32] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                // Dst: (FSGNJX_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs1)
/* 18003*/    /*SwitchType*/ 10, MVT::f64,// ->18015
/* 18005*/      OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 18007*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSGNJX_D), 0,
                    MVT::f64, 2/*#Ops*/, 0, 0, 
                // Src: (fabs:{ *:[f64] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                // Dst: (FSGNJX_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs1)
/* 18015*/    0, // EndSwitchType
/* 18016*/  /*SwitchOpcode*/ 28, TARGET_VAL(ISD::FMINNUM),// ->18047
/* 18019*/    OPC_RecordChild0, // #0 = $rs1
/* 18020*/    OPC_RecordChild1, // #1 = $rs2
/* 18021*/    OPC_SwitchType /*2 cases */, 10, MVT::f32,// ->18034
/* 18024*/      OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 18026*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMIN_S), 0,
                    MVT::f32, 2/*#Ops*/, 0, 1, 
                // Src: (fminnum:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                // Dst: (FMIN_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 18034*/    /*SwitchType*/ 10, MVT::f64,// ->18046
/* 18036*/      OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 18038*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMIN_D), 0,
                    MVT::f64, 2/*#Ops*/, 0, 1, 
                // Src: (fminnum:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                // Dst: (FMIN_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 18046*/    0, // EndSwitchType
/* 18047*/  /*SwitchOpcode*/ 28, TARGET_VAL(ISD::FMAXNUM),// ->18078
/* 18050*/    OPC_RecordChild0, // #0 = $rs1
/* 18051*/    OPC_RecordChild1, // #1 = $rs2
/* 18052*/    OPC_SwitchType /*2 cases */, 10, MVT::f32,// ->18065
/* 18055*/      OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 18057*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMAX_S), 0,
                    MVT::f32, 2/*#Ops*/, 0, 1, 
                // Src: (fmaxnum:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                // Dst: (FMAX_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2)
/* 18065*/    /*SwitchType*/ 10, MVT::f64,// ->18077
/* 18067*/      OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 18069*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMAX_D), 0,
                    MVT::f64, 2/*#Ops*/, 0, 1, 
                // Src: (fmaxnum:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                // Dst: (FMAX_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2)
/* 18077*/    0, // EndSwitchType
/* 18078*/  /*SwitchOpcode*/ 10, TARGET_VAL(ISD::FP_EXTEND),// ->18091
/* 18081*/    OPC_RecordChild0, // #0 = $rs1
/* 18082*/    OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 18084*/    OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_D_S), 0,
                  MVT::f64, 1/*#Ops*/, 0, 
              // Src: (fpextend:{ *:[f64] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
              // Dst: (FCVT_D_S:{ *:[f64] } FPR32:{ *:[f32] }:$rs1)
/* 18091*/  /*SwitchOpcode*/ 102, TARGET_VAL(ISD::FADD),// ->18196
/* 18094*/    OPC_RecordChild0, // #0 = $rs1
/* 18095*/    OPC_RecordChild1, // #1 = $rs2
/* 18096*/    OPC_SwitchType /*2 cases */, 47, MVT::f32,// ->18146
/* 18099*/      OPC_Scope, 14, /*->18115*/ // 3 children in Scope
/* 18101*/        OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18103*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18106*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FADD_S), 0,
                      MVT::f32, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fadd:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                  // Dst: (FADD_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, 7:{ *:[i32] })
/* 18115*/      /*Scope*/ 14, /*->18130*/
/* 18116*/        OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18118*/        OPC_EmitInteger, MVT::i64, 7, 
/* 18121*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FADD_S), 0,
                      MVT::f32, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fadd:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                  // Dst: (FADD_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, 7:{ *:[i64] })
/* 18130*/      /*Scope*/ 14, /*->18145*/
/* 18131*/        OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 18133*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18136*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FADD_S), 0,
                      MVT::f32, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fadd:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                  // Dst: (FADD_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, 7:{ *:[i32] })
/* 18145*/      0, /*End of Scope*/
/* 18146*/    /*SwitchType*/ 47, MVT::f64,// ->18195
/* 18148*/      OPC_Scope, 14, /*->18164*/ // 3 children in Scope
/* 18150*/        OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18152*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18155*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FADD_D), 0,
                      MVT::f64, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fadd:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                  // Dst: (FADD_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, 7:{ *:[i32] })
/* 18164*/      /*Scope*/ 14, /*->18179*/
/* 18165*/        OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18167*/        OPC_EmitInteger, MVT::i64, 7, 
/* 18170*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FADD_D), 0,
                      MVT::f64, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fadd:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                  // Dst: (FADD_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, 7:{ *:[i64] })
/* 18179*/      /*Scope*/ 14, /*->18194*/
/* 18180*/        OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 18182*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18185*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FADD_D), 0,
                      MVT::f64, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fadd:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                  // Dst: (FADD_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, 7:{ *:[i32] })
/* 18194*/      0, /*End of Scope*/
/* 18195*/    0, // EndSwitchType
/* 18196*/  /*SwitchOpcode*/ 102, TARGET_VAL(ISD::FSUB),// ->18301
/* 18199*/    OPC_RecordChild0, // #0 = $rs1
/* 18200*/    OPC_RecordChild1, // #1 = $rs2
/* 18201*/    OPC_SwitchType /*2 cases */, 47, MVT::f32,// ->18251
/* 18204*/      OPC_Scope, 14, /*->18220*/ // 3 children in Scope
/* 18206*/        OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18208*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18211*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSUB_S), 0,
                      MVT::f32, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fsub:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                  // Dst: (FSUB_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, 7:{ *:[i32] })
/* 18220*/      /*Scope*/ 14, /*->18235*/
/* 18221*/        OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18223*/        OPC_EmitInteger, MVT::i64, 7, 
/* 18226*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSUB_S), 0,
                      MVT::f32, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fsub:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                  // Dst: (FSUB_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, 7:{ *:[i64] })
/* 18235*/      /*Scope*/ 14, /*->18250*/
/* 18236*/        OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 18238*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18241*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSUB_S), 0,
                      MVT::f32, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fsub:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                  // Dst: (FSUB_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, 7:{ *:[i32] })
/* 18250*/      0, /*End of Scope*/
/* 18251*/    /*SwitchType*/ 47, MVT::f64,// ->18300
/* 18253*/      OPC_Scope, 14, /*->18269*/ // 3 children in Scope
/* 18255*/        OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18257*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18260*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSUB_D), 0,
                      MVT::f64, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fsub:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                  // Dst: (FSUB_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, 7:{ *:[i32] })
/* 18269*/      /*Scope*/ 14, /*->18284*/
/* 18270*/        OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18272*/        OPC_EmitInteger, MVT::i64, 7, 
/* 18275*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSUB_D), 0,
                      MVT::f64, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fsub:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                  // Dst: (FSUB_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, 7:{ *:[i64] })
/* 18284*/      /*Scope*/ 14, /*->18299*/
/* 18285*/        OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 18287*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18290*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSUB_D), 0,
                      MVT::f64, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fsub:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                  // Dst: (FSUB_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, 7:{ *:[i32] })
/* 18299*/      0, /*End of Scope*/
/* 18300*/    0, // EndSwitchType
/* 18301*/  /*SwitchOpcode*/ 102, TARGET_VAL(ISD::FMUL),// ->18406
/* 18304*/    OPC_RecordChild0, // #0 = $rs1
/* 18305*/    OPC_RecordChild1, // #1 = $rs2
/* 18306*/    OPC_SwitchType /*2 cases */, 47, MVT::f32,// ->18356
/* 18309*/      OPC_Scope, 14, /*->18325*/ // 3 children in Scope
/* 18311*/        OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18313*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18316*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMUL_S), 0,
                      MVT::f32, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fmul:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                  // Dst: (FMUL_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, 7:{ *:[i32] })
/* 18325*/      /*Scope*/ 14, /*->18340*/
/* 18326*/        OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18328*/        OPC_EmitInteger, MVT::i64, 7, 
/* 18331*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMUL_S), 0,
                      MVT::f32, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fmul:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                  // Dst: (FMUL_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, 7:{ *:[i64] })
/* 18340*/      /*Scope*/ 14, /*->18355*/
/* 18341*/        OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 18343*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18346*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMUL_S), 0,
                      MVT::f32, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fmul:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                  // Dst: (FMUL_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, 7:{ *:[i32] })
/* 18355*/      0, /*End of Scope*/
/* 18356*/    /*SwitchType*/ 47, MVT::f64,// ->18405
/* 18358*/      OPC_Scope, 14, /*->18374*/ // 3 children in Scope
/* 18360*/        OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18362*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18365*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMUL_D), 0,
                      MVT::f64, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fmul:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                  // Dst: (FMUL_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, 7:{ *:[i32] })
/* 18374*/      /*Scope*/ 14, /*->18389*/
/* 18375*/        OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18377*/        OPC_EmitInteger, MVT::i64, 7, 
/* 18380*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMUL_D), 0,
                      MVT::f64, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fmul:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                  // Dst: (FMUL_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, 7:{ *:[i64] })
/* 18389*/      /*Scope*/ 14, /*->18404*/
/* 18390*/        OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 18392*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18395*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FMUL_D), 0,
                      MVT::f64, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fmul:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                  // Dst: (FMUL_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, 7:{ *:[i32] })
/* 18404*/      0, /*End of Scope*/
/* 18405*/    0, // EndSwitchType
/* 18406*/  /*SwitchOpcode*/ 102, TARGET_VAL(ISD::FDIV),// ->18511
/* 18409*/    OPC_RecordChild0, // #0 = $rs1
/* 18410*/    OPC_RecordChild1, // #1 = $rs2
/* 18411*/    OPC_SwitchType /*2 cases */, 47, MVT::f32,// ->18461
/* 18414*/      OPC_Scope, 14, /*->18430*/ // 3 children in Scope
/* 18416*/        OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18418*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18421*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FDIV_S), 0,
                      MVT::f32, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fdiv:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                  // Dst: (FDIV_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, 7:{ *:[i32] })
/* 18430*/      /*Scope*/ 14, /*->18445*/
/* 18431*/        OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18433*/        OPC_EmitInteger, MVT::i64, 7, 
/* 18436*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FDIV_S), 0,
                      MVT::f32, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fdiv:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                  // Dst: (FDIV_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, 7:{ *:[i64] })
/* 18445*/      /*Scope*/ 14, /*->18460*/
/* 18446*/        OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 18448*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18451*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FDIV_S), 0,
                      MVT::f32, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fdiv:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, FPR32:{ *:[f32] }:$rs2) - Complexity = 3
                  // Dst: (FDIV_S:{ *:[f32] } ?:{ *:[f32] }:$rs1, ?:{ *:[f32] }:$rs2, 7:{ *:[i32] })
/* 18460*/      0, /*End of Scope*/
/* 18461*/    /*SwitchType*/ 47, MVT::f64,// ->18510
/* 18463*/      OPC_Scope, 14, /*->18479*/ // 3 children in Scope
/* 18465*/        OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18467*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18470*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FDIV_D), 0,
                      MVT::f64, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fdiv:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                  // Dst: (FDIV_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, 7:{ *:[i32] })
/* 18479*/      /*Scope*/ 14, /*->18494*/
/* 18480*/        OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18482*/        OPC_EmitInteger, MVT::i64, 7, 
/* 18485*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FDIV_D), 0,
                      MVT::f64, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fdiv:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                  // Dst: (FDIV_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, 7:{ *:[i64] })
/* 18494*/      /*Scope*/ 14, /*->18509*/
/* 18495*/        OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 18497*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18500*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FDIV_D), 0,
                      MVT::f64, 3/*#Ops*/, 0, 1, 2, 
                  // Src: (fdiv:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, FPR64:{ *:[f64] }:$rs2) - Complexity = 3
                  // Dst: (FDIV_D:{ *:[f64] } ?:{ *:[f64] }:$rs1, ?:{ *:[f64] }:$rs2, 7:{ *:[i32] })
/* 18509*/      0, /*End of Scope*/
/* 18510*/    0, // EndSwitchType
/* 18511*/  /*SwitchOpcode*/ 95, TARGET_VAL(ISD::FSQRT),// ->18609
/* 18514*/    OPC_RecordChild0, // #0 = $rs1
/* 18515*/    OPC_SwitchType /*2 cases */, 44, MVT::f32,// ->18562
/* 18518*/      OPC_Scope, 13, /*->18533*/ // 3 children in Scope
/* 18520*/        OPC_CheckPatternPredicate, 8, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18522*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18525*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSQRT_S), 0,
                      MVT::f32, 2/*#Ops*/, 0, 1, 
                  // Src: (fsqrt:{ *:[f32] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                  // Dst: (FSQRT_S:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, 7:{ *:[i32] })
/* 18533*/      /*Scope*/ 13, /*->18547*/
/* 18534*/        OPC_CheckPatternPredicate, 12, // (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18536*/        OPC_EmitInteger, MVT::i64, 7, 
/* 18539*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSQRT_S), 0,
                      MVT::f32, 2/*#Ops*/, 0, 1, 
                  // Src: (fsqrt:{ *:[f32] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                  // Dst: (FSQRT_S:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, 7:{ *:[i64] })
/* 18547*/      /*Scope*/ 13, /*->18561*/
/* 18548*/        OPC_CheckPatternPredicate, 9, // (Subtarget->hasStdExtF())
/* 18550*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18553*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSQRT_S), 0,
                      MVT::f32, 2/*#Ops*/, 0, 1, 
                  // Src: (fsqrt:{ *:[f32] } FPR32:{ *:[f32] }:$rs1) - Complexity = 3
                  // Dst: (FSQRT_S:{ *:[f32] } FPR32:{ *:[f32] }:$rs1, 7:{ *:[i32] })
/* 18561*/      0, /*End of Scope*/
/* 18562*/    /*SwitchType*/ 44, MVT::f64,// ->18608
/* 18564*/      OPC_Scope, 13, /*->18579*/ // 3 children in Scope
/* 18566*/        OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18568*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18571*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSQRT_D), 0,
                      MVT::f64, 2/*#Ops*/, 0, 1, 
                  // Src: (fsqrt:{ *:[f64] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                  // Dst: (FSQRT_D:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, 7:{ *:[i32] })
/* 18579*/      /*Scope*/ 13, /*->18593*/
/* 18580*/        OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18582*/        OPC_EmitInteger, MVT::i64, 7, 
/* 18585*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSQRT_D), 0,
                      MVT::f64, 2/*#Ops*/, 0, 1, 
                  // Src: (fsqrt:{ *:[f64] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                  // Dst: (FSQRT_D:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, 7:{ *:[i64] })
/* 18593*/      /*Scope*/ 13, /*->18607*/
/* 18594*/        OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 18596*/        OPC_EmitInteger, MVT::i32, 7, 
/* 18599*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FSQRT_D), 0,
                      MVT::f64, 2/*#Ops*/, 0, 1, 
                  // Src: (fsqrt:{ *:[f64] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                  // Dst: (FSQRT_D:{ *:[f64] } FPR64:{ *:[f64] }:$rs1, 7:{ *:[i32] })
/* 18607*/      0, /*End of Scope*/
/* 18608*/    0, // EndSwitchType
/* 18609*/  /*SwitchOpcode*/ 95, TARGET_VAL(ISD::SINT_TO_FP),// ->18707
/* 18612*/    OPC_RecordChild0, // #0 = $rs1
/* 18613*/    OPC_Scope, 60, /*->18675*/ // 2 children in Scope
/* 18615*/      OPC_CheckChild0Type, MVT::i32,
/* 18617*/      OPC_SwitchType /*2 cases */, 30, MVT::f32,// ->18650
/* 18620*/        OPC_Scope, 13, /*->18635*/ // 2 children in Scope
/* 18622*/          OPC_CheckPatternPredicate, 20, // (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18624*/          OPC_EmitInteger, MVT::i32, 7, 
/* 18627*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_S_W), 0,
                        MVT::f32, 2/*#Ops*/, 0, 1, 
                    // Src: (sint_to_fp:{ *:[f32] } GPR:{ *:[i32] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_S_W:{ *:[f32] } ?:{ *:[i32] }:$rs1, 7:{ *:[i32] })
/* 18635*/        /*Scope*/ 13, /*->18649*/
/* 18636*/          OPC_CheckPatternPredicate, 21, // (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit())
/* 18638*/          OPC_EmitInteger, MVT::i32, 7, 
/* 18641*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_S_W), 0,
                        MVT::f32, 2/*#Ops*/, 0, 1, 
                    // Src: (sint_to_fp:{ *:[f32] } GPR:{ *:[i32] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_S_W:{ *:[f32] } ?:{ *:[i32] }:$rs1, 7:{ *:[i32] })
/* 18649*/        0, /*End of Scope*/
/* 18650*/      /*SwitchType*/ 22, MVT::f64,// ->18674
/* 18652*/        OPC_Scope, 9, /*->18663*/ // 2 children in Scope
/* 18654*/          OPC_CheckPatternPredicate, 23, // (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18656*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_D_W), 0,
                        MVT::f64, 1/*#Ops*/, 0, 
                    // Src: (sint_to_fp:{ *:[f64] } GPR:{ *:[i32] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_D_W:{ *:[f64] } GPR:{ *:[i32] }:$rs1)
/* 18663*/        /*Scope*/ 9, /*->18673*/
/* 18664*/          OPC_CheckPatternPredicate, 24, // (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit())
/* 18666*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_D_W), 0,
                        MVT::f64, 1/*#Ops*/, 0, 
                    // Src: (sint_to_fp:{ *:[f64] } GPR:{ *:[i32] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_D_W:{ *:[f64] } GPR:{ *:[i32] }:$rs1)
/* 18673*/        0, /*End of Scope*/
/* 18674*/      0, // EndSwitchType
/* 18675*/    /*Scope*/ 30, /*->18706*/
/* 18676*/      OPC_CheckChild0Type, MVT::i64,
/* 18678*/      OPC_SwitchType /*2 cases */, 13, MVT::f32,// ->18694
/* 18681*/        OPC_CheckPatternPredicate, 22, // (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18683*/        OPC_EmitInteger, MVT::i64, 7, 
/* 18686*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_S_W), 0,
                      MVT::f32, 2/*#Ops*/, 0, 1, 
                  // Src: (sint_to_fp:{ *:[f32] } GPR:{ *:[i64] }:$rs1) - Complexity = 3
                  // Dst: (FCVT_S_W:{ *:[f32] } ?:{ *:[i64] }:$rs1, 7:{ *:[i64] })
/* 18694*/      /*SwitchType*/ 9, MVT::f64,// ->18705
/* 18696*/        OPC_CheckPatternPredicate, 25, // (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18698*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_D_W), 0,
                      MVT::f64, 1/*#Ops*/, 0, 
                  // Src: (sint_to_fp:{ *:[f64] } GPR:{ *:[i64] }:$rs1) - Complexity = 3
                  // Dst: (FCVT_D_W:{ *:[f64] } GPR:{ *:[i64] }:$rs1)
/* 18705*/      0, // EndSwitchType
/* 18706*/    0, /*End of Scope*/
/* 18707*/  /*SwitchOpcode*/ 95, TARGET_VAL(ISD::UINT_TO_FP),// ->18805
/* 18710*/    OPC_RecordChild0, // #0 = $rs1
/* 18711*/    OPC_Scope, 60, /*->18773*/ // 2 children in Scope
/* 18713*/      OPC_CheckChild0Type, MVT::i32,
/* 18715*/      OPC_SwitchType /*2 cases */, 30, MVT::f32,// ->18748
/* 18718*/        OPC_Scope, 13, /*->18733*/ // 2 children in Scope
/* 18720*/          OPC_CheckPatternPredicate, 20, // (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18722*/          OPC_EmitInteger, MVT::i32, 7, 
/* 18725*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_S_WU), 0,
                        MVT::f32, 2/*#Ops*/, 0, 1, 
                    // Src: (uint_to_fp:{ *:[f32] } GPR:{ *:[i32] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_S_WU:{ *:[f32] } ?:{ *:[i32] }:$rs1, 7:{ *:[i32] })
/* 18733*/        /*Scope*/ 13, /*->18747*/
/* 18734*/          OPC_CheckPatternPredicate, 21, // (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit())
/* 18736*/          OPC_EmitInteger, MVT::i32, 7, 
/* 18739*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_S_WU), 0,
                        MVT::f32, 2/*#Ops*/, 0, 1, 
                    // Src: (uint_to_fp:{ *:[f32] } GPR:{ *:[i32] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_S_WU:{ *:[f32] } ?:{ *:[i32] }:$rs1, 7:{ *:[i32] })
/* 18747*/        0, /*End of Scope*/
/* 18748*/      /*SwitchType*/ 22, MVT::f64,// ->18772
/* 18750*/        OPC_Scope, 9, /*->18761*/ // 2 children in Scope
/* 18752*/          OPC_CheckPatternPredicate, 23, // (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18754*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_D_WU), 0,
                        MVT::f64, 1/*#Ops*/, 0, 
                    // Src: (uint_to_fp:{ *:[f64] } GPR:{ *:[i32] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_D_WU:{ *:[f64] } GPR:{ *:[i32] }:$rs1)
/* 18761*/        /*Scope*/ 9, /*->18771*/
/* 18762*/          OPC_CheckPatternPredicate, 24, // (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit())
/* 18764*/          OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_D_WU), 0,
                        MVT::f64, 1/*#Ops*/, 0, 
                    // Src: (uint_to_fp:{ *:[f64] } GPR:{ *:[i32] }:$rs1) - Complexity = 3
                    // Dst: (FCVT_D_WU:{ *:[f64] } GPR:{ *:[i32] }:$rs1)
/* 18771*/        0, /*End of Scope*/
/* 18772*/      0, // EndSwitchType
/* 18773*/    /*Scope*/ 30, /*->18804*/
/* 18774*/      OPC_CheckChild0Type, MVT::i64,
/* 18776*/      OPC_SwitchType /*2 cases */, 13, MVT::f32,// ->18792
/* 18779*/        OPC_CheckPatternPredicate, 22, // (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18781*/        OPC_EmitInteger, MVT::i64, 7, 
/* 18784*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_S_WU), 0,
                      MVT::f32, 2/*#Ops*/, 0, 1, 
                  // Src: (uint_to_fp:{ *:[f32] } GPR:{ *:[i64] }:$rs1) - Complexity = 3
                  // Dst: (FCVT_S_WU:{ *:[f32] } ?:{ *:[i64] }:$rs1, 7:{ *:[i64] })
/* 18792*/      /*SwitchType*/ 9, MVT::f64,// ->18803
/* 18794*/        OPC_CheckPatternPredicate, 25, // (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18796*/        OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_D_WU), 0,
                      MVT::f64, 1/*#Ops*/, 0, 
                  // Src: (uint_to_fp:{ *:[f64] } GPR:{ *:[i64] }:$rs1) - Complexity = 3
                  // Dst: (FCVT_D_WU:{ *:[f64] } GPR:{ *:[i64] }:$rs1)
/* 18803*/      0, // EndSwitchType
/* 18804*/    0, /*End of Scope*/
/* 18805*/  /*SwitchOpcode*/ 45, TARGET_VAL(ISD::FP_ROUND),// ->18853
/* 18808*/    OPC_RecordChild0, // #0 = $rs1
/* 18809*/    OPC_Scope, 13, /*->18824*/ // 3 children in Scope
/* 18811*/      OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18813*/      OPC_EmitInteger, MVT::i32, 7, 
/* 18816*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_S_D), 0,
                    MVT::f32, 2/*#Ops*/, 0, 1, 
                // Src: (fpround:{ *:[f32] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                // Dst: (FCVT_S_D:{ *:[f32] } FPR64:{ *:[f64] }:$rs1, 7:{ *:[i32] })
/* 18824*/    /*Scope*/ 13, /*->18838*/
/* 18825*/      OPC_CheckPatternPredicate, 13, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"))
/* 18827*/      OPC_EmitInteger, MVT::i64, 7, 
/* 18830*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_S_D), 0,
                    MVT::f32, 2/*#Ops*/, 0, 1, 
                // Src: (fpround:{ *:[f32] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                // Dst: (FCVT_S_D:{ *:[f32] } FPR64:{ *:[f64] }:$rs1, 7:{ *:[i64] })
/* 18838*/    /*Scope*/ 13, /*->18852*/
/* 18839*/      OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 18841*/      OPC_EmitInteger, MVT::i32, 7, 
/* 18844*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::FCVT_S_D), 0,
                    MVT::f32, 2/*#Ops*/, 0, 1, 
                // Src: (fpround:{ *:[f32] } FPR64:{ *:[f64] }:$rs1) - Complexity = 3
                // Dst: (FCVT_S_D:{ *:[f32] } FPR64:{ *:[f64] }:$rs1, 7:{ *:[i32] })
/* 18852*/    0, /*End of Scope*/
/* 18853*/  /*SwitchOpcode*/ 26, TARGET_VAL(RISCVISD::BuildPairF64),// ->18882
/* 18856*/    OPC_RecordChild0, // #0 = $src1
/* 18857*/    OPC_RecordChild1, // #1 = $src2
/* 18858*/    OPC_Scope, 10, /*->18870*/ // 2 children in Scope
/* 18860*/      OPC_CheckPatternPredicate, 10, // (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"))
/* 18862*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::BuildPairF64Pseudo), 0,
                    MVT::f64, 2/*#Ops*/, 0, 1, 
                // Src: (RISCVBuildPairF64:{ *:[f64] } GPR:{ *:[i32] }:$src1, GPR:{ *:[i32] }:$src2) - Complexity = 3
                // Dst: (BuildPairF64Pseudo:{ *:[f64] } GPR:{ *:[i32] }:$src1, GPR:{ *:[i32] }:$src2)
/* 18870*/    /*Scope*/ 10, /*->18881*/
/* 18871*/      OPC_CheckPatternPredicate, 11, // (Subtarget->hasStdExtD())
/* 18873*/      OPC_MorphNodeTo1, TARGET_VAL(RISCV::BuildPairF64Pseudo), 0,
                    MVT::f64, 2/*#Ops*/, 0, 1, 
                // Src: (RISCVBuildPairF64:{ *:[f64] } GPR:{ *:[i32] }:$src1, GPR:{ *:[i32] }:$src2) - Complexity = 3
                // Dst: (BuildPairF64Pseudo:{ *:[f64] } GPR:{ *:[i32] }:$src1, GPR:{ *:[i32] }:$src2)
/* 18881*/    0, /*End of Scope*/
/* 18882*/  0, // EndSwitchOpcode
    0
  }; // Total Array size is 18884 bytes

  // Opcode Histogram:
  // #OPC_Scope                                = 450
  // #OPC_RecordNode                           = 30
  // #OPC_RecordChild                          = 265
  // #OPC_RecordMemRef                         = 16
  // #OPC_CaptureGlueInput                     = 8
  // #OPC_MoveChild                            = 118
  // #OPC_MoveParent                           = 226
  // #OPC_CheckSame                            = 0
  // #OPC_CheckChildSame                       = 0
  // #OPC_CheckPatternPredicate                = 853
  // #OPC_CheckPredicate                       = 527
  // #OPC_CheckOpcode                          = 91
  // #OPC_SwitchOpcode                         = 12
  // #OPC_CheckType                            = 102
  // #OPC_SwitchType                           = 108
  // #OPC_CheckChildType                       = 104
  // #OPC_CheckInteger                         = 0
  // #OPC_CheckChildInteger                    = 15
  // #OPC_CheckCondCode                        = 62
  // #OPC_CheckValueType                       = 6
  // #OPC_CheckComplexPat                      = 238
  // #OPC_CheckAndImm                          = 1
  // #OPC_CheckOrImm                           = 0
  // #OPC_CheckFoldableChainNode               = 0
  // #OPC_EmitInteger                          = 313
  // #OPC_EmitStringInteger                    = 0
  // #OPC_EmitRegister                         = 45
  // #OPC_EmitConvertToTarget                  = 310
  // #OPC_EmitMergeInputChains                 = 670
  // #OPC_EmitCopyToReg                        = 0
  // #OPC_EmitNode                             = 57
  // #OPC_EmitNodeXForm                        = 9
  // #OPC_CompleteMatch                        = 0
  // #OPC_MorphNodeTo                          = 964

  #undef TARGET_VAL
  SelectCodeCommon(N, MatcherTable,sizeof(MatcherTable));
}
#endif // GET_DAGISEL_BODY

#ifdef GET_DAGISEL_DECL
bool CheckPatternPredicate(unsigned PredNo) const override;
#endif
#if defined(GET_DAGISEL_BODY) || DAGISEL_INLINE
bool DAGISEL_CLASS_COLONCOLON CheckPatternPredicate(unsigned PredNo) const
#if DAGISEL_INLINE
  override
#endif
{
  switch (PredNo) {
  default: llvm_unreachable("Invalid predicate in table?");
  case 0: return (MF->getSubtarget().checkFeatures("-64bit"));
  case 1: return (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"));
  case 2: return (!Subtarget->is64Bit());
  case 3: return (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"));
  case 4: return (Subtarget->is64Bit());
  case 5: return (MF->getSubtarget().checkFeatures("+64bit"));
  case 6: return (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"));
  case 7: return (Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"));
  case 8: return (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("-64bit"));
  case 9: return (Subtarget->hasStdExtF());
  case 10: return (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("-64bit"));
  case 11: return (Subtarget->hasStdExtD());
  case 12: return (Subtarget->hasStdExtF()) && (MF->getSubtarget().checkFeatures("+64bit"));
  case 13: return (Subtarget->hasStdExtD()) && (MF->getSubtarget().checkFeatures("+64bit"));
  case 14: return (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("-64bit"));
  case 15: return (Subtarget->hasStdExtA());
  case 16: return (Subtarget->hasStdExtA()) && (MF->getSubtarget().checkFeatures("+64bit"));
  case 17: return (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("-64bit"));
  case 18: return (Subtarget->hasStdExtM());
  case 19: return (Subtarget->hasStdExtM()) && (MF->getSubtarget().checkFeatures("+64bit"));
  case 20: return (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"));
  case 21: return (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit());
  case 22: return (Subtarget->hasStdExtF()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"));
  case 23: return (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("-64bit"));
  case 24: return (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit());
  case 25: return (Subtarget->hasStdExtD()) && (!Subtarget->is64Bit()) && (MF->getSubtarget().checkFeatures("+64bit"));
  }
}
#endif // GET_DAGISEL_BODY

#ifdef GET_DAGISEL_DECL
bool CheckNodePredicate(SDNode *Node, unsigned PredNo) const override;
#endif
#if defined(GET_DAGISEL_BODY) || DAGISEL_INLINE
bool DAGISEL_CLASS_COLONCOLON CheckNodePredicate(SDNode *Node, unsigned PredNo) const
#if DAGISEL_INLINE
  override
#endif
{
  switch (PredNo) {
  default: llvm_unreachable("Invalid predicate in table?");
  case 0: { 
    // Predicate_simm12
    int64_t Imm = cast<ConstantSDNode>(Node)->getSExtValue();
return isInt<12>(Imm);
  }
  case 1: { 
    // Predicate_IsOrAdd
    SDNode *N = Node;
    (void)N;

  return isOrEquivalentToAdd(N);

  }
  case 2: { 
    // Predicate_unindexedload
    SDNode *N = Node;
    (void)N;
if (cast<LoadSDNode>(N)->getAddressingMode() != ISD::UNINDEXED) return false;
return true;

  }
  case 3: { 
    // Predicate_sextload
    SDNode *N = Node;
    (void)N;
if (cast<LoadSDNode>(N)->getExtensionType() != ISD::SEXTLOAD) return false;
return true;

  }
  case 4: { 
    // Predicate_sextloadi8
    // Predicate_extloadi8
    // Predicate_zextloadi8
    SDNode *N = Node;
    (void)N;
if (cast<LoadSDNode>(N)->getMemoryVT() != MVT::i8) return false;
return true;

  }
  case 5: { 
    // Predicate_extload
    SDNode *N = Node;
    (void)N;
if (cast<LoadSDNode>(N)->getExtensionType() != ISD::EXTLOAD) return false;
return true;

  }
  case 6: { 
    // Predicate_sextloadi16
    // Predicate_extloadi16
    // Predicate_zextloadi16
    SDNode *N = Node;
    (void)N;
if (cast<LoadSDNode>(N)->getMemoryVT() != MVT::i16) return false;
return true;

  }
  case 7: { 
    // Predicate_load
    SDNode *N = Node;
    (void)N;
if (cast<LoadSDNode>(N)->getExtensionType() != ISD::NON_EXTLOAD) return false;
return true;

  }
  case 8: { 
    // Predicate_zextload
    SDNode *N = Node;
    (void)N;
if (cast<LoadSDNode>(N)->getExtensionType() != ISD::ZEXTLOAD) return false;
return true;

  }
  case 9: { 
    // Predicate_sextloadi32
    // Predicate_extloadi32
    // Predicate_zextloadi32
    SDNode *N = Node;
    (void)N;
if (cast<LoadSDNode>(N)->getMemoryVT() != MVT::i32) return false;
return true;

  }
  case 10: { 
    // Predicate_unindexedstore
    SDNode *N = Node;
    (void)N;
if (cast<StoreSDNode>(N)->getAddressingMode() != ISD::UNINDEXED) return false;
return true;

  }
  case 11: { 
    // Predicate_truncstore
    SDNode *N = Node;
    (void)N;
 if (!cast<StoreSDNode>(N)->isTruncatingStore()) return false;
return true;

  }
  case 12: { 
    // Predicate_truncstorei8
    SDNode *N = Node;
    (void)N;
if (cast<StoreSDNode>(N)->getMemoryVT() != MVT::i8) return false;
return true;

  }
  case 13: { 
    // Predicate_truncstorei16
    SDNode *N = Node;
    (void)N;
if (cast<StoreSDNode>(N)->getMemoryVT() != MVT::i16) return false;
return true;

  }
  case 14: { 
    // Predicate_store
    SDNode *N = Node;
    (void)N;
 if (cast<StoreSDNode>(N)->isTruncatingStore()) return false;
return true;

  }
  case 15: { 
    // Predicate_truncstorei32
    SDNode *N = Node;
    (void)N;
if (cast<StoreSDNode>(N)->getMemoryVT() != MVT::i32) return false;
return true;

  }
  case 16: { 
    // Predicate_atomic_store_8
    // Predicate_atomic_load_8
    SDNode *N = Node;
    (void)N;
if (cast<AtomicSDNode>(N)->getMemoryVT() != MVT::i8) return false;
return true;

  }
  case 17: { 
    // Predicate_atomic_store_16
    // Predicate_atomic_load_16
    SDNode *N = Node;
    (void)N;
if (cast<AtomicSDNode>(N)->getMemoryVT() != MVT::i16) return false;
return true;

  }
  case 18: { 
    // Predicate_atomic_store_32
    // Predicate_atomic_load_32
    // Predicate_atomic_swap_32
    // Predicate_atomic_load_add_32
    // Predicate_atomic_load_and_32
    // Predicate_atomic_load_or_32
    // Predicate_atomic_load_xor_32
    // Predicate_atomic_load_max_32
    // Predicate_atomic_load_min_32
    // Predicate_atomic_load_umax_32
    // Predicate_atomic_load_umin_32
    // Predicate_atomic_load_nand_32
    // Predicate_atomic_cmp_swap_32
    // Predicate_atomic_load_sub_32
    SDNode *N = Node;
    (void)N;
if (cast<AtomicSDNode>(N)->getMemoryVT() != MVT::i32) return false;
return true;

  }
  case 19: { 
    // Predicate_immbottomxlenset
    int64_t Imm = cast<ConstantSDNode>(Node)->getSExtValue();

  if (Subtarget->is64Bit())
    return countTrailingOnes<uint64_t>(Imm) >= 6;
  return countTrailingOnes<uint64_t>(Imm) >= 5;

  }
  case 20: { 
    // Predicate_uimmlog2xlen
    int64_t Imm = cast<ConstantSDNode>(Node)->getSExtValue();

  if (Subtarget->is64Bit())
    return isUInt<6>(Imm);
  return isUInt<5>(Imm);

  }
  case 21: { 
    // Predicate_uimm5
    int64_t Imm = cast<ConstantSDNode>(Node)->getSExtValue();
return isUInt<5>(Imm);
  }
  case 22: { 
    // Predicate_simm32hi20
    int64_t Imm = cast<ConstantSDNode>(Node)->getSExtValue();
return isShiftedInt<20, 12>(Imm);
  }
  case 23: { 
    // Predicate_simm32
    int64_t Imm = cast<ConstantSDNode>(Node)->getSExtValue();
return isInt<32>(Imm);
  }
  case 24: { 
    // Predicate_atomic_swap_32_monotonic
    // Predicate_atomic_load_add_32_monotonic
    // Predicate_atomic_load_and_32_monotonic
    // Predicate_atomic_load_or_32_monotonic
    // Predicate_atomic_load_xor_32_monotonic
    // Predicate_atomic_load_max_32_monotonic
    // Predicate_atomic_load_min_32_monotonic
    // Predicate_atomic_load_umax_32_monotonic
    // Predicate_atomic_load_umin_32_monotonic
    // Predicate_atomic_load_nand_32_monotonic
    // Predicate_atomic_cmp_swap_32_monotonic
    // Predicate_atomic_load_sub_32_monotonic
    SDNode *N = Node;
    (void)N;
if (cast<AtomicSDNode>(N)->getOrdering() != AtomicOrdering::Monotonic) return false;
return true;

  }
  case 25: { 
    // Predicate_atomic_swap_32_acquire
    // Predicate_atomic_load_add_32_acquire
    // Predicate_atomic_load_and_32_acquire
    // Predicate_atomic_load_or_32_acquire
    // Predicate_atomic_load_xor_32_acquire
    // Predicate_atomic_load_max_32_acquire
    // Predicate_atomic_load_min_32_acquire
    // Predicate_atomic_load_umax_32_acquire
    // Predicate_atomic_load_umin_32_acquire
    // Predicate_atomic_load_nand_32_acquire
    // Predicate_atomic_cmp_swap_32_acquire
    // Predicate_atomic_load_sub_32_acquire
    SDNode *N = Node;
    (void)N;
if (cast<AtomicSDNode>(N)->getOrdering() != AtomicOrdering::Acquire) return false;
return true;

  }
  case 26: { 
    // Predicate_atomic_swap_32_release
    // Predicate_atomic_load_add_32_release
    // Predicate_atomic_load_and_32_release
    // Predicate_atomic_load_or_32_release
    // Predicate_atomic_load_xor_32_release
    // Predicate_atomic_load_max_32_release
    // Predicate_atomic_load_min_32_release
    // Predicate_atomic_load_umax_32_release
    // Predicate_atomic_load_umin_32_release
    // Predicate_atomic_load_nand_32_release
    // Predicate_atomic_cmp_swap_32_release
    // Predicate_atomic_load_sub_32_release
    SDNode *N = Node;
    (void)N;
if (cast<AtomicSDNode>(N)->getOrdering() != AtomicOrdering::Release) return false;
return true;

  }
  case 27: { 
    // Predicate_atomic_swap_32_acq_rel
    // Predicate_atomic_load_add_32_acq_rel
    // Predicate_atomic_load_and_32_acq_rel
    // Predicate_atomic_load_or_32_acq_rel
    // Predicate_atomic_load_xor_32_acq_rel
    // Predicate_atomic_load_max_32_acq_rel
    // Predicate_atomic_load_min_32_acq_rel
    // Predicate_atomic_load_umax_32_acq_rel
    // Predicate_atomic_load_umin_32_acq_rel
    // Predicate_atomic_load_nand_32_acq_rel
    // Predicate_atomic_cmp_swap_32_acq_rel
    // Predicate_atomic_load_sub_32_acq_rel
    SDNode *N = Node;
    (void)N;
if (cast<AtomicSDNode>(N)->getOrdering() != AtomicOrdering::AcquireRelease) return false;
return true;

  }
  case 28: { 
    // Predicate_atomic_swap_32_seq_cst
    // Predicate_atomic_load_add_32_seq_cst
    // Predicate_atomic_load_and_32_seq_cst
    // Predicate_atomic_load_or_32_seq_cst
    // Predicate_atomic_load_xor_32_seq_cst
    // Predicate_atomic_load_max_32_seq_cst
    // Predicate_atomic_load_min_32_seq_cst
    // Predicate_atomic_load_umax_32_seq_cst
    // Predicate_atomic_load_umin_32_seq_cst
    // Predicate_atomic_load_nand_32_seq_cst
    // Predicate_atomic_cmp_swap_32_seq_cst
    // Predicate_atomic_load_sub_32_seq_cst
    SDNode *N = Node;
    (void)N;
if (cast<AtomicSDNode>(N)->getOrdering() != AtomicOrdering::SequentiallyConsistent) return false;
return true;

  }
  }
}
#endif // GET_DAGISEL_BODY

#ifdef GET_DAGISEL_DECL
bool CheckComplexPattern(SDNode *Root, SDNode *Parent,
      SDValue N, unsigned PatternNo,
      SmallVectorImpl<std::pair<SDValue, SDNode*>> &Result) override;
#endif
#if defined(GET_DAGISEL_BODY) || DAGISEL_INLINE
bool DAGISEL_CLASS_COLONCOLON CheckComplexPattern(SDNode *Root, SDNode *Parent,
      SDValue N, unsigned PatternNo,
      SmallVectorImpl<std::pair<SDValue, SDNode*>> &Result)
#if DAGISEL_INLINE
  override
#endif
{
  unsigned NextRes = Result.size();
  switch (PatternNo) {
  default: llvm_unreachable("Invalid pattern # in table?");
  case 0:
    Result.resize(NextRes+1);
  return SelectAddrFI(N, Result[NextRes+0].first);
  }
}
#endif // GET_DAGISEL_BODY

#ifdef GET_DAGISEL_DECL
SDValue RunSDNodeXForm(SDValue V, unsigned XFormNo) override;
#endif
#if defined(GET_DAGISEL_BODY) || DAGISEL_INLINE
SDValue DAGISEL_CLASS_COLONCOLON RunSDNodeXForm(SDValue V, unsigned XFormNo)
#if DAGISEL_INLINE
  override
#endif
{
  switch (XFormNo) {
  default: llvm_unreachable("Invalid xform # in table?");
  case 0: {  // HI20
    ConstantSDNode *N = cast<ConstantSDNode>(V.getNode());

  return CurDAG->getTargetConstant(((N->getZExtValue()+0x800) >> 12) & 0xfffff,
                                   SDLoc(N), N->getValueType(0));

  }
  case 1: {  // LO12Sext
    ConstantSDNode *N = cast<ConstantSDNode>(V.getNode());

  return CurDAG->getTargetConstant(SignExtend64<12>(N->getZExtValue()),
                                   SDLoc(N), N->getValueType(0));

  }
  }
}
#endif // GET_DAGISEL_BODY


#ifdef DAGISEL_INLINE
#undef DAGISEL_INLINE
#endif
#ifdef DAGISEL_CLASS_COLONCOLON
#undef DAGISEL_CLASS_COLONCOLON
#endif
#ifdef GET_DAGISEL_DECL
#undef GET_DAGISEL_DECL
#endif
#ifdef GET_DAGISEL_BODY
#undef GET_DAGISEL_BODY
#endif
