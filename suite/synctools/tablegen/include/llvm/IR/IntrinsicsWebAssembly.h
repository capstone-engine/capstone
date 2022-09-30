/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Intrinsic Function Source Fragment                                         *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifndef LLVM_IR_INTRINSIC_WASM_ENUMS_H
#define LLVM_IR_INTRINSIC_WASM_ENUMS_H

namespace llvm {
namespace Intrinsic {
enum WASMIntrinsics : unsigned {
// Enum values for intrinsics
    wasm_alltrue = 9286,                              // llvm.wasm.alltrue
    wasm_anytrue,                              // llvm.wasm.anytrue
    wasm_avgr_unsigned,                        // llvm.wasm.avgr.unsigned
    wasm_bitmask,                              // llvm.wasm.bitmask
    wasm_bitselect,                            // llvm.wasm.bitselect
    wasm_catch,                                // llvm.wasm.catch
    wasm_dot,                                  // llvm.wasm.dot
    wasm_extadd_pairwise_signed,               // llvm.wasm.extadd.pairwise.signed
    wasm_extadd_pairwise_unsigned,             // llvm.wasm.extadd.pairwise.unsigned
    wasm_fma,                                  // llvm.wasm.fma
    wasm_fms,                                  // llvm.wasm.fms
    wasm_get_ehselector,                       // llvm.wasm.get.ehselector
    wasm_get_exception,                        // llvm.wasm.get.exception
    wasm_landingpad_index,                     // llvm.wasm.landingpad.index
    wasm_laneselect,                           // llvm.wasm.laneselect
    wasm_lsda,                                 // llvm.wasm.lsda
    wasm_memory_atomic_notify,                 // llvm.wasm.memory.atomic.notify
    wasm_memory_atomic_wait32,                 // llvm.wasm.memory.atomic.wait32
    wasm_memory_atomic_wait64,                 // llvm.wasm.memory.atomic.wait64
    wasm_memory_grow,                          // llvm.wasm.memory.grow
    wasm_memory_size,                          // llvm.wasm.memory.size
    wasm_narrow_signed,                        // llvm.wasm.narrow.signed
    wasm_narrow_unsigned,                      // llvm.wasm.narrow.unsigned
    wasm_pmax,                                 // llvm.wasm.pmax
    wasm_pmin,                                 // llvm.wasm.pmin
    wasm_q15mulr_sat_signed,                   // llvm.wasm.q15mulr.sat.signed
    wasm_ref_null_extern,                      // llvm.wasm.ref.null.extern
    wasm_ref_null_func,                        // llvm.wasm.ref.null.func
    wasm_relaxed_max,                          // llvm.wasm.relaxed.max
    wasm_relaxed_min,                          // llvm.wasm.relaxed.min
    wasm_relaxed_swizzle,                      // llvm.wasm.relaxed.swizzle
    wasm_relaxed_trunc_signed,                 // llvm.wasm.relaxed.trunc.signed
    wasm_relaxed_trunc_unsigned,               // llvm.wasm.relaxed.trunc.unsigned
    wasm_relaxed_trunc_zero_signed,            // llvm.wasm.relaxed.trunc.zero.signed
    wasm_relaxed_trunc_zero_unsigned,          // llvm.wasm.relaxed.trunc.zero.unsigned
    wasm_rethrow,                              // llvm.wasm.rethrow
    wasm_shuffle,                              // llvm.wasm.shuffle
    wasm_sub_sat_signed,                       // llvm.wasm.sub.sat.signed
    wasm_sub_sat_unsigned,                     // llvm.wasm.sub.sat.unsigned
    wasm_swizzle,                              // llvm.wasm.swizzle
    wasm_table_copy,                           // llvm.wasm.table.copy
    wasm_table_fill_externref,                 // llvm.wasm.table.fill.externref
    wasm_table_fill_funcref,                   // llvm.wasm.table.fill.funcref
    wasm_table_grow_externref,                 // llvm.wasm.table.grow.externref
    wasm_table_grow_funcref,                   // llvm.wasm.table.grow.funcref
    wasm_table_size,                           // llvm.wasm.table.size
    wasm_throw,                                // llvm.wasm.throw
    wasm_tls_align,                            // llvm.wasm.tls.align
    wasm_tls_base,                             // llvm.wasm.tls.base
    wasm_tls_size,                             // llvm.wasm.tls.size
    wasm_trunc_saturate_signed,                // llvm.wasm.trunc.saturate.signed
    wasm_trunc_saturate_unsigned,              // llvm.wasm.trunc.saturate.unsigned
    wasm_trunc_signed,                         // llvm.wasm.trunc.signed
    wasm_trunc_unsigned,                       // llvm.wasm.trunc.unsigned
}; // enum
} // namespace Intrinsic
} // namespace llvm

#endif
