// Copyright © 2026 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest.details;

import java.util.List;
import java.util.Map;
import static java.util.Map.entry;

import org.capstone_engine.cstest.Compare;

import capstone.Capstone;
import capstone.Riscv;
import static capstone.Riscv_const.*;

public class RiscvDetails {
    // Add functionality to the generator script to generate this from the SYSREG array
    public static final Map<String, Integer> SYSREG_NAME_TO_VAL = Map.ofEntries(
        entry("fflags", RISCV_SYSREG_FFLAGS), entry("frm", RISCV_SYSREG_FRM), entry("fcsr", RISCV_SYSREG_FCSR),
        entry("vstart", RISCV_SYSREG_VSTART), entry("vxsat", RISCV_SYSREG_VXSAT), entry("vxrm", RISCV_SYSREG_VXRM),
        entry("vcsr", RISCV_SYSREG_VCSR), entry("seed", RISCV_SYSREG_SEED), entry("jvt", RISCV_SYSREG_JVT),
        entry("sstatus", RISCV_SYSREG_SSTATUS), entry("sie", RISCV_SYSREG_SIE), entry("stvec", RISCV_SYSREG_STVEC),
        entry("scounteren", RISCV_SYSREG_SCOUNTEREN), entry("senvcfg", RISCV_SYSREG_SENVCFG), entry("sstateen0", RISCV_SYSREG_SSTATEEN0),
        entry("sstateen1", RISCV_SYSREG_SSTATEEN1), entry("sstateen2", RISCV_SYSREG_SSTATEEN2), entry("sstateen3", RISCV_SYSREG_SSTATEEN3),
        entry("sieh", RISCV_SYSREG_SIEH), entry("sscratch", RISCV_SYSREG_SSCRATCH), entry("sepc", RISCV_SYSREG_SEPC),
        entry("scause", RISCV_SYSREG_SCAUSE), entry("stval", RISCV_SYSREG_STVAL), entry("sip", RISCV_SYSREG_SIP),
        entry("stimecmp", RISCV_SYSREG_STIMECMP), entry("siselect", RISCV_SYSREG_SISELECT), entry("sireg", RISCV_SYSREG_SIREG),
        entry("siph", RISCV_SYSREG_SIPH), entry("stopei", RISCV_SYSREG_STOPEI), entry("stimecmph", RISCV_SYSREG_STIMECMPH),
        entry("satp", RISCV_SYSREG_SATP), entry("vsstatus", RISCV_SYSREG_VSSTATUS), entry("vsie", RISCV_SYSREG_VSIE),
        entry("vstvec", RISCV_SYSREG_VSTVEC), entry("vsieh", RISCV_SYSREG_VSIEH), entry("vsscratch", RISCV_SYSREG_VSSCRATCH),
        entry("vsepc", RISCV_SYSREG_VSEPC), entry("vscause", RISCV_SYSREG_VSCAUSE), entry("vstval", RISCV_SYSREG_VSTVAL),
        entry("vsip", RISCV_SYSREG_VSIP), entry("vstimecmp", RISCV_SYSREG_VSTIMECMP), entry("vsiselect", RISCV_SYSREG_VSISELECT),
        entry("vsireg", RISCV_SYSREG_VSIREG), entry("vsiph", RISCV_SYSREG_VSIPH), entry("vstopei", RISCV_SYSREG_VSTOPEI),
        entry("vstimecmph", RISCV_SYSREG_VSTIMECMPH), entry("vsatp", RISCV_SYSREG_VSATP), entry("mstatus", RISCV_SYSREG_MSTATUS),
        entry("misa", RISCV_SYSREG_MISA), entry("medeleg", RISCV_SYSREG_MEDELEG), entry("mideleg", RISCV_SYSREG_MIDELEG),
        entry("mie", RISCV_SYSREG_MIE), entry("mtvec", RISCV_SYSREG_MTVEC), entry("mcounteren", RISCV_SYSREG_MCOUNTEREN),
        entry("mvien", RISCV_SYSREG_MVIEN), entry("mvip", RISCV_SYSREG_MVIP), entry("menvcfg", RISCV_SYSREG_MENVCFG),
        entry("mstateen0", RISCV_SYSREG_MSTATEEN0), entry("mstateen1", RISCV_SYSREG_MSTATEEN1), entry("mstateen2", RISCV_SYSREG_MSTATEEN2),
        entry("mstateen3", RISCV_SYSREG_MSTATEEN3), entry("mstatush", RISCV_SYSREG_MSTATUSH), entry("midelegh", RISCV_SYSREG_MIDELEGH),
        entry("mieh", RISCV_SYSREG_MIEH), entry("mvienh", RISCV_SYSREG_MVIENH), entry("mviph", RISCV_SYSREG_MVIPH),
        entry("menvcfgh", RISCV_SYSREG_MENVCFGH), entry("mstateen0h", RISCV_SYSREG_MSTATEEN0H), entry("mstateen1h", RISCV_SYSREG_MSTATEEN1H),
        entry("mstateen2h", RISCV_SYSREG_MSTATEEN2H), entry("mstateen3h", RISCV_SYSREG_MSTATEEN3H), entry("mcountinhibit", RISCV_SYSREG_MCOUNTINHIBIT),
        entry("mhpmevent3", RISCV_SYSREG_MHPMEVENT3), entry("mhpmevent4", RISCV_SYSREG_MHPMEVENT4), entry("mhpmevent5", RISCV_SYSREG_MHPMEVENT5),
        entry("mhpmevent6", RISCV_SYSREG_MHPMEVENT6), entry("mhpmevent7", RISCV_SYSREG_MHPMEVENT7), entry("mhpmevent8", RISCV_SYSREG_MHPMEVENT8),
        entry("mhpmevent9", RISCV_SYSREG_MHPMEVENT9), entry("mhpmevent10", RISCV_SYSREG_MHPMEVENT10), entry("mhpmevent11", RISCV_SYSREG_MHPMEVENT11),
        entry("mhpmevent12", RISCV_SYSREG_MHPMEVENT12), entry("mhpmevent13", RISCV_SYSREG_MHPMEVENT13), entry("mhpmevent14", RISCV_SYSREG_MHPMEVENT14),
        entry("mhpmevent15", RISCV_SYSREG_MHPMEVENT15), entry("mhpmevent16", RISCV_SYSREG_MHPMEVENT16), entry("mhpmevent17", RISCV_SYSREG_MHPMEVENT17),
        entry("mhpmevent18", RISCV_SYSREG_MHPMEVENT18), entry("mhpmevent19", RISCV_SYSREG_MHPMEVENT19), entry("mhpmevent20", RISCV_SYSREG_MHPMEVENT20),
        entry("mhpmevent21", RISCV_SYSREG_MHPMEVENT21), entry("mhpmevent22", RISCV_SYSREG_MHPMEVENT22), entry("mhpmevent23", RISCV_SYSREG_MHPMEVENT23),
        entry("mhpmevent24", RISCV_SYSREG_MHPMEVENT24), entry("mhpmevent25", RISCV_SYSREG_MHPMEVENT25), entry("mhpmevent26", RISCV_SYSREG_MHPMEVENT26),
        entry("mhpmevent27", RISCV_SYSREG_MHPMEVENT27), entry("mhpmevent28", RISCV_SYSREG_MHPMEVENT28), entry("mhpmevent29", RISCV_SYSREG_MHPMEVENT29),
        entry("mhpmevent30", RISCV_SYSREG_MHPMEVENT30), entry("mhpmevent31", RISCV_SYSREG_MHPMEVENT31), entry("mscratch", RISCV_SYSREG_MSCRATCH),
        entry("mepc", RISCV_SYSREG_MEPC), entry("mcause", RISCV_SYSREG_MCAUSE), entry("mtval", RISCV_SYSREG_MTVAL),
        entry("mip", RISCV_SYSREG_MIP), entry("mtinst", RISCV_SYSREG_MTINST), entry("mtval2", RISCV_SYSREG_MTVAL2),
        entry("miselect", RISCV_SYSREG_MISELECT), entry("mireg", RISCV_SYSREG_MIREG), entry("miph", RISCV_SYSREG_MIPH),
        entry("mtopei", RISCV_SYSREG_MTOPEI), entry("pmpcfg0", RISCV_SYSREG_PMPCFG0), entry("pmpcfg1", RISCV_SYSREG_PMPCFG1),
        entry("pmpcfg2", RISCV_SYSREG_PMPCFG2), entry("pmpcfg3", RISCV_SYSREG_PMPCFG3), entry("pmpcfg4", RISCV_SYSREG_PMPCFG4),
        entry("pmpcfg5", RISCV_SYSREG_PMPCFG5), entry("pmpcfg6", RISCV_SYSREG_PMPCFG6), entry("pmpcfg7", RISCV_SYSREG_PMPCFG7),
        entry("pmpcfg8", RISCV_SYSREG_PMPCFG8), entry("pmpcfg9", RISCV_SYSREG_PMPCFG9), entry("pmpcfg10", RISCV_SYSREG_PMPCFG10),
        entry("pmpcfg11", RISCV_SYSREG_PMPCFG11), entry("pmpcfg12", RISCV_SYSREG_PMPCFG12), entry("pmpcfg13", RISCV_SYSREG_PMPCFG13),
        entry("pmpcfg14", RISCV_SYSREG_PMPCFG14), entry("pmpcfg15", RISCV_SYSREG_PMPCFG15), entry("pmpaddr0", RISCV_SYSREG_PMPADDR0),
        entry("pmpaddr1", RISCV_SYSREG_PMPADDR1), entry("pmpaddr2", RISCV_SYSREG_PMPADDR2), entry("pmpaddr3", RISCV_SYSREG_PMPADDR3),
        entry("pmpaddr4", RISCV_SYSREG_PMPADDR4), entry("pmpaddr5", RISCV_SYSREG_PMPADDR5), entry("pmpaddr6", RISCV_SYSREG_PMPADDR6),
        entry("pmpaddr7", RISCV_SYSREG_PMPADDR7), entry("pmpaddr8", RISCV_SYSREG_PMPADDR8), entry("pmpaddr9", RISCV_SYSREG_PMPADDR9),
        entry("pmpaddr10", RISCV_SYSREG_PMPADDR10), entry("pmpaddr11", RISCV_SYSREG_PMPADDR11), entry("pmpaddr12", RISCV_SYSREG_PMPADDR12),
        entry("pmpaddr13", RISCV_SYSREG_PMPADDR13), entry("pmpaddr14", RISCV_SYSREG_PMPADDR14), entry("pmpaddr15", RISCV_SYSREG_PMPADDR15),
        entry("pmpaddr16", RISCV_SYSREG_PMPADDR16), entry("pmpaddr17", RISCV_SYSREG_PMPADDR17), entry("pmpaddr18", RISCV_SYSREG_PMPADDR18),
        entry("pmpaddr19", RISCV_SYSREG_PMPADDR19), entry("pmpaddr20", RISCV_SYSREG_PMPADDR20), entry("pmpaddr21", RISCV_SYSREG_PMPADDR21),
        entry("pmpaddr22", RISCV_SYSREG_PMPADDR22), entry("pmpaddr23", RISCV_SYSREG_PMPADDR23), entry("pmpaddr24", RISCV_SYSREG_PMPADDR24),
        entry("pmpaddr25", RISCV_SYSREG_PMPADDR25), entry("pmpaddr26", RISCV_SYSREG_PMPADDR26), entry("pmpaddr27", RISCV_SYSREG_PMPADDR27),
        entry("pmpaddr28", RISCV_SYSREG_PMPADDR28), entry("pmpaddr29", RISCV_SYSREG_PMPADDR29), entry("pmpaddr30", RISCV_SYSREG_PMPADDR30),
        entry("pmpaddr31", RISCV_SYSREG_PMPADDR31), entry("pmpaddr32", RISCV_SYSREG_PMPADDR32), entry("pmpaddr33", RISCV_SYSREG_PMPADDR33),
        entry("pmpaddr34", RISCV_SYSREG_PMPADDR34), entry("pmpaddr35", RISCV_SYSREG_PMPADDR35), entry("pmpaddr36", RISCV_SYSREG_PMPADDR36),
        entry("pmpaddr37", RISCV_SYSREG_PMPADDR37), entry("pmpaddr38", RISCV_SYSREG_PMPADDR38), entry("pmpaddr39", RISCV_SYSREG_PMPADDR39),
        entry("pmpaddr40", RISCV_SYSREG_PMPADDR40), entry("pmpaddr41", RISCV_SYSREG_PMPADDR41), entry("pmpaddr42", RISCV_SYSREG_PMPADDR42),
        entry("pmpaddr43", RISCV_SYSREG_PMPADDR43), entry("pmpaddr44", RISCV_SYSREG_PMPADDR44), entry("pmpaddr45", RISCV_SYSREG_PMPADDR45),
        entry("pmpaddr46", RISCV_SYSREG_PMPADDR46), entry("pmpaddr47", RISCV_SYSREG_PMPADDR47), entry("pmpaddr48", RISCV_SYSREG_PMPADDR48),
        entry("pmpaddr49", RISCV_SYSREG_PMPADDR49), entry("pmpaddr50", RISCV_SYSREG_PMPADDR50), entry("pmpaddr51", RISCV_SYSREG_PMPADDR51),
        entry("pmpaddr52", RISCV_SYSREG_PMPADDR52), entry("pmpaddr53", RISCV_SYSREG_PMPADDR53), entry("pmpaddr54", RISCV_SYSREG_PMPADDR54),
        entry("pmpaddr55", RISCV_SYSREG_PMPADDR55), entry("pmpaddr56", RISCV_SYSREG_PMPADDR56), entry("pmpaddr57", RISCV_SYSREG_PMPADDR57),
        entry("pmpaddr58", RISCV_SYSREG_PMPADDR58), entry("pmpaddr59", RISCV_SYSREG_PMPADDR59), entry("pmpaddr60", RISCV_SYSREG_PMPADDR60),
        entry("pmpaddr61", RISCV_SYSREG_PMPADDR61), entry("pmpaddr62", RISCV_SYSREG_PMPADDR62), entry("pmpaddr63", RISCV_SYSREG_PMPADDR63),
        entry("scontext", RISCV_SYSREG_SCONTEXT), entry("hstatus", RISCV_SYSREG_HSTATUS), entry("hedeleg", RISCV_SYSREG_HEDELEG),
        entry("hideleg", RISCV_SYSREG_HIDELEG), entry("hie", RISCV_SYSREG_HIE), entry("htimedelta", RISCV_SYSREG_HTIMEDELTA),
        entry("hcounteren", RISCV_SYSREG_HCOUNTEREN), entry("hgeie", RISCV_SYSREG_HGEIE), entry("hvien", RISCV_SYSREG_HVIEN),
        entry("hvictl", RISCV_SYSREG_HVICTL), entry("henvcfg", RISCV_SYSREG_HENVCFG), entry("hstateen0", RISCV_SYSREG_HSTATEEN0),
        entry("hstateen1", RISCV_SYSREG_HSTATEEN1), entry("hstateen2", RISCV_SYSREG_HSTATEEN2), entry("hstateen3", RISCV_SYSREG_HSTATEEN3),
        entry("hidelegh", RISCV_SYSREG_HIDELEGH), entry("htimedeltah", RISCV_SYSREG_HTIMEDELTAH), entry("hvienh", RISCV_SYSREG_HVIENH),
        entry("henvcfgh", RISCV_SYSREG_HENVCFGH), entry("hstateen0h", RISCV_SYSREG_HSTATEEN0H), entry("hstateen1h", RISCV_SYSREG_HSTATEEN1H),
        entry("hstateen2h", RISCV_SYSREG_HSTATEEN2H), entry("hstateen3h", RISCV_SYSREG_HSTATEEN3H), entry("htval", RISCV_SYSREG_HTVAL),
        entry("hip", RISCV_SYSREG_HIP), entry("hvip", RISCV_SYSREG_HVIP), entry("hviprio1", RISCV_SYSREG_HVIPRIO1),
        entry("hviprio2", RISCV_SYSREG_HVIPRIO2), entry("htinst", RISCV_SYSREG_HTINST), entry("hviph", RISCV_SYSREG_HVIPH),
        entry("hviprio1h", RISCV_SYSREG_HVIPRIO1H), entry("hviprio2h", RISCV_SYSREG_HVIPRIO2H), entry("hgatp", RISCV_SYSREG_HGATP),
        entry("hcontext", RISCV_SYSREG_HCONTEXT), entry("mhpmevent3h", RISCV_SYSREG_MHPMEVENT3H), entry("mhpmevent4h", RISCV_SYSREG_MHPMEVENT4H),
        entry("mhpmevent5h", RISCV_SYSREG_MHPMEVENT5H), entry("mhpmevent6h", RISCV_SYSREG_MHPMEVENT6H), entry("mhpmevent7h", RISCV_SYSREG_MHPMEVENT7H),
        entry("mhpmevent8h", RISCV_SYSREG_MHPMEVENT8H), entry("mhpmevent9h", RISCV_SYSREG_MHPMEVENT9H), entry("mhpmevent10h", RISCV_SYSREG_MHPMEVENT10H),
        entry("mhpmevent11h", RISCV_SYSREG_MHPMEVENT11H), entry("mhpmevent12h", RISCV_SYSREG_MHPMEVENT12H), entry("mhpmevent13h", RISCV_SYSREG_MHPMEVENT13H),
        entry("mhpmevent14h", RISCV_SYSREG_MHPMEVENT14H), entry("mhpmevent15h", RISCV_SYSREG_MHPMEVENT15H), entry("mhpmevent16h", RISCV_SYSREG_MHPMEVENT16H),
        entry("mhpmevent17h", RISCV_SYSREG_MHPMEVENT17H), entry("mhpmevent18h", RISCV_SYSREG_MHPMEVENT18H), entry("mhpmevent19h", RISCV_SYSREG_MHPMEVENT19H),
        entry("mhpmevent20h", RISCV_SYSREG_MHPMEVENT20H), entry("mhpmevent21h", RISCV_SYSREG_MHPMEVENT21H), entry("mhpmevent22h", RISCV_SYSREG_MHPMEVENT22H),
        entry("mhpmevent23h", RISCV_SYSREG_MHPMEVENT23H), entry("mhpmevent24h", RISCV_SYSREG_MHPMEVENT24H), entry("mhpmevent25h", RISCV_SYSREG_MHPMEVENT25H),
        entry("mhpmevent26h", RISCV_SYSREG_MHPMEVENT26H), entry("mhpmevent27h", RISCV_SYSREG_MHPMEVENT27H), entry("mhpmevent28h", RISCV_SYSREG_MHPMEVENT28H),
        entry("mhpmevent29h", RISCV_SYSREG_MHPMEVENT29H), entry("mhpmevent30h", RISCV_SYSREG_MHPMEVENT30H), entry("mhpmevent31h", RISCV_SYSREG_MHPMEVENT31H),
        entry("mseccfg", RISCV_SYSREG_MSECCFG), entry("mseccfgh", RISCV_SYSREG_MSECCFGH), entry("tselect", RISCV_SYSREG_TSELECT),
        entry("tdata1", RISCV_SYSREG_TDATA1), entry("tdata2", RISCV_SYSREG_TDATA2), entry("tdata3", RISCV_SYSREG_TDATA3),
        entry("mcontext", RISCV_SYSREG_MCONTEXT), entry("dcsr", RISCV_SYSREG_DCSR), entry("dpc", RISCV_SYSREG_DPC),
        entry("dscratch0", RISCV_SYSREG_DSCRATCH0), entry("dscratch1", RISCV_SYSREG_DSCRATCH1), entry("mcycle", RISCV_SYSREG_MCYCLE),
        entry("minstret", RISCV_SYSREG_MINSTRET), entry("mhpmcounter3", RISCV_SYSREG_MHPMCOUNTER3), entry("mhpmcounter4", RISCV_SYSREG_MHPMCOUNTER4),
        entry("mhpmcounter5", RISCV_SYSREG_MHPMCOUNTER5), entry("mhpmcounter6", RISCV_SYSREG_MHPMCOUNTER6), entry("mhpmcounter7", RISCV_SYSREG_MHPMCOUNTER7),
        entry("mhpmcounter8", RISCV_SYSREG_MHPMCOUNTER8), entry("mhpmcounter9", RISCV_SYSREG_MHPMCOUNTER9), entry("mhpmcounter10", RISCV_SYSREG_MHPMCOUNTER10),
        entry("mhpmcounter11", RISCV_SYSREG_MHPMCOUNTER11), entry("mhpmcounter12", RISCV_SYSREG_MHPMCOUNTER12), entry("mhpmcounter13", RISCV_SYSREG_MHPMCOUNTER13),
        entry("mhpmcounter14", RISCV_SYSREG_MHPMCOUNTER14), entry("mhpmcounter15", RISCV_SYSREG_MHPMCOUNTER15), entry("mhpmcounter16", RISCV_SYSREG_MHPMCOUNTER16),
        entry("mhpmcounter17", RISCV_SYSREG_MHPMCOUNTER17), entry("mhpmcounter18", RISCV_SYSREG_MHPMCOUNTER18), entry("mhpmcounter19", RISCV_SYSREG_MHPMCOUNTER19),
        entry("mhpmcounter20", RISCV_SYSREG_MHPMCOUNTER20), entry("mhpmcounter21", RISCV_SYSREG_MHPMCOUNTER21), entry("mhpmcounter22", RISCV_SYSREG_MHPMCOUNTER22),
        entry("mhpmcounter23", RISCV_SYSREG_MHPMCOUNTER23), entry("mhpmcounter24", RISCV_SYSREG_MHPMCOUNTER24), entry("mhpmcounter25", RISCV_SYSREG_MHPMCOUNTER25),
        entry("mhpmcounter26", RISCV_SYSREG_MHPMCOUNTER26), entry("mhpmcounter27", RISCV_SYSREG_MHPMCOUNTER27), entry("mhpmcounter28", RISCV_SYSREG_MHPMCOUNTER28),
        entry("mhpmcounter29", RISCV_SYSREG_MHPMCOUNTER29), entry("mhpmcounter30", RISCV_SYSREG_MHPMCOUNTER30), entry("mhpmcounter31", RISCV_SYSREG_MHPMCOUNTER31),
        entry("mcycleh", RISCV_SYSREG_MCYCLEH), entry("minstreth", RISCV_SYSREG_MINSTRETH), entry("mhpmcounter3h", RISCV_SYSREG_MHPMCOUNTER3H),
        entry("mhpmcounter4h", RISCV_SYSREG_MHPMCOUNTER4H), entry("mhpmcounter5h", RISCV_SYSREG_MHPMCOUNTER5H), entry("mhpmcounter6h", RISCV_SYSREG_MHPMCOUNTER6H),
        entry("mhpmcounter7h", RISCV_SYSREG_MHPMCOUNTER7H), entry("mhpmcounter8h", RISCV_SYSREG_MHPMCOUNTER8H), entry("mhpmcounter9h", RISCV_SYSREG_MHPMCOUNTER9H),
        entry("mhpmcounter10h", RISCV_SYSREG_MHPMCOUNTER10H), entry("mhpmcounter11h", RISCV_SYSREG_MHPMCOUNTER11H), entry("mhpmcounter12h", RISCV_SYSREG_MHPMCOUNTER12H),
        entry("mhpmcounter13h", RISCV_SYSREG_MHPMCOUNTER13H), entry("mhpmcounter14h", RISCV_SYSREG_MHPMCOUNTER14H), entry("mhpmcounter15h", RISCV_SYSREG_MHPMCOUNTER15H),
        entry("mhpmcounter16h", RISCV_SYSREG_MHPMCOUNTER16H), entry("mhpmcounter17h", RISCV_SYSREG_MHPMCOUNTER17H), entry("mhpmcounter18h", RISCV_SYSREG_MHPMCOUNTER18H),
        entry("mhpmcounter19h", RISCV_SYSREG_MHPMCOUNTER19H), entry("mhpmcounter20h", RISCV_SYSREG_MHPMCOUNTER20H), entry("mhpmcounter21h", RISCV_SYSREG_MHPMCOUNTER21H),
        entry("mhpmcounter22h", RISCV_SYSREG_MHPMCOUNTER22H), entry("mhpmcounter23h", RISCV_SYSREG_MHPMCOUNTER23H), entry("mhpmcounter24h", RISCV_SYSREG_MHPMCOUNTER24H),
        entry("mhpmcounter25h", RISCV_SYSREG_MHPMCOUNTER25H), entry("mhpmcounter26h", RISCV_SYSREG_MHPMCOUNTER26H), entry("mhpmcounter27h", RISCV_SYSREG_MHPMCOUNTER27H),
        entry("mhpmcounter28h", RISCV_SYSREG_MHPMCOUNTER28H), entry("mhpmcounter29h", RISCV_SYSREG_MHPMCOUNTER29H), entry("mhpmcounter30h", RISCV_SYSREG_MHPMCOUNTER30H),
        entry("mhpmcounter31h", RISCV_SYSREG_MHPMCOUNTER31H), entry("cycle", RISCV_SYSREG_CYCLE), entry("time", RISCV_SYSREG_TIME),
        entry("instret", RISCV_SYSREG_INSTRET), entry("hpmcounter3", RISCV_SYSREG_HPMCOUNTER3), entry("hpmcounter4", RISCV_SYSREG_HPMCOUNTER4),
        entry("hpmcounter5", RISCV_SYSREG_HPMCOUNTER5), entry("hpmcounter6", RISCV_SYSREG_HPMCOUNTER6), entry("hpmcounter7", RISCV_SYSREG_HPMCOUNTER7),
        entry("hpmcounter8", RISCV_SYSREG_HPMCOUNTER8), entry("hpmcounter9", RISCV_SYSREG_HPMCOUNTER9), entry("hpmcounter10", RISCV_SYSREG_HPMCOUNTER10),
        entry("hpmcounter11", RISCV_SYSREG_HPMCOUNTER11), entry("hpmcounter12", RISCV_SYSREG_HPMCOUNTER12), entry("hpmcounter13", RISCV_SYSREG_HPMCOUNTER13),
        entry("hpmcounter14", RISCV_SYSREG_HPMCOUNTER14), entry("hpmcounter15", RISCV_SYSREG_HPMCOUNTER15), entry("hpmcounter16", RISCV_SYSREG_HPMCOUNTER16),
        entry("hpmcounter17", RISCV_SYSREG_HPMCOUNTER17), entry("hpmcounter18", RISCV_SYSREG_HPMCOUNTER18), entry("hpmcounter19", RISCV_SYSREG_HPMCOUNTER19),
        entry("hpmcounter20", RISCV_SYSREG_HPMCOUNTER20), entry("hpmcounter21", RISCV_SYSREG_HPMCOUNTER21), entry("hpmcounter22", RISCV_SYSREG_HPMCOUNTER22),
        entry("hpmcounter23", RISCV_SYSREG_HPMCOUNTER23), entry("hpmcounter24", RISCV_SYSREG_HPMCOUNTER24), entry("hpmcounter25", RISCV_SYSREG_HPMCOUNTER25),
        entry("hpmcounter26", RISCV_SYSREG_HPMCOUNTER26), entry("hpmcounter27", RISCV_SYSREG_HPMCOUNTER27), entry("hpmcounter28", RISCV_SYSREG_HPMCOUNTER28),
        entry("hpmcounter29", RISCV_SYSREG_HPMCOUNTER29), entry("hpmcounter30", RISCV_SYSREG_HPMCOUNTER30), entry("hpmcounter31", RISCV_SYSREG_HPMCOUNTER31),
        entry("vl", RISCV_SYSREG_VL), entry("vtype", RISCV_SYSREG_VTYPE), entry("vlenb", RISCV_SYSREG_VLENB),
        entry("cycleh", RISCV_SYSREG_CYCLEH), entry("timeh", RISCV_SYSREG_TIMEH), entry("instreth", RISCV_SYSREG_INSTRETH),
        entry("hpmcounter3h", RISCV_SYSREG_HPMCOUNTER3H), entry("hpmcounter4h", RISCV_SYSREG_HPMCOUNTER4H), entry("hpmcounter5h", RISCV_SYSREG_HPMCOUNTER5H),
        entry("hpmcounter6h", RISCV_SYSREG_HPMCOUNTER6H), entry("hpmcounter7h", RISCV_SYSREG_HPMCOUNTER7H), entry("hpmcounter8h", RISCV_SYSREG_HPMCOUNTER8H),
        entry("hpmcounter9h", RISCV_SYSREG_HPMCOUNTER9H), entry("hpmcounter10h", RISCV_SYSREG_HPMCOUNTER10H), entry("hpmcounter11h", RISCV_SYSREG_HPMCOUNTER11H),
        entry("hpmcounter12h", RISCV_SYSREG_HPMCOUNTER12H), entry("hpmcounter13h", RISCV_SYSREG_HPMCOUNTER13H), entry("hpmcounter14h", RISCV_SYSREG_HPMCOUNTER14H),
        entry("hpmcounter15h", RISCV_SYSREG_HPMCOUNTER15H), entry("hpmcounter16h", RISCV_SYSREG_HPMCOUNTER16H), entry("hpmcounter17h", RISCV_SYSREG_HPMCOUNTER17H),
        entry("hpmcounter18h", RISCV_SYSREG_HPMCOUNTER18H), entry("hpmcounter19h", RISCV_SYSREG_HPMCOUNTER19H), entry("hpmcounter20h", RISCV_SYSREG_HPMCOUNTER20H),
        entry("hpmcounter21h", RISCV_SYSREG_HPMCOUNTER21H), entry("hpmcounter22h", RISCV_SYSREG_HPMCOUNTER22H), entry("hpmcounter23h", RISCV_SYSREG_HPMCOUNTER23H),
        entry("hpmcounter24h", RISCV_SYSREG_HPMCOUNTER24H), entry("hpmcounter25h", RISCV_SYSREG_HPMCOUNTER25H), entry("hpmcounter26h", RISCV_SYSREG_HPMCOUNTER26H),
        entry("hpmcounter27h", RISCV_SYSREG_HPMCOUNTER27H), entry("hpmcounter28h", RISCV_SYSREG_HPMCOUNTER28H), entry("hpmcounter29h", RISCV_SYSREG_HPMCOUNTER29H),
        entry("hpmcounter30h", RISCV_SYSREG_HPMCOUNTER30H), entry("hpmcounter31h", RISCV_SYSREG_HPMCOUNTER31H), entry("scountovf", RISCV_SYSREG_SCOUNTOVF),
        entry("stopi", RISCV_SYSREG_STOPI), entry("hgeip", RISCV_SYSREG_HGEIP), entry("vstopi", RISCV_SYSREG_VSTOPI),
        entry("mvendorid", RISCV_SYSREG_MVENDORID), entry("marchid", RISCV_SYSREG_MARCHID), entry("mimpid", RISCV_SYSREG_MIMPID),
        entry("mhartid", RISCV_SYSREG_MHARTID), entry("mconfigptr", RISCV_SYSREG_MCONFIGPTR), entry("mtopi", RISCV_SYSREG_MTOPI)
        
    );

    public static boolean testExpected(Capstone.CsInsn actual, Map<String, Object> expected) {
        Riscv.OpInfo riscv = (Riscv.OpInfo) actual.operands;
        if (expected.get("operands") == null) {
            return true;
        }
        
        List<Map<String, Object>> expectedOperands = (List<Map<String, Object>>) expected.get("operands");
        if (!Compare.compareUInt32(riscv.op.length, expectedOperands.size(), "operands_count")) {
            return false;
        }
        for (int i = 0; i < riscv.op.length; i++) {
            Riscv.Operand aop = riscv.op[i];
            Map<String, Object> eop = expectedOperands.get(i);

            if (!Compare.compareEnum(aop.type, (String) eop.get("type"), "type")) {
                return false;
            }
            if (!Compare.compareEnum(aop.access, (String) eop.get("access"), "access")) {
                return false;
            }

            switch (aop.type) {
                case RISCV_OP_REG:
                    if (!Compare.compareReg(actual, aop.value.reg, (String) eop.get("reg"), "reg")) {
                        return false;
                    }
                    break;
                case RISCV_OP_IMM:
                    if (!Compare.compareUInt64(aop.value.imm, Details.getLongFromMap(eop, "imm"), "imm")) {
                        return false;
                    }
                    break;
                case RISCV_OP_MEM:
                    if (!Compare.compareReg(actual, aop.value.mem.base, (String) eop.get("mem_base"), "mem_base")) {
                        return false;
                    }
                    if (!Compare.compareInt64(aop.value.mem.disp, Details.getLongFromMap(eop, "mem_disp"), "mem_disp")) {
                        return false;
                    }
                    break;
                case RISCV_OP_FP:
                    if (!Compare.compareDp(aop.value.dimm, Details.getDoubleFromMap(eop, "dimm"), "dimm")) {
                        return false;
                    }
                    break;
                case RISCV_OP_CSR:
                    if (!Compare.compareUInt16(aop.value.csr, SYSREG_NAME_TO_VAL.get((String) eop.get("csr")), "csr")) {
                        return false;
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Riscv operand type not handled");
            }
        }
        return true;
    }
}
