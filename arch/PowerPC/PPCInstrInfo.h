/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Rot127 <unisono@quyllur.org> 2022-2023 */

#ifndef CS_PPC_INSTRINFO_H
#define CS_PPC_INSTRINFO_H

#include "PPCMCTargetDesc.h"

static bool isVFRegister(unsigned Reg)
{
	return Reg >= PPC_VF0 && Reg <= PPC_VF31;
}
static bool isVRRegister(unsigned Reg)
{
	return Reg >= PPC_V0 && Reg <= PPC_V31;
}

/// getRegNumForOperand - some operands use different numbering schemes
/// for the same registers. For example, a VSX instruction may have any of
/// vs0-vs63 allocated whereas an Altivec instruction could only have
/// vs32-vs63 allocated (numbered as v0-v31). This function returns the actual
/// register number needed for the opcode/operand number combination.
/// The operand number argument will be useful when we need to extend this
/// to instructions that use both Altivec and VSX numbering (for different
/// operands).
static unsigned PPCInstrInfo_getRegNumForOperand(const MCInstrDesc *Desc,
						 unsigned Reg, unsigned OpNo)
{
	int16_t regClass = Desc->OpInfo[OpNo].RegClass;
	switch (regClass) {
	// We store F0-F31, VF0-VF31 in MCOperand and it should be F0-F31,
	// VSX32-VSX63 during encoding/disassembling
	case PPC_VSSRCRegClassID:
	case PPC_VSFRCRegClassID:
		if (isVFRegister(Reg))
			return PPC_VSX32 + (Reg - PPC_VF0);
		break;
	// We store VSL0-VSL31, V0-V31 in MCOperand and it should be VSL0-VSL31,
	// VSX32-VSX63 during encoding/disassembling
	case PPC_VSRCRegClassID:
		if (isVRRegister(Reg))
			return PPC_VSX32 + (Reg - PPC_V0);
		break;
	// Other RegClass doesn't need mapping
	default:
		break;
	}
	return Reg;
}

#endif // CS_PPC_INSTRINFO_H
