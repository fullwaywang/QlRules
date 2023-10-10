/**
 * @name ffmpeg-b3a43515827f3d22a881c33b87384f01c86786fd-decode_channel_residues
 * @id cpp/ffmpeg/b3a43515827f3d22a881c33b87384f01c86786fd/decode-channel-residues
 * @description ffmpeg-b3a43515827f3d22a881c33b87384f01c86786fd-libavcodec/wmalosslessdec.c-decode_channel_residues CVE-2012-2795
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrem_bits_509, Parameter vs_482, FunctionCall target_0) {
		target_0.getTarget().hasName("get_bits")
		and not target_0.getTarget().hasName("get_bits_long")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_482
		and target_0.getArgument(1).(VariableAccess).getTarget()=vrem_bits_509
}

predicate func_1(Variable vrem_bits_509, ConditionalExpr target_1) {
		target_1.getCondition().(VariableAccess).getTarget()=vrem_bits_509
		and target_1.getThen() instanceof FunctionCall
		and target_1.getElse().(Literal).getValue()="0"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vrem_bits_509, Parameter vs_482, FunctionCall target_0, ConditionalExpr target_1
where
func_0(vrem_bits_509, vs_482, target_0)
and func_1(vrem_bits_509, target_1)
and vrem_bits_509.getType().hasName("int")
and vs_482.getType().hasName("WmallDecodeCtx *")
and vrem_bits_509.(LocalVariable).getFunction() = func
and vs_482.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
