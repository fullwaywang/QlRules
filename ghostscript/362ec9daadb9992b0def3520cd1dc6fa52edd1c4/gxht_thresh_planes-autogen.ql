/**
 * @name ghostscript-362ec9daadb9992b0def3520cd1dc6fa52edd1c4-gxht_thresh_planes
 * @id cpp/ghostscript/362ec9daadb9992b0def3520cd1dc6fa52edd1c4/gxht-thresh-planes
 * @description ghostscript-362ec9daadb9992b0def3520cd1dc6fa52edd1c4-base/gxht_thresh.c-gxht_thresh_planes CVE-2016-10317
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vthresh_align_843, Variable vthresh_width_846, Variable vdx_846, Variable vleft_width_847, Variable vnum_full_tiles_848, Variable vright_tile_width_848, Variable vthresh_tile_850, Variable vposition_851, FunctionCall target_0) {
		target_0.getTarget().hasName("fill_threshhold_buffer")
		and not target_0.getTarget().hasName("fill_threshold_buffer")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vthresh_align_843
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vposition_851
		and target_0.getArgument(1).(VariableAccess).getTarget()=vthresh_tile_850
		and target_0.getArgument(2).(VariableAccess).getTarget()=vthresh_width_846
		and target_0.getArgument(3).(VariableAccess).getTarget()=vdx_846
		and target_0.getArgument(4).(VariableAccess).getTarget()=vleft_width_847
		and target_0.getArgument(5).(VariableAccess).getTarget()=vnum_full_tiles_848
		and target_0.getArgument(6).(VariableAccess).getTarget()=vright_tile_width_848
}

from Function func, Parameter vthresh_align_843, Variable vthresh_width_846, Variable vdx_846, Variable vleft_width_847, Variable vnum_full_tiles_848, Variable vright_tile_width_848, Variable vthresh_tile_850, Variable vposition_851, FunctionCall target_0
where
func_0(vthresh_align_843, vthresh_width_846, vdx_846, vleft_width_847, vnum_full_tiles_848, vright_tile_width_848, vthresh_tile_850, vposition_851, target_0)
and vthresh_align_843.getType().hasName("byte *")
and vthresh_width_846.getType().hasName("int")
and vdx_846.getType().hasName("int")
and vleft_width_847.getType().hasName("int")
and vnum_full_tiles_848.getType().hasName("int")
and vright_tile_width_848.getType().hasName("int")
and vthresh_tile_850.getType().hasName("byte *")
and vposition_851.getType().hasName("int")
and vthresh_align_843.getFunction() = func
and vthresh_width_846.(LocalVariable).getFunction() = func
and vdx_846.(LocalVariable).getFunction() = func
and vleft_width_847.(LocalVariable).getFunction() = func
and vnum_full_tiles_848.(LocalVariable).getFunction() = func
and vright_tile_width_848.(LocalVariable).getFunction() = func
and vthresh_tile_850.(LocalVariable).getFunction() = func
and vposition_851.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
