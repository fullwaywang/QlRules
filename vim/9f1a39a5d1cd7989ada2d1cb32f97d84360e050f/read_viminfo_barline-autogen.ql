/**
 * @name vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-read_viminfo_barline
 * @id cpp/vim/9f1a39a5d1cd7989ada2d1cb32f97d84360e050f/read-viminfo-barline
 * @description vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-src/viminfo.c-read_viminfo_barline CVE-2022-0156
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvirp_2712, FunctionCall target_0) {
		target_0.getTarget().hasName("ga_add_string")
		and not target_0.getTarget().hasName("ga_copy_string")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="vir_barlines"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvirp_2712
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="vir_line"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvirp_2712
}

predicate func_1(Parameter vvirp_2712, FunctionCall target_1) {
		target_1.getTarget().hasName("ga_add_string")
		and not target_1.getTarget().hasName("ga_copy_string")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="vir_barlines"
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvirp_2712
		and target_1.getArgument(1).(PointerFieldAccess).getTarget().getName()="vir_line"
		and target_1.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvirp_2712
}

from Function func, Parameter vvirp_2712, FunctionCall target_0, FunctionCall target_1
where
func_0(vvirp_2712, target_0)
and func_1(vvirp_2712, target_1)
and vvirp_2712.getType().hasName("vir_T *")
and vvirp_2712.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
