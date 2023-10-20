/**
 * @name vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-may_get_cmd_block
 * @id cpp/vim/9f1a39a5d1cd7989ada2d1cb32f97d84360e050f/may-get-cmd-block
 * @description vim-9f1a39a5d1cd7989ada2d1cb32f97d84360e050f-src/usercmd.c-may_get_cmd_block CVE-2022-0156
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vp_1013, Variable vga_1020, FunctionCall target_0) {
		target_0.getTarget().hasName("ga_add_string")
		and not target_0.getTarget().hasName("ga_copy_string")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vga_1020
		and target_0.getArgument(1).(VariableAccess).getTarget()=vp_1013
}

predicate func_1(Variable vga_1020, Variable vline_1021, FunctionCall target_1) {
		target_1.getTarget().hasName("ga_add_string")
		and not target_1.getTarget().hasName("ga_copy_string")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vga_1020
		and target_1.getArgument(1).(VariableAccess).getTarget()=vline_1021
}

from Function func, Parameter vp_1013, Variable vga_1020, Variable vline_1021, FunctionCall target_0, FunctionCall target_1
where
func_0(vp_1013, vga_1020, target_0)
and func_1(vga_1020, vline_1021, target_1)
and vp_1013.getType().hasName("char_u *")
and vga_1020.getType().hasName("garray_T")
and vline_1021.getType().hasName("char_u *")
and vp_1013.getParentScope+() = func
and vga_1020.getParentScope+() = func
and vline_1021.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
