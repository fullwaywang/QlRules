/**
 * @name wireshark-3b7555d32d11862f0e500ec466ad6bfe54190076-get_value_length
 * @id cpp/wireshark/3b7555d32d11862f0e500ec466ad6bfe54190076/get-value-length
 * @description wireshark-3b7555d32d11862f0e500ec466ad6bfe54190076-epan/dissectors/packet-mmse.c-get_value_length CVE-2018-19622
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtvb_491, Parameter voffset_491, Variable vfield_493, ExprStmt target_1, ReturnStmt target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("tvb_ensure_bytes_exist")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_491
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_491
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vfield_493
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_2.getExpr().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtvb_491, Parameter voffset_491, Variable vfield_493, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfield_493
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_get_guintvar")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_491
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_491
}

predicate func_2(Variable vfield_493, ReturnStmt target_2) {
		target_2.getExpr().(VariableAccess).getTarget()=vfield_493
}

from Function func, Parameter vtvb_491, Parameter voffset_491, Variable vfield_493, ExprStmt target_1, ReturnStmt target_2
where
not func_0(vtvb_491, voffset_491, vfield_493, target_1, target_2, func)
and func_1(vtvb_491, voffset_491, vfield_493, target_1)
and func_2(vfield_493, target_2)
and vtvb_491.getType().hasName("tvbuff_t *")
and voffset_491.getType().hasName("guint")
and vfield_493.getType().hasName("guint")
and vtvb_491.getParentScope+() = func
and voffset_491.getParentScope+() = func
and vfield_493.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
