/**
 * @name freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-rdp_read_order_capability_set
 * @id cpp/freerdp/c367f65d42e0d2e1ca248998175180aa9c2eacd0/rdp-read-order-capability-set
 * @description freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-libfreerdp/core/capabilities.c-rdp_read_order_capability_set CVE-2020-11049
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlength_492, Literal target_0) {
		target_0.getValue()="88"
		and not target_0.getValue()="84"
		and target_0.getParent().(LTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlength_492
}

predicate func_1(Parameter vs_492, ExprStmt target_3) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("Stream_GetRemainingLength")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vs_492
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vlength_492, ReturnStmt target_4, VariableAccess target_2) {
		target_2.getTarget()=vlength_492
		and target_2.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_2.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Parameter vs_492, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_492
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
}

predicate func_4(ReturnStmt target_4) {
		target_4.getExpr().(Literal).getValue()="0"
}

from Function func, Parameter vlength_492, Parameter vs_492, Literal target_0, VariableAccess target_2, ExprStmt target_3, ReturnStmt target_4
where
func_0(vlength_492, target_0)
and not func_1(vs_492, target_3)
and func_2(vlength_492, target_4, target_2)
and func_3(vs_492, target_3)
and func_4(target_4)
and vlength_492.getType().hasName("UINT16")
and vs_492.getType().hasName("wStream *")
and vlength_492.getParentScope+() = func
and vs_492.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
