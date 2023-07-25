/**
 * @name freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-rdp_read_bitmap_capability_set
 * @id cpp/freerdp/c367f65d42e0d2e1ca248998175180aa9c2eacd0/rdp-read-bitmap-capability-set
 * @description freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-libfreerdp/core/capabilities.c-rdp_read_bitmap_capability_set CVE-2020-11049
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlength_314, Literal target_0) {
		target_0.getValue()="28"
		and not target_0.getValue()="24"
		and target_0.getParent().(LTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlength_314
}

predicate func_1(Parameter vs_314, ExprStmt target_3) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("Stream_GetRemainingLength")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vs_314
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vlength_314, ReturnStmt target_4, VariableAccess target_2) {
		target_2.getTarget()=vlength_314
		and target_2.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_2.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Parameter vs_314, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_314
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

predicate func_4(ReturnStmt target_4) {
		target_4.getExpr().(Literal).getValue()="0"
}

from Function func, Parameter vs_314, Parameter vlength_314, Literal target_0, VariableAccess target_2, ExprStmt target_3, ReturnStmt target_4
where
func_0(vlength_314, target_0)
and not func_1(vs_314, target_3)
and func_2(vlength_314, target_4, target_2)
and func_3(vs_314, target_3)
and func_4(target_4)
and vs_314.getType().hasName("wStream *")
and vlength_314.getType().hasName("UINT16")
and vs_314.getParentScope+() = func
and vlength_314.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
