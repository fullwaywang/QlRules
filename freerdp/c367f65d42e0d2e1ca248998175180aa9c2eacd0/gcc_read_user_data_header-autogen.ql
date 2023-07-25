/**
 * @name freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-gcc_read_user_data_header
 * @id cpp/freerdp/c367f65d42e0d2e1ca248998175180aa9c2eacd0/gcc-read-user-data-header
 * @description freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-libfreerdp/core/gcc.c-gcc_read_user_data_header CVE-2020-11049
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlength_605, ReturnStmt target_2, ExprStmt target_3, RelationalOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlength_605
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(SubExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_605, Parameter vlength_605, ReturnStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_1.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_605
		and target_1.getGreaterOperand().(SubExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlength_605
		and target_1.getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="4"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(ReturnStmt target_2) {
		target_2.getExpr().(Literal).getValue()="0"
}

predicate func_3(Parameter vs_605, Parameter vlength_605, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vlength_605
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_605
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

from Function func, Parameter vs_605, Parameter vlength_605, RelationalOperation target_1, ReturnStmt target_2, ExprStmt target_3
where
not func_0(vlength_605, target_2, target_3, target_1)
and func_1(vs_605, vlength_605, target_2, target_1)
and func_2(target_2)
and func_3(vs_605, vlength_605, target_3)
and vs_605.getType().hasName("wStream *")
and vlength_605.getType().hasName("UINT16 *")
and vs_605.getParentScope+() = func
and vlength_605.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
