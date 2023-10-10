/**
 * @name freerdp-67c2aa52b2ae0341d469071d1bc8aab91f8d2ed8-update_read_cache_bitmap_v3_order
 * @id cpp/freerdp/67c2aa52b2ae0341d469071d1bc8aab91f8d2ed8/update-read-cache-bitmap-v3-order
 * @description freerdp-67c2aa52b2ae0341d469071d1bc8aab91f8d2ed8-libfreerdp/core/orders.c-update_read_cache_bitmap_v3_order CVE-2020-11044
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnew_len_2125, GotoStmt target_2, ExprStmt target_3, RelationalOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnew_len_2125
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_2120, Variable vnew_len_2125, GotoStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_1.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_2120
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vnew_len_2125
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(GotoStmt target_2) {
		target_2.toString() = "goto ..."
		and target_2.getName() ="fail"
}

predicate func_3(Variable vnew_len_2125, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnew_len_2125
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="3"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
}

from Function func, Parameter vs_2120, Variable vnew_len_2125, RelationalOperation target_1, GotoStmt target_2, ExprStmt target_3
where
not func_0(vnew_len_2125, target_2, target_3, target_1)
and func_1(vs_2120, vnew_len_2125, target_2, target_1)
and func_2(target_2)
and func_3(vnew_len_2125, target_3)
and vs_2120.getType().hasName("wStream *")
and vnew_len_2125.getType().hasName("UINT32")
and vs_2120.getParentScope+() = func
and vnew_len_2125.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
