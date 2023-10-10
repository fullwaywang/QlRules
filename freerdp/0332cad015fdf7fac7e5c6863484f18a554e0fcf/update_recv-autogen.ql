/**
 * @name freerdp-0332cad015fdf7fac7e5c6863484f18a554e0fcf-update_recv
 * @id cpp/freerdp/0332cad015fdf7fac7e5c6863484f18a554e0fcf/update-recv
 * @description freerdp-0332cad015fdf7fac7e5c6863484f18a554e0fcf-libfreerdp/core/update.c-update_recv CVE-2020-11019
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vupdateType_767, ExprStmt target_3, SwitchStmt target_4) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("update_type_to_string")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vupdateType_767
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(VariableAccess).getLocation()))
}

predicate func_1(Variable vupdateType_767, Variable vUPDATE_TYPE_STRINGS, VariableAccess target_1) {
		target_1.getTarget()=vupdateType_767
		and target_1.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vUPDATE_TYPE_STRINGS
}

predicate func_2(Variable vupdateType_767, Variable vUPDATE_TYPE_STRINGS, ArrayExpr target_2) {
		target_2.getArrayBase().(VariableAccess).getTarget()=vUPDATE_TYPE_STRINGS
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vupdateType_767
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("WLog_PrintMessage")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="%s Update Data PDU"
}

predicate func_3(Variable vupdateType_767, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vupdateType_767
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

predicate func_4(Variable vupdateType_767, SwitchStmt target_4) {
		target_4.getExpr().(VariableAccess).getTarget()=vupdateType_767
		and target_4.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="0"
		and target_4.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("update_recv_orders")
		and target_4.getStmt().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_4.getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(Literal).getValue()="1"
		and target_4.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_4.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_4.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="fail"
		and target_4.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_4.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free_bitmap_update")
		and target_4.getStmt().(BlockStmt).getStmt(4).(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="context"
}

from Function func, Variable vupdateType_767, Variable vUPDATE_TYPE_STRINGS, VariableAccess target_1, ArrayExpr target_2, ExprStmt target_3, SwitchStmt target_4
where
not func_0(vupdateType_767, target_3, target_4)
and func_1(vupdateType_767, vUPDATE_TYPE_STRINGS, target_1)
and func_2(vupdateType_767, vUPDATE_TYPE_STRINGS, target_2)
and func_3(vupdateType_767, target_3)
and func_4(vupdateType_767, target_4)
and vupdateType_767.getType().hasName("UINT16")
and vUPDATE_TYPE_STRINGS.getType() instanceof ArrayType
and vupdateType_767.getParentScope+() = func
and not vUPDATE_TYPE_STRINGS.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
