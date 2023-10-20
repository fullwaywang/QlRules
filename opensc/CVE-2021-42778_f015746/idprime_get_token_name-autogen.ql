/**
 * @name opensc-f015746d-idprime_get_token_name
 * @id cpp/opensc/f015746d/idprime-get-token-name
 * @description opensc-f015746d-src/libopensc/card-idprime.c-idprime_get_token_name CVE-2021-42778
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_6(Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("char *")
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_6))
}

predicate func_7(Parameter vtname_415, PointerDereferenceExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=vtname_415
		and target_7.getParent().(AssignExpr).getLValue() = target_7
		and target_7.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("malloc")
		and target_7.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_8(Parameter vtname_415, BlockStmt target_13, PointerDereferenceExpr target_9, PointerDereferenceExpr target_8) {
		target_8.getOperand().(VariableAccess).getTarget()=vtname_415
		and target_8.getParent().(EQExpr).getAnOperand().(Literal).getValue()="0"
		and target_8.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_13
		and target_8.getOperand().(VariableAccess).getLocation().isBefore(target_9.getOperand().(VariableAccess).getLocation())
}

predicate func_9(Parameter vtname_415, PointerDereferenceExpr target_10, PointerDereferenceExpr target_9) {
		target_9.getOperand().(VariableAccess).getTarget()=vtname_415
		and target_9.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="read_binary"
		and target_9.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(1).(Literal).getValue()="2"
		and target_9.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(3).(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_9.getParent().(VariableCall).getParent().(AssignExpr).getRValue().(VariableCall).getArgument(4).(Literal).getValue()="0"
		and target_9.getOperand().(VariableAccess).getLocation().isBefore(target_10.getOperand().(VariableAccess).getLocation())
}

predicate func_10(Parameter vtname_415, PointerDereferenceExpr target_9, PointerDereferenceExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vtname_415
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_9.getOperand().(VariableAccess).getLocation().isBefore(target_10.getOperand().(VariableAccess).getLocation())
}

predicate func_11(Parameter vtname_415, PointerDereferenceExpr target_10, PointerDereferenceExpr target_11) {
		target_11.getOperand().(VariableAccess).getTarget()=vtname_415
		and target_11.getParent().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_10.getOperand().(VariableAccess).getLocation().isBefore(target_11.getOperand().(VariableAccess).getLocation())
}

predicate func_12(Parameter vtname_415, PointerDereferenceExpr target_12) {
		target_12.getOperand().(VariableAccess).getTarget()=vtname_415
		and target_12.getParent().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_13(BlockStmt target_13) {
		target_13.getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_13.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_13.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sc_do_log_color")
		and target_13.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sc_do_log")
}

from Function func, Parameter vtname_415, PointerDereferenceExpr target_7, PointerDereferenceExpr target_8, PointerDereferenceExpr target_9, PointerDereferenceExpr target_10, PointerDereferenceExpr target_11, PointerDereferenceExpr target_12, BlockStmt target_13
where
not func_6(func)
and func_7(vtname_415, target_7)
and func_8(vtname_415, target_13, target_9, target_8)
and func_9(vtname_415, target_10, target_9)
and func_10(vtname_415, target_9, target_10)
and func_11(vtname_415, target_10, target_11)
and func_12(vtname_415, target_12)
and func_13(target_13)
and vtname_415.getType().hasName("char **")
and vtname_415.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
