/**
 * @name httpd-ac62c7e7436560cf4f7725ee586364ce95c07804-ap_escape_quotes
 * @id cpp/httpd/ac62c7e7436560cf4f7725ee586364ce95c07804/ap-escape-quotes
 * @description httpd-ac62c7e7436560cf4f7725ee586364ce95c07804-server/util.c-ap_escape_quotes CVE-2021-39275
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinchr_2515, Variable voutchr_2516, LogicalAndExpr target_3, ExprStmt target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition() instanceof LogicalAndExpr
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=voutchr_2516
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vinchr_2515
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vinchr_2515, Variable voutchr_2516, PointerDereferenceExpr target_1) {
		target_1.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=voutchr_2516
		and target_1.getParent().(AssignExpr).getLValue() = target_1
		and target_1.getParent().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vinchr_2515
}

/*predicate func_2(Variable vinchr_2515, Variable voutchr_2516, PointerDereferenceExpr target_2) {
		target_2.getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vinchr_2515
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=voutchr_2516
}

*/
predicate func_3(Variable vinchr_2515, LogicalAndExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vinchr_2515
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="92"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vinchr_2515
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
}

predicate func_4(Variable vinchr_2515, Variable voutchr_2516, WhileStmt target_4) {
		target_4.getCondition() instanceof LogicalAndExpr
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=voutchr_2516
		and target_4.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vinchr_2515
		and target_4.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
		and target_4.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof PointerDereferenceExpr
}

predicate func_5(ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
		and target_5.getExpr().(AssignExpr).getRValue() instanceof PointerDereferenceExpr
}

predicate func_6(Variable voutchr_2516, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voutchr_2516
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("char *")
}

from Function func, Variable vinchr_2515, Variable voutchr_2516, PointerDereferenceExpr target_1, LogicalAndExpr target_3, WhileStmt target_4, ExprStmt target_5, ExprStmt target_6
where
not func_0(vinchr_2515, voutchr_2516, target_3, target_5, target_6)
and func_1(vinchr_2515, voutchr_2516, target_1)
and func_3(vinchr_2515, target_3)
and func_4(vinchr_2515, voutchr_2516, target_4)
and func_5(target_5)
and func_6(voutchr_2516, target_6)
and vinchr_2515.getType().hasName("const char *")
and voutchr_2516.getType().hasName("char *")
and vinchr_2515.(LocalVariable).getFunction() = func
and voutchr_2516.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
