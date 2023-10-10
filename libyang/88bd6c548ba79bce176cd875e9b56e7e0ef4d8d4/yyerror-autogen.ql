/**
 * @name libyang-88bd6c548ba79bce176cd875e9b56e7e0ef4d8d4-yyerror
 * @id cpp/libyang/88bd6c548ba79bce176cd875e9b56e7e0ef4d8d4/yyerror
 * @description libyang-88bd6c548ba79bce176cd875e9b56e7e0ef4d8d4-src/parser_yang_bis.c-yyerror CVE-2019-20397
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vparam_9123, PointerDereferenceExpr target_1, LogicalAndExpr target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="value"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_9123
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0)
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vparam_9123, PointerDereferenceExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="value"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_9123
}

predicate func_2(Parameter vparam_9123, LogicalAndExpr target_2) {
		target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="data_node"
		and target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_9123
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="data_node"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_9123
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="actual_node"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparam_9123
}

from Function func, Parameter vparam_9123, PointerDereferenceExpr target_1, LogicalAndExpr target_2
where
not func_0(vparam_9123, target_1, target_2, func)
and func_1(vparam_9123, target_1)
and func_2(vparam_9123, target_2)
and vparam_9123.getType().hasName("yang_parameter *")
and vparam_9123.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
