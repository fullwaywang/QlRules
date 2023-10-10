/**
 * @name linux-397d425dc26da728396e66d392d5dcb8dac30c37-handle_dots
 * @id cpp/linux/397d425dc26da728396e66d392d5dcb8dac30c37/handle_dots
 * @description linux-397d425dc26da728396e66d392d5dcb8dac30c37-handle_dots 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vnd_1631) {
	exists(ReturnStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("follow_dotdot")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnd_1631
		and target_0.getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnd_1631
		and target_0.getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="64")
}

predicate func_2(Parameter vnd_1631) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("follow_dotdot")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnd_1631
		and target_2.getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnd_1631
		and target_2.getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="64")
}

from Function func, Parameter vnd_1631
where
not func_0(vnd_1631)
and func_2(vnd_1631)
and vnd_1631.getType().hasName("nameidata *")
and vnd_1631.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
