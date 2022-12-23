/**
 * @name linux-af368027a49a751d6ff4ee9e3f9961f35bb4fede-snd_timer_user_tselect
 * @id cpp/linux/af368027a49a751d6ff4ee9e3f9961f35bb4fede/snd_timer_user_tselect
 * @description linux-af368027a49a751d6ff4ee9e3f9961f35bb4fede-snd_timer_user_tselect 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vtu_1509, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tread_sem"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtu_1509
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Variable vtu_1509, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tread_sem"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtu_1509
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Variable vtu_1509
where
func_0(vtu_1509, func)
and func_1(vtu_1509, func)
and vtu_1509.getType().hasName("snd_timer_user *")
and vtu_1509.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
