/**
 * @name linux-af368027a49a751d6ff4ee9e3f9961f35bb4fede-snd_timer_user_release
 * @id cpp/linux/af368027a49a751d6ff4ee9e3f9961f35bb4fede/snd_timer_user_release
 * @description linux-af368027a49a751d6ff4ee9e3f9961f35bb4fede-snd_timer_user_release 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vfile_1269, Variable vtu_1271) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ioctl_lock"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtu_1271
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="private_data"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfile_1269)
}

predicate func_1(Parameter vfile_1269, Variable vtu_1271) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ioctl_lock"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtu_1271
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="private_data"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfile_1269)
}

predicate func_2(Parameter vfile_1269, Variable vtu_1271) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vtu_1271
		and target_2.getRValue().(PointerFieldAccess).getTarget().getName()="private_data"
		and target_2.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfile_1269)
}

predicate func_3(Variable vtu_1271) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="timeri"
		and target_3.getQualifier().(VariableAccess).getTarget()=vtu_1271)
}

from Function func, Parameter vfile_1269, Variable vtu_1271
where
not func_0(vfile_1269, vtu_1271)
and not func_1(vfile_1269, vtu_1271)
and vfile_1269.getType().hasName("file *")
and vtu_1271.getType().hasName("snd_timer_user *")
and func_2(vfile_1269, vtu_1271)
and func_3(vtu_1271)
and vfile_1269.getParentScope+() = func
and vtu_1271.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
