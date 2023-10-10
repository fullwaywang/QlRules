/**
 * @name linux-8c2f870890fd28e023b0fcf49dcee333f2c8bad7-snd_info_create_entry
 * @id cpp/linux/8c2f870890fd28e023b0fcf49dcee333f2c8bad7/snd-info-create-entry
 * @description linux-8c2f870890fd28e023b0fcf49dcee333f2c8bad7-snd_info_create_entry 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vparent_697) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="access"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparent_697
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vparent_697)
}

predicate func_1(Parameter vparent_697) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="access"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparent_697
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vparent_697)
}

predicate func_2(Parameter vparent_697, Variable ventry_700) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("list_add_tail")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="list"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ventry_700
		and target_2.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="children"
		and target_2.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparent_697
		and target_2.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vparent_697)
}

predicate func_3(Parameter vparent_697, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(VariableAccess).getTarget()=vparent_697
		and target_3.getThen() instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

from Function func, Parameter vparent_697, Variable ventry_700
where
not func_0(vparent_697)
and not func_1(vparent_697)
and func_2(vparent_697, ventry_700)
and vparent_697.getType().hasName("snd_info_entry *")
and func_3(vparent_697, func)
and ventry_700.getType().hasName("snd_info_entry *")
and vparent_697.getParentScope+() = func
and ventry_700.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
