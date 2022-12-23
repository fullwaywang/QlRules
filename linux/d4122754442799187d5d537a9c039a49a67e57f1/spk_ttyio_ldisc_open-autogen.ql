/**
 * @name linux-d4122754442799187d5d537a9c039a49a67e57f1-spk_ttyio_ldisc_open
 * @id cpp/linux/d4122754442799187d5d537a9c039a49a67e57f1/spk_ttyio_ldisc_open
 * @description linux-d4122754442799187d5d537a9c039a49a67e57f1-spk_ttyio_ldisc_open 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("mutex")
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_2(Variable vspeakup_tty) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("mutex")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vspeakup_tty)
}

predicate func_3(Variable vspeakup_tty) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(UnaryMinusExpr).getValue()="-16"
		and target_3.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="16"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vspeakup_tty)
}

predicate func_4(Variable vspeakup_tty, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition() instanceof NotExpr
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vspeakup_tty
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("mutex")
		and target_4.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_4))
}

predicate func_10(Parameter vtty_46, Variable vspeakup_tty) {
	exists(AssignExpr target_10 |
		target_10.getLValue().(VariableAccess).getTarget()=vspeakup_tty
		and target_10.getRValue().(VariableAccess).getTarget()=vtty_46)
}

predicate func_11(Variable vspeakup_tty) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="disc_data"
		and target_11.getQualifier().(VariableAccess).getTarget()=vspeakup_tty)
}

from Function func, Parameter vtty_46, Variable vldisc_data_48, Variable vspeakup_tty
where
not func_0(func)
and not func_2(vspeakup_tty)
and not func_3(vspeakup_tty)
and not func_4(vspeakup_tty, func)
and vldisc_data_48.getType().hasName("spk_ldisc_data *")
and vspeakup_tty.getType().hasName("tty_struct *")
and func_10(vtty_46, vspeakup_tty)
and func_11(vspeakup_tty)
and vtty_46.getParentScope+() = func
and vldisc_data_48.getParentScope+() = func
and not vspeakup_tty.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
