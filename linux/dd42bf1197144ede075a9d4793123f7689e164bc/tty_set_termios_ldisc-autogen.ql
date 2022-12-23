/**
 * @name linux-dd42bf1197144ede075a9d4793123f7689e164bc-tty_set_termios_ldisc
 * @id cpp/linux/dd42bf1197144ede075a9d4793123f7689e164bc/tty_set_termios_ldisc
 * @description linux-dd42bf1197144ede075a9d4793123f7689e164bc-tty_set_termios_ldisc 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vtty_423, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="disc_data"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtty_423
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vtty_423, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="receive_room"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtty_423
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vtty_423) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="termios_rwsem"
		and target_2.getQualifier().(VariableAccess).getTarget()=vtty_423)
}

from Function func, Parameter vtty_423
where
not func_0(vtty_423, func)
and not func_1(vtty_423, func)
and vtty_423.getType().hasName("tty_struct *")
and func_2(vtty_423)
and vtty_423.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
