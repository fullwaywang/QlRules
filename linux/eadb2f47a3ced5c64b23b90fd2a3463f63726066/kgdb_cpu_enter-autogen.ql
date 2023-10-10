/**
 * @name linux-eadb2f47a3ced5c64b23b90fd2a3463f63726066-kgdb_cpu_enter
 * @id cpp/linux/eadb2f47a3ced5c64b23b90fd2a3463f63726066/kgdb_cpu_enter
 * @description linux-eadb2f47a3ced5c64b23b90fd2a3463f63726066-kgdb_cpu_enter CVE-2022-21499
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vdbg_kdb_mode) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("security_locked_down")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdbg_kdb_mode
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(BreakStmt).toString() = "break;"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vdbg_kdb_mode)
}

from Function func, Variable vdbg_kdb_mode
where
not func_0(vdbg_kdb_mode)
and vdbg_kdb_mode.getType().hasName("int")
and not vdbg_kdb_mode.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
