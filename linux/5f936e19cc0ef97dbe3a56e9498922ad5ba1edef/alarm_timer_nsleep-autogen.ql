/**
 * @name linux-5f936e19cc0ef97dbe3a56e9498922ad5ba1edef-alarm_timer_nsleep
 * @id cpp/linux/5f936e19cc0ef97dbe3a56e9498922ad5ba1edef/alarm_timer_nsleep
 * @description linux-5f936e19cc0ef97dbe3a56e9498922ad5ba1edef-alarm_timer_nsleep 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vexp_793, Variable vnow_810) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("ktime_add_safe")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vnow_810
		and target_0.getArgument(1).(VariableAccess).getTarget()=vexp_793)
}

predicate func_3(Variable vexp_793, Variable vnow_810) {
	exists(AddExpr target_3 |
		target_3.getAnOperand().(VariableAccess).getTarget()=vnow_810
		and target_3.getAnOperand().(VariableAccess).getTarget()=vexp_793
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexp_793)
}

from Function func, Variable vexp_793, Variable vnow_810
where
not func_0(vexp_793, vnow_810)
and func_3(vexp_793, vnow_810)
and vexp_793.getType().hasName("ktime_t")
and vnow_810.getType().hasName("ktime_t")
and vexp_793.getParentScope+() = func
and vnow_810.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
