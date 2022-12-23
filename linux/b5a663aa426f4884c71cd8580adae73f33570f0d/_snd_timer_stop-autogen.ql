/**
 * @name linux-b5a663aa426f4884c71cd8580adae73f33570f0d-_snd_timer_stop
 * @id cpp/linux/b5a663aa426f4884c71cd8580adae73f33570f0d/_snd_timer_stop
 * @description linux-b5a663aa426f4884c71cd8580adae73f33570f0d-_snd_timer_stop 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_2(Parameter vtimeri_479, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("list_del_init")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ack_list"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtimeri_479
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Parameter vtimeri_479, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("list_del_init")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="active_list"
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtimeri_479
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Parameter vtimeri_479) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="timer"
		and target_4.getQualifier().(VariableAccess).getTarget()=vtimeri_479)
}

from Function func, Parameter vtimeri_479
where
func_2(vtimeri_479, func)
and func_3(vtimeri_479, func)
and vtimeri_479.getType().hasName("snd_timer_instance *")
and func_4(vtimeri_479)
and vtimeri_479.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
