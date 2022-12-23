/**
 * @name linux-b5a663aa426f4884c71cd8580adae73f33570f0d-snd_timer_close
 * @id cpp/linux/b5a663aa426f4884c71cd8580adae73f33570f0d/snd_timer_close
 * @description linux-b5a663aa426f4884c71cd8580adae73f33570f0d-snd_timer_close 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vtimer_310) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("spin_lock")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtimer_310)
}

predicate func_1(Variable vslave_311) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("list_del_init")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ack_list"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vslave_311)
}

predicate func_2(Variable vslave_311) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("list_del_init")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="active_list"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vslave_311)
}

predicate func_3(Parameter vtimeri_308, Variable vtimer_310) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lock"
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtimer_310
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtimeri_308
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_4(Variable vslave_active_lock) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("spin_lock_irq")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vslave_active_lock)
}

predicate func_5(Variable vslave_active_lock) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("spin_unlock_irq")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vslave_active_lock)
}

predicate func_7(Variable vslave_311) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("_snd_timer_stop")
		and target_7.getArgument(0).(VariableAccess).getTarget()=vslave_311
		and target_7.getArgument(1).(Literal).getValue()="1")
}

predicate func_8(Variable vtimer_310) {
	exists(VariableCall target_8 |
		target_8.getExpr().(ValueFieldAccess).getTarget().getName()="close"
		and target_8.getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hw"
		and target_8.getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtimer_310
		and target_8.getArgument(0).(VariableAccess).getTarget()=vtimer_310)
}

predicate func_9(Variable vslave_311) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="open_list"
		and target_9.getQualifier().(VariableAccess).getTarget()=vslave_311)
}

from Function func, Parameter vtimeri_308, Variable vtimer_310, Variable vslave_311, Variable vslave_active_lock
where
not func_0(vtimer_310)
and not func_1(vslave_311)
and not func_2(vslave_311)
and not func_3(vtimeri_308, vtimer_310)
and func_4(vslave_active_lock)
and func_5(vslave_active_lock)
and func_7(vslave_311)
and vtimeri_308.getType().hasName("snd_timer_instance *")
and vtimer_310.getType().hasName("snd_timer *")
and func_8(vtimer_310)
and vslave_311.getType().hasName("snd_timer_instance *")
and func_9(vslave_311)
and vslave_active_lock.getType().hasName("spinlock_t")
and vtimeri_308.getParentScope+() = func
and vtimer_310.getParentScope+() = func
and vslave_311.getParentScope+() = func
and not vslave_active_lock.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
