/**
 * @name linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-evtchn_2l_handle_events
 * @id cpp/linux/e99502f76271d6bc4e374fe368c50c67a1fd3070/evtchn-2l-handle-events
 * @description linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-evtchn_2l_handle_events 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vport_233) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("handle_irq_for_port")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vport_233
		and target_0.getArgument(1).(VariableAccess).getType().hasName("evtchn_loop_ctrl *"))
}

predicate func_2(Variable virq_166, Variable vport_233) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=virq_166
		and target_2.getRValue().(FunctionCall).getTarget().hasName("get_evtchn_to_irq")
		and target_2.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vport_233)
}

predicate func_3(Variable virq_166) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=virq_166
		and target_3.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_3.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("generic_handle_irq")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=virq_166)
}

from Function func, Variable virq_166, Variable vport_233
where
not func_0(vport_233)
and func_2(virq_166, vport_233)
and func_3(virq_166)
and virq_166.getType().hasName("int")
and vport_233.getType().hasName("evtchn_port_t")
and virq_166.getParentScope+() = func
and vport_233.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
