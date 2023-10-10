/**
 * @name linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-__evtchn_fifo_handle_events
 * @id cpp/linux/e99502f76271d6bc4e374fe368c50c67a1fd3070/--evtchn-fifo-handle-events
 * @description linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-__evtchn_fifo_handle_events 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vdrop_332, Variable vcontrol_block_334, Variable vready_335, Variable vq_336, Parameter vcpu_332) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vdrop_332
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("consume_one_event")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcpu_332
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcontrol_block_334
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vq_336
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vready_335)
}

from Function func, Parameter vdrop_332, Variable vcontrol_block_334, Variable vready_335, Variable vq_336, Parameter vcpu_332
where
func_1(vdrop_332, vcontrol_block_334, vready_335, vq_336, vcpu_332)
and vdrop_332.getType().hasName("bool")
and vcontrol_block_334.getType().hasName("evtchn_fifo_control_block *")
and vready_335.getType().hasName("unsigned long")
and vq_336.getType().hasName("unsigned int")
and vcpu_332.getType().hasName("unsigned int")
and vdrop_332.getParentScope+() = func
and vcontrol_block_334.getParentScope+() = func
and vready_335.getParentScope+() = func
and vq_336.getParentScope+() = func
and vcpu_332.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
