/**
 * @name linux-e50293ef9775c5f1cf3fcc093037dd6a8c5684ea-hub_activate
 * @id cpp/linux/e50293ef9775c5f1cf3fcc093037dd6a8c5684ea/hub_activate
 * @description linux-e50293ef9775c5f1cf3fcc093037dd6a8c5684ea-hub_activate 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_5(Parameter vhub_1027, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("kref_get")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="kref"
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhub_1027
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_5))
}

predicate func_6(Parameter vhub_1027, Parameter vtype_1027, Variable vneed_debounce_delay_1034) {
	exists(IfStmt target_6 |
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_1027
		and target_6.getThen().(BlockStmt).getStmt(0) instanceof DoStmt
		and target_6.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_6.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("device_unlock")
		and target_6.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="intfdev"
		and target_6.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhub_1027
		and target_6.getThen().(BlockStmt).getStmt(3).(ReturnStmt).toString() = "return ..."
		and target_6.getElse() instanceof BlockStmt
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vneed_debounce_delay_1034)
}

predicate func_9(Parameter vhub_1027, Parameter vtype_1027, Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_1027
		and target_9.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_1027
		and target_9.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("device_unlock")
		and target_9.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="intfdev"
		and target_9.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhub_1027
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_9))
}

predicate func_11(Parameter vtype_1027, Function func) {
	exists(IfStmt target_11 |
		target_11.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_1027
		and target_11.getThen().(GotoStmt).toString() = "goto ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11)
}

predicate func_13(Variable vneed_debounce_delay_1034, Variable vdelay_1035) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdelay_1035
		and target_13.getExpr().(AssignExpr).getRValue().(Literal).getValue()="100"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vneed_debounce_delay_1034)
}

predicate func_16(Parameter vhub_1027, Parameter vtype_1027, Variable vdelay_1035, Variable vsystem_power_efficient_wq) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(FunctionCall).getTarget().hasName("queue_delayed_work")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsystem_power_efficient_wq
		and target_16.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="init_work"
		and target_16.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhub_1027
		and target_16.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("msecs_to_jiffies")
		and target_16.getExpr().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdelay_1035
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_1027)
}

predicate func_17(Parameter vtype_1027, Variable vdelay_1035) {
	exists(BlockStmt target_17 |
		target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("msleep")
		and target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdelay_1035
		and target_17.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_1027)
}

predicate func_19(Parameter vhub_1027) {
	exists(PointerFieldAccess target_19 |
		target_19.getTarget().getName()="hdev"
		and target_19.getQualifier().(VariableAccess).getTarget()=vhub_1027)
}

predicate func_20(Parameter vhub_1027) {
	exists(PointerFieldAccess target_20 |
		target_20.getTarget().getName()="change_bits"
		and target_20.getQualifier().(VariableAccess).getTarget()=vhub_1027)
}

predicate func_21(Parameter vhub_1027) {
	exists(FunctionCall target_21 |
		target_21.getTarget().hasName("kick_hub_wq")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vhub_1027)
}

predicate func_22(Parameter vtype_1027) {
	exists(EqualityOperation target_22 |
		target_22.getAnOperand().(VariableAccess).getTarget()=vtype_1027)
}

from Function func, Parameter vhub_1027, Parameter vtype_1027, Variable vneed_debounce_delay_1034, Variable vdelay_1035, Variable vsystem_power_efficient_wq, Variable v__key_1235, Variable v__key_1_1235
where
not func_5(vhub_1027, func)
and not func_6(vhub_1027, vtype_1027, vneed_debounce_delay_1034)
and not func_9(vhub_1027, vtype_1027, func)
and func_11(vtype_1027, func)
and func_13(vneed_debounce_delay_1034, vdelay_1035)
and func_16(vhub_1027, vtype_1027, vdelay_1035, vsystem_power_efficient_wq)
and func_17(vtype_1027, vdelay_1035)
and vhub_1027.getType().hasName("usb_hub *")
and func_19(vhub_1027)
and func_20(vhub_1027)
and func_21(vhub_1027)
and vtype_1027.getType().hasName("hub_activation_type")
and func_22(vtype_1027)
and vneed_debounce_delay_1034.getType().hasName("bool")
and vdelay_1035.getType().hasName("unsigned int")
and vsystem_power_efficient_wq.getType().hasName("workqueue_struct *")
and v__key_1235.getType().hasName("lock_class_key")
and vhub_1027.getParentScope+() = func
and vtype_1027.getParentScope+() = func
and vneed_debounce_delay_1034.getParentScope+() = func
and vdelay_1035.getParentScope+() = func
and not vsystem_power_efficient_wq.getParentScope+() = func
and v__key_1235.getParentScope+() = func
and v__key_1_1235.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
