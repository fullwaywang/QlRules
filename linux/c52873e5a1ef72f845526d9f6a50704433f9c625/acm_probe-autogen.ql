/**
 * @name linux-c52873e5a1ef72f845526d9f6a50704433f9c625-acm_probe
 * @id cpp/linux/c52873e5a1ef72f845526d9f6a50704433f9c625/acm_probe
 * @description linux-c52873e5a1ef72f845526d9f6a50704433f9c625-acm_probe 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Variable vcontrol_interface_1124) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vcontrol_interface_1124
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("usb_get_intf"))
}

predicate func_2(Variable vdata_interface_1125, Variable vacm_1131) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("usb_set_intfdata")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vdata_interface_1125
		and target_2.getArgument(1).(VariableAccess).getTarget()=vacm_1131)
}

from Function func, Variable vcontrol_interface_1124, Variable vdata_interface_1125, Variable vacm_1131
where
func_1(vcontrol_interface_1124)
and vcontrol_interface_1124.getType().hasName("usb_interface *")
and vacm_1131.getType().hasName("acm *")
and func_2(vdata_interface_1125, vacm_1131)
and vcontrol_interface_1124.getParentScope+() = func
and vdata_interface_1125.getParentScope+() = func
and vacm_1131.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
