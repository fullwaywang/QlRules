/**
 * @name linux-6af3aa57a0984e061f61308fe181a9a12359fecc-pn533_usb_probe
 * @id cpp/linux/6af3aa57a0984e061f61308fe181a9a12359fecc/pn533_usb_probe
 * @description linux-6af3aa57a0984e061f61308fe181a9a12359fecc-pn533_usb_probe 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vphy_446, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("pn533_unregister_device")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="priv"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vphy_446
		and (func.getEntryPoint().(BlockStmt).getStmt(39)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(39).getFollowingStmt()=target_0))
}

predicate func_1(Function func) {
	exists(LabelStmt target_1 |
		target_1.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(40)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(40).getFollowingStmt()=target_1))
}

predicate func_2(Variable vphy_446, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("usb_kill_urb")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="in_urb"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vphy_446
		and (func.getEntryPoint().(BlockStmt).getStmt(41)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(41).getFollowingStmt()=target_2))
}

predicate func_3(Variable vphy_446, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("usb_kill_urb")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="out_urb"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vphy_446
		and (func.getEntryPoint().(BlockStmt).getStmt(42)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(42).getFollowingStmt()=target_3))
}

predicate func_4(Variable vphy_446, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("usb_kill_urb")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ack_urb"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vphy_446
		and (func.getEntryPoint().(BlockStmt).getStmt(43)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(43).getFollowingStmt()=target_4))
}

predicate func_5(Variable vphy_446, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ack_buffer"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vphy_446
		and (func.getEntryPoint().(BlockStmt).getStmt(49)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(49).getFollowingStmt()=target_5))
}

predicate func_6(Parameter vinterface_442, Variable vphy_446) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("usb_set_intfdata")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vinterface_442
		and target_6.getArgument(1).(VariableAccess).getTarget()=vphy_446)
}

predicate func_7(Variable vphy_446) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="udev"
		and target_7.getQualifier().(VariableAccess).getTarget()=vphy_446)
}

from Function func, Parameter vinterface_442, Variable vphy_446
where
not func_0(vphy_446, func)
and not func_1(func)
and not func_2(vphy_446, func)
and not func_3(vphy_446, func)
and not func_4(vphy_446, func)
and not func_5(vphy_446, func)
and vphy_446.getType().hasName("pn533_usb_phy *")
and func_6(vinterface_442, vphy_446)
and func_7(vphy_446)
and vinterface_442.getParentScope+() = func
and vphy_446.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
