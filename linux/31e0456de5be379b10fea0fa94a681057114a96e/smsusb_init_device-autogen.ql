/**
 * @name linux-31e0456de5be379b10fea0fa94a681057114a96e-smsusb_init_device
 * @id cpp/linux/31e0456de5be379b10fea0fa94a681057114a96e/smsusb-init-device
 * @description linux-31e0456de5be379b10fea0fa94a681057114a96e-smsusb_init_device 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1"
		and not target_0.getValue()="19"
		and target_0.getParent().(ArrayExpr).getParent().(PointerFieldAccess).getQualifier() instanceof ArrayExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vi_402) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vi_402
		and target_1.getParent().(ArrayExpr).getArrayBase() instanceof PointerFieldAccess)
}

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		func.getEntryPoint().(BlockStmt).getStmt(4)=target_2)
}

predicate func_3(Function func) {
	exists(DeclStmt target_3 |
		target_3.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(AddressOfExpr).getOperand() instanceof ValueFieldAccess
		and target_3.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("usb_endpoint_maxp")
		and target_7.getArgument(0).(VariableAccess).getType().hasName("usb_endpoint_descriptor *")
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Variable vdev_400) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="out_ep"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_400
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="bEndpointAddress"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("usb_endpoint_descriptor *")
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="bEndpointAddress"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("usb_endpoint_descriptor *")
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="128")
}

predicate func_10(Parameter vintf_397, Variable vdev_400, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="in_ep"
		and target_10.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_400
		and target_10.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="out_ep"
		and target_10.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_400
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("smsusb_term_device")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vintf_397
		and target_10.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_10.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_10))
}

predicate func_13(Function func) {
	exists(AssignExpr target_13 |
		target_13.getLValue() instanceof PointerFieldAccess
		and target_13.getRValue().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_13.getRValue().(SubExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_13.getRValue().(SubExpr).getRightOperand().(SizeofTypeOperator).getValue()="8"
		and target_13.getEnclosingFunction() = func)
}

predicate func_15(Variable vdev_400) {
	exists(ExprStmt target_15 |
		target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buffer_size"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_400
		and target_15.getExpr().(AssignExpr).getRValue().(Literal).getValue()="4096")
}

predicate func_16(Variable vparams_399) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="setmode_handler"
		and target_16.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_399)
}

predicate func_17(Variable vparams_399) {
	exists(ExprStmt target_17 |
		target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="detectmode_handler"
		and target_17.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_399)
}

predicate func_19(Variable v__func__) {
	exists(ExprStmt target_19 |
		target_19.getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_19.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3%s:%s: Unspecified sms device type!\n"
		and target_19.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="smsusb"
		and target_19.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__)
}

predicate func_20(Variable vdev_400) {
	exists(ExprStmt target_20 |
		target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buffer_size"
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_400
		and target_20.getExpr().(AssignExpr).getRValue().(Literal).getValue()="8192")
}

predicate func_21(Variable vdev_400) {
	exists(PointerFieldAccess target_21 |
		target_21.getTarget().getName()="response_alignment"
		and target_21.getQualifier().(VariableAccess).getTarget()=vdev_400
		and target_21.getParent().(AssignExpr).getLValue() = target_21
		and target_21.getParent().(AssignExpr).getRValue().(SubExpr).getLeftOperand() instanceof ValueFieldAccess
		and target_21.getParent().(AssignExpr).getRValue().(SubExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_21.getParent().(AssignExpr).getRValue().(SubExpr).getRightOperand().(SizeofTypeOperator).getValue()="8")
}

predicate func_22(Variable vdev_400) {
	exists(PointerFieldAccess target_22 |
		target_22.getTarget().getName()="udev"
		and target_22.getQualifier().(VariableAccess).getTarget()=vdev_400)
}

predicate func_23(Variable vparams_399) {
	exists(ExprStmt target_23 |
		target_23.getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getTarget().getName()="flags"
		and target_23.getExpr().(AssignOrExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_399
		and target_23.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="1")
}

predicate func_24(Parameter vintf_397, Variable vi_402) {
	exists(ValueFieldAccess target_24 |
		target_24.getTarget().getName()="desc"
		and target_24.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="endpoint"
		and target_24.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cur_altsetting"
		and target_24.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vintf_397
		and target_24.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_402)
}

predicate func_25(Function func) {
	exists(BreakStmt target_25 |
		target_25.toString() = "break;"
		and target_25.getEnclosingFunction() = func)
}

predicate func_26(Function func) {
	exists(SwitchCase target_26 |
		target_26.toString() = "default: "
		and target_26.getEnclosingFunction() = func)
}

predicate func_29(Function func) {
	exists(ValueFieldAccess target_29 |
		target_29.getTarget().getName()="wMaxPacketSize"
		and target_29.getQualifier().(PointerFieldAccess).getTarget().getName()="desc"
		and target_29.getQualifier().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="ep_in"
		and target_29.getQualifier().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_29.getQualifier().(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_29.getEnclosingFunction() = func)
}

predicate func_30(Function func) {
	exists(ValueFieldAccess target_30 |
		target_30.getTarget().getName()="bEndpointAddress"
		and target_30.getQualifier() instanceof ValueFieldAccess
		and target_30.getEnclosingFunction() = func)
}

from Function func, Parameter vintf_397, Variable vparams_399, Variable vdev_400, Variable vi_402, Variable v__func__
where
func_0(func)
and func_1(vi_402)
and not func_2(func)
and not func_3(func)
and not func_7(func)
and not func_8(vdev_400)
and not func_10(vintf_397, vdev_400, func)
and not func_13(func)
and func_15(vdev_400)
and func_16(vparams_399)
and func_17(vparams_399)
and func_19(v__func__)
and func_20(vdev_400)
and func_21(vdev_400)
and func_22(vdev_400)
and func_23(vparams_399)
and func_24(vintf_397, vi_402)
and func_25(func)
and func_26(func)
and func_29(func)
and func_30(func)
and vintf_397.getType().hasName("usb_interface *")
and vparams_399.getType().hasName("smsdevice_params_t")
and vdev_400.getType().hasName("smsusb_device_t *")
and vi_402.getType().hasName("int")
and v__func__.getType().hasName("const char[19]")
and vintf_397.getParentScope+() = func
and vparams_399.getParentScope+() = func
and vdev_400.getParentScope+() = func
and vi_402.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
