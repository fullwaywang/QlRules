/**
 * @name linux-3864d33943b4a76c6e64616280e98d2410b1190f-probe_rio
 * @id cpp/linux/3864d33943b4a76c6e64616280e98d2410b1190f/probe_rio
 * @description linux-3864d33943b4a76c6e64616280e98d2410b1190f-probe_rio 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Initializer target_0 |
		target_0.getExpr() instanceof Literal
		and target_0.getExpr().getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("mutex")
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_1))
}

predicate func_3(Parameter vintf_445, Variable vdev_448, Variable vrio_449) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("_dev_info")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vintf_445
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Second USB Rio at address %d refused\n"
		and target_3.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="devnum"
		and target_3.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_448
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="present"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrio_449)
}

predicate func_4(Variable vrio_449, Variable vretval_450) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_450
		and target_4.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-16"
		and target_4.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="16"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="present"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrio_449)
}

predicate func_5(Variable vrio_449) {
	exists(GotoStmt target_5 |
		target_5.toString() = "goto ..."
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="present"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrio_449)
}

predicate func_6(Variable vretval_450) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_450
		and target_6.getExpr().(AssignExpr).getRValue() instanceof UnaryMinusExpr
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vretval_450)
}

predicate func_10(Variable vretval_450, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition() instanceof NotExpr
		and target_10.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_10.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_10.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_10.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_450
		and target_10.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof UnaryMinusExpr
		and target_10.getThen().(BlockStmt).getStmt(4).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_10))
}

predicate func_13(Function func) {
	exists(LabelStmt target_13 |
		target_13.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_13 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_13))
}

predicate func_14(Function func) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_14.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("mutex")
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_14 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_14))
}

predicate func_16(Parameter vintf_445, Variable vdev_448, Function func) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(FunctionCall).getTarget().hasName("_dev_info")
		and target_16.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_16.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vintf_445
		and target_16.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="USB Rio found at address %d\n"
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="devnum"
		and target_16.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_448
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_16)
}

predicate func_17(Variable vdev_448, Variable vretval_450) {
	exists(ExprStmt target_17 |
		target_17.getExpr().(FunctionCall).getTarget().hasName("_dev_err")
		and target_17.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_17.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_448
		and target_17.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Not able to get a minor for this device.\n"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vretval_450)
}

predicate func_18(Function func) {
	exists(UnaryMinusExpr target_18 |
		target_18.getValue()="-12"
		and target_18.getOperand().(Literal).getValue()="12"
		and target_18.getEnclosingFunction() = func)
}

predicate func_29(Function func) {
	exists(Literal target_29 |
		target_29.getValue()="0"
		and target_29.getEnclosingFunction() = func)
}

predicate func_30(Function func) {
	exists(ReturnStmt target_30 |
		target_30.getExpr() instanceof UnaryMinusExpr
		and target_30.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof NotExpr
		and target_30.getEnclosingFunction() = func)
}

predicate func_32(Function func) {
	exists(ReturnStmt target_32 |
		target_32.getExpr() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_32)
}

predicate func_33(Parameter vintf_445, Variable vusb_rio_class) {
	exists(FunctionCall target_33 |
		target_33.getTarget().hasName("usb_register_dev")
		and target_33.getArgument(0).(VariableAccess).getTarget()=vintf_445
		and target_33.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vusb_rio_class)
}

predicate func_34(Variable vdev_448) {
	exists(PointerFieldAccess target_34 |
		target_34.getTarget().getName()="devnum"
		and target_34.getQualifier().(VariableAccess).getTarget()=vdev_448)
}

from Function func, Parameter vintf_445, Variable vdev_448, Variable vrio_449, Variable vretval_450, Variable vusb_rio_class
where
not func_0(func)
and not func_1(func)
and not func_3(vintf_445, vdev_448, vrio_449)
and not func_4(vrio_449, vretval_450)
and not func_5(vrio_449)
and not func_6(vretval_450)
and not func_10(vretval_450, func)
and not func_13(func)
and not func_14(func)
and func_16(vintf_445, vdev_448, func)
and func_17(vdev_448, vretval_450)
and func_18(func)
and func_29(func)
and func_30(func)
and func_32(func)
and vintf_445.getType().hasName("usb_interface *")
and func_33(vintf_445, vusb_rio_class)
and vdev_448.getType().hasName("usb_device *")
and func_34(vdev_448)
and vrio_449.getType().hasName("rio_usb_data *")
and vretval_450.getType().hasName("int")
and vusb_rio_class.getType().hasName("usb_class_driver")
and vintf_445.getParentScope+() = func
and vdev_448.getParentScope+() = func
and vrio_449.getParentScope+() = func
and vretval_450.getParentScope+() = func
and not vusb_rio_class.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
