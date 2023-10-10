/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rsi_usb_card_write
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/rsi-usb-card-write
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rsi_usb_card_write CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="250"
		and not target_0.getValue()="5000"
		and target_0.getParent().(MulExpr).getParent().(FunctionCall).getArgument(5) instanceof MulExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vlen_43, Variable vdev_46, Variable vseg_48, Variable vtransfer_49, Variable vep_50) {
	exists(MulExpr target_1 |
		target_1.getValue()="1250"
		and target_1.getLeftOperand() instanceof Literal
		and target_1.getRightOperand().(Literal).getValue()="5"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("usb_bulk_msg")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="usbdev"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_46
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getValue()="-1073741824"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="3"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="30"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(FunctionCall).getTarget().hasName("__create_pipe")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="usbdev"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_46
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vep_50
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vseg_48
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vlen_43
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtransfer_49)
}

from Function func, Parameter vlen_43, Variable vdev_46, Variable vseg_48, Variable vtransfer_49, Variable vep_50
where
func_0(func)
and func_1(vlen_43, vdev_46, vseg_48, vtransfer_49, vep_50)
and vlen_43.getType().hasName("u16")
and vdev_46.getType().hasName("rsi_91x_usbdev *")
and vseg_48.getType().hasName("u8 *")
and vtransfer_49.getType().hasName("int")
and vep_50.getType().hasName("int")
and vlen_43.getParentScope+() = func
and vdev_46.getParentScope+() = func
and vseg_48.getParentScope+() = func
and vtransfer_49.getParentScope+() = func
and vep_50.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
