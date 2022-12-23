/**
 * @name linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-ath6kl_usb_submit_ctrl_in
 * @id cpp/linux/d7333a8ec8ca88b106a2f9729b119cb09c7e41dc/ath6kl-usb-submit-ctrl-in
 * @description linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-ath6kl_usb_submit_ctrl_in CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="2"
		and not target_0.getValue()="2000"
		and target_0.getParent().(MulExpr).getParent().(FunctionCall).getArgument(8) instanceof MulExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter var_usb_891, Parameter vreq_892, Parameter vvalue_892, Parameter vindex_892, Parameter vsize_893, Variable vbuf_895) {
	exists(MulExpr target_1 |
		target_1.getValue()="500"
		and target_1.getLeftOperand() instanceof Literal
		and target_1.getRightOperand().(Literal).getValue()="250"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("usb_control_msg")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="udev"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=var_usb_891
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="2"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="30"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(FunctionCall).getTarget().hasName("__create_pipe")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="udev"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=var_usb_891
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vreq_892
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(BitwiseOrExpr).getValue()="192"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="192"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="128"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="2"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="5"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue_892
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vindex_892
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vbuf_895
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vsize_893)
}

from Function func, Parameter var_usb_891, Parameter vreq_892, Parameter vvalue_892, Parameter vindex_892, Parameter vsize_893, Variable vbuf_895
where
func_0(func)
and func_1(var_usb_891, vreq_892, vvalue_892, vindex_892, vsize_893, vbuf_895)
and var_usb_891.getType().hasName("ath6kl_usb *")
and vreq_892.getType().hasName("u8")
and vvalue_892.getType().hasName("u16")
and vindex_892.getType().hasName("u16")
and vsize_893.getType().hasName("u32")
and vbuf_895.getType().hasName("u8 *")
and var_usb_891.getParentScope+() = func
and vreq_892.getParentScope+() = func
and vvalue_892.getParentScope+() = func
and vindex_892.getParentScope+() = func
and vsize_893.getParentScope+() = func
and vbuf_895.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
