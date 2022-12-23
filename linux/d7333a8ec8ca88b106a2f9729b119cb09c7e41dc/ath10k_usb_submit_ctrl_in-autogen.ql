/**
 * @name linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-ath10k_usb_submit_ctrl_in
 * @id cpp/linux/d7333a8ec8ca88b106a2f9729b119cb09c7e41dc/ath10k-usb-submit-ctrl-in
 * @description linux-d7333a8ec8ca88b106a2f9729b119cb09c7e41dc-ath10k_usb_submit_ctrl_in CVE-2020-24588
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

predicate func_1(Parameter vreq_509, Parameter vvalue_509, Parameter vindex_509, Parameter vsize_510, Variable var_usb_512, Variable vbuf_513) {
	exists(MulExpr target_1 |
		target_1.getValue()="500"
		and target_1.getLeftOperand() instanceof Literal
		and target_1.getRightOperand().(Literal).getValue()="250"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("usb_control_msg")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="udev"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=var_usb_512
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="2"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="30"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(FunctionCall).getTarget().hasName("__create_pipe")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="udev"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=var_usb_512
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vreq_509
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(BitwiseOrExpr).getValue()="192"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="192"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="128"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="2"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="5"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue_509
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vindex_509
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vbuf_513
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vsize_510)
}

from Function func, Parameter vreq_509, Parameter vvalue_509, Parameter vindex_509, Parameter vsize_510, Variable var_usb_512, Variable vbuf_513
where
func_0(func)
and func_1(vreq_509, vvalue_509, vindex_509, vsize_510, var_usb_512, vbuf_513)
and vreq_509.getType().hasName("u8")
and vvalue_509.getType().hasName("u16")
and vindex_509.getType().hasName("u16")
and vsize_510.getType().hasName("u32")
and var_usb_512.getType().hasName("ath10k_usb *")
and vbuf_513.getType().hasName("u8 *")
and vreq_509.getParentScope+() = func
and vvalue_509.getParentScope+() = func
and vindex_509.getParentScope+() = func
and vsize_510.getParentScope+() = func
and var_usb_512.getParentScope+() = func
and vbuf_513.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
