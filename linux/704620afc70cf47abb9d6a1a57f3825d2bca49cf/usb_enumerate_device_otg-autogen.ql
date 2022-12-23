/**
 * @name linux-704620afc70cf47abb9d6a1a57f3825d2bca49cf-usb_enumerate_device_otg
 * @id cpp/linux/704620afc70cf47abb9d6a1a57f3825d2bca49cf/usb-enumerate-device-otg
 * @description linux-704620afc70cf47abb9d6a1a57f3825d2bca49cf-usb_enumerate_device_otg NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdesc_2247) {
	exists(SizeofExprOperator target_0 |
		target_0.getValue()="3"
		and target_0.getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdesc_2247)
}

predicate func_1(Parameter vudev_2234, Variable vdesc_2247) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vdesc_2247
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__usb_get_extra_descriptor")
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="rawdescriptors"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vudev_2234
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="wTotalLength"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="desc"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="config"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vudev_2234
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="9")
}

from Function func, Parameter vudev_2234, Variable vdesc_2247
where
not func_0(vdesc_2247)
and vdesc_2247.getType().hasName("usb_otg_descriptor *")
and func_1(vudev_2234, vdesc_2247)
and vudev_2234.getParentScope+() = func
and vdesc_2247.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
