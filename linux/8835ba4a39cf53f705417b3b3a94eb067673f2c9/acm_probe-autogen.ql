/**
 * @name linux-8835ba4a39cf53f705417b3b3a94eb067673f2c9-acm_probe
 * @id cpp/linux/8835ba4a39cf53f705417b3b3a94eb067673f2c9/acm_probe
 * @description linux-8835ba4a39cf53f705417b3b3a94eb067673f2c9-acm_probe 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vquirks_1162, Variable vcontrol_interface_1148, Variable vdata_interface_1149) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vdata_interface_1149
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vcontrol_interface_1148
		and target_0.getThen() instanceof ReturnStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vquirks_1162
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0")
}

predicate func_2(Parameter vintf_1141) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_2.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="bNumEndpoints"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="desc"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cur_altsetting"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vintf_1141
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="3")
}

predicate func_3(Variable vcontrol_interface_1148, Variable vusb_dev_1153) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vcontrol_interface_1148
		and target_3.getRValue().(FunctionCall).getTarget().hasName("usb_ifnum_to_if")
		and target_3.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vusb_dev_1153
		and target_3.getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_4(Variable vdata_interface_1149, Variable vusb_dev_1153) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getTarget()=vdata_interface_1149
		and target_4.getRValue().(FunctionCall).getTarget().hasName("usb_ifnum_to_if")
		and target_4.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vusb_dev_1153
		and target_4.getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1")
}

from Function func, Variable vquirks_1162, Variable vcontrol_interface_1148, Variable vdata_interface_1149, Variable vusb_dev_1153, Parameter vintf_1141
where
not func_0(vquirks_1162, vcontrol_interface_1148, vdata_interface_1149)
and func_2(vintf_1141)
and vquirks_1162.getType().hasName("unsigned long")
and vcontrol_interface_1148.getType().hasName("usb_interface *")
and func_3(vcontrol_interface_1148, vusb_dev_1153)
and vdata_interface_1149.getType().hasName("usb_interface *")
and func_4(vdata_interface_1149, vusb_dev_1153)
and vusb_dev_1153.getType().hasName("usb_device *")
and vintf_1141.getType().hasName("usb_interface *")
and vquirks_1162.getParentScope+() = func
and vcontrol_interface_1148.getParentScope+() = func
and vdata_interface_1149.getParentScope+() = func
and vusb_dev_1153.getParentScope+() = func
and vintf_1141.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
