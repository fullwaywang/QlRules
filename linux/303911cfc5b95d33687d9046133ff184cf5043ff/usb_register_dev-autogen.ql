/**
 * @name linux-303911cfc5b95d33687d9046133ff184cf5043ff-usb_register_dev
 * @id cpp/linux/303911cfc5b95d33687d9046133ff184cf5043ff/usb_register_dev
 * @description linux-303911cfc5b95d33687d9046133ff184cf5043ff-usb_register_dev 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vminor_rwsem, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("up_write")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vminor_rwsem
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Parameter vintf_156) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(UnaryMinusExpr).getValue()="-54"
		and target_1.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="54"
		and target_1.getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="minor"
		and target_1.getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vintf_156
		and target_1.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_2(Variable vminor_rwsem) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vminor_rwsem
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_3(Variable vminor_161, Variable vusb_minors, Parameter vintf_156) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vusb_minors
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vminor_161
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="usb_dev"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vintf_156)
}

predicate func_4(Parameter vintf_156) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="minor"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vintf_156
		and target_4.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_4.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="usb_dev"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vintf_156)
}

predicate func_6(Variable vretval_159, Parameter vintf_156) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_159
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PTR_ERR")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="usb_dev"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vintf_156
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="usb_dev"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vintf_156)
}

predicate func_7(Parameter vintf_156) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("down_write")
		and target_7.getExpr().(FunctionCall).getArgument(0) instanceof AddressOfExpr
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("IS_ERR")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="usb_dev"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vintf_156)
}

from Function func, Variable vretval_159, Variable vminor_161, Variable vminor_rwsem, Variable vusb_minors, Parameter vintf_156
where
func_0(vminor_rwsem, func)
and func_1(vintf_156)
and func_2(vminor_rwsem)
and func_3(vminor_161, vusb_minors, vintf_156)
and func_4(vintf_156)
and func_6(vretval_159, vintf_156)
and func_7(vintf_156)
and vretval_159.getType().hasName("int")
and vminor_161.getType().hasName("int")
and vminor_rwsem.getType().hasName("rw_semaphore")
and vusb_minors.getType().hasName("const file_operations *[256]")
and vintf_156.getType().hasName("usb_interface *")
and vretval_159.getParentScope+() = func
and vminor_161.getParentScope+() = func
and not vminor_rwsem.getParentScope+() = func
and not vusb_minors.getParentScope+() = func
and vintf_156.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
