/**
 * @name linux-f1e255d60ae66a9f672ff9a207ee6cd8e33d2679-yurex_read
 * @id cpp/linux/f1e255d60ae66a9f672ff9a207ee6cd8e33d2679/yurex_read
 * @description linux-f1e255d60ae66a9f672ff9a207ee6cd8e33d2679-yurex_read 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(VariableDeclarationEntry target_1 |
		target_1.getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and target_1.getDeclaration().getParentScope+() = func)
}

predicate func_2(Variable vdev_398, Variable vbytes_read_400, Variable vin_buffer_401) {
	exists(VariableAccess target_2 |
		target_2.getTarget()=vbytes_read_400
		and target_2.getParent().(AssignExpr).getLValue() = target_2
		and target_2.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("snprintf")
		and target_2.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_buffer_401
		and target_2.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="20"
		and target_2.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%lld\n"
		and target_2.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="bbu"
		and target_2.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_398)
}

predicate func_3(Variable vbytes_read_400) {
	exists(VariableAccess target_3 |
		target_3.getTarget()=vbytes_read_400
		and target_3.getParent().(LTExpr).getLesserOperand() instanceof PointerDereferenceExpr
		and target_3.getParent().(LTExpr).getParent().(IfStmt).getThen() instanceof BlockStmt)
}

predicate func_5(Parameter vbuffer_395, Parameter vcount_395, Parameter vppos_396, Variable vin_buffer_401, Function func) {
	exists(ReturnStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("simple_read_from_buffer")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_395
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcount_395
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vppos_396
		and target_5.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vin_buffer_401
		and target_5.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_5))
}

predicate func_6(Variable vretval_399) {
	exists(UnaryMinusExpr target_6 |
		target_6.getValue()="-19"
		and target_6.getOperand().(Literal).getValue()="19"
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_399)
}

predicate func_7(Variable vdev_398, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="io_mutex"
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_398
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_11(Function func) {
	exists(DeclStmt target_11 |
		target_11.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11)
}

predicate func_12(Variable vdev_398, Variable vretval_399) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_399
		and target_12.getExpr().(AssignExpr).getRValue() instanceof UnaryMinusExpr
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="interface"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_398)
}

predicate func_13(Variable vdev_398) {
	exists(GotoStmt target_13 |
		target_13.toString() = "goto ..."
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="interface"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_398)
}

predicate func_14(Parameter vbuffer_395, Parameter vppos_396, Variable vretval_399, Variable vbytes_read_400, Variable vin_buffer_401, Function func) {
	exists(IfStmt target_14 |
		target_14.getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vppos_396
		and target_14.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbytes_read_400
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("copy_to_user")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_395
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vin_buffer_401
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vppos_396
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbytes_read_400
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vppos_396
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_399
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="14"
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vretval_399
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbytes_read_400
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vppos_396
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vppos_396
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vbytes_read_400
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14)
}

predicate func_18(Function func) {
	exists(LabelStmt target_18 |
		target_18.toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18)
}

predicate func_19(Variable vretval_399) {
	exists(VariableAccess target_19 |
		target_19.getTarget()=vretval_399)
}

predicate func_20(Variable vdev_398) {
	exists(PointerFieldAccess target_20 |
		target_20.getTarget().getName()="lock"
		and target_20.getQualifier().(VariableAccess).getTarget()=vdev_398)
}

from Function func, Parameter vbuffer_395, Parameter vcount_395, Parameter vppos_396, Variable vdev_398, Variable vretval_399, Variable vbytes_read_400, Variable vin_buffer_401
where
func_1(func)
and func_2(vdev_398, vbytes_read_400, vin_buffer_401)
and func_3(vbytes_read_400)
and not func_5(vbuffer_395, vcount_395, vppos_396, vin_buffer_401, func)
and func_6(vretval_399)
and func_7(vdev_398, func)
and func_11(func)
and func_12(vdev_398, vretval_399)
and func_13(vdev_398)
and func_14(vbuffer_395, vppos_396, vretval_399, vbytes_read_400, vin_buffer_401, func)
and func_18(func)
and func_19(vretval_399)
and vbuffer_395.getType().hasName("char *")
and vcount_395.getType().hasName("size_t")
and vppos_396.getType().hasName("loff_t *")
and vdev_398.getType().hasName("usb_yurex *")
and func_20(vdev_398)
and vbytes_read_400.getType().hasName("int")
and vin_buffer_401.getType().hasName("char[20]")
and vbuffer_395.getParentScope+() = func
and vcount_395.getParentScope+() = func
and vppos_396.getParentScope+() = func
and vdev_398.getParentScope+() = func
and vretval_399.getParentScope+() = func
and vbytes_read_400.getParentScope+() = func
and vin_buffer_401.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
