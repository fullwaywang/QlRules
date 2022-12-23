/**
 * @name linux-cb222aed03d798fc074be55e59d9a112338ee784-input_default_setkeycode
 * @id cpp/linux/cb222aed03d798fc074be55e59d9a112338ee784/input_default_setkeycode
 * @description linux-cb222aed03d798fc074be55e59d9a112338ee784-input_default_setkeycode 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vold_keycode_836, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vold_keycode_836
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="767"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ForStmt
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof LabelStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vold_keycode_836, Parameter vdev_834, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("__clear_bit")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vold_keycode_836
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="keybit"
		and target_1.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_834
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Parameter vold_keycode_836, Variable vi_840, Parameter vdev_834, Function func) {
	exists(ForStmt target_2 |
		target_2.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_840
		and target_2.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_840
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="keycodemax"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_834
		and target_2.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_840
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("input_fetch_keycode")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_834
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vi_840
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vold_keycode_836
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__set_bit")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vold_keycode_836
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="keybit"
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_834
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Function func) {
	exists(LabelStmt target_3 |
		target_3.toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Parameter vold_keycode_836, Variable vindex_838, Variable vk_874) {
	exists(PointerDereferenceExpr target_4 |
		target_4.getOperand().(VariableAccess).getTarget()=vold_keycode_836
		and target_4.getParent().(AssignExpr).getLValue() = target_4
		and target_4.getParent().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vk_874
		and target_4.getParent().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vindex_838)
}

from Function func, Parameter vold_keycode_836, Variable vindex_838, Variable vi_840, Variable vk_874, Parameter vdev_834
where
not func_0(vold_keycode_836, func)
and func_1(vold_keycode_836, vdev_834, func)
and func_2(vold_keycode_836, vi_840, vdev_834, func)
and func_3(func)
and vold_keycode_836.getType().hasName("unsigned int *")
and func_4(vold_keycode_836, vindex_838, vk_874)
and vindex_838.getType().hasName("unsigned int")
and vi_840.getType().hasName("int")
and vk_874.getType().hasName("u32 *")
and vdev_834.getType().hasName("input_dev *")
and vold_keycode_836.getParentScope+() = func
and vindex_838.getParentScope+() = func
and vi_840.getParentScope+() = func
and vk_874.getParentScope+() = func
and vdev_834.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
