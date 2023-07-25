/**
 * @name freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-update_read_icon_info
 * @id cpp/freerdp/c367f65d42e0d2e1ca248998175180aa9c2eacd0/update-read-icon-info
 * @description freerdp-c367f65d42e0d2e1ca248998175180aa9c2eacd0-libfreerdp/core/window.c-update_read_icon_info CVE-2020-11049
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter viconInfo_96, Parameter vs_96, PointerFieldAccess target_6, IfStmt target_7, ExprStmt target_4, ExprStmt target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_96
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="cbColorTable"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viconInfo_96
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_7.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter viconInfo_96, Parameter vs_96, ExprStmt target_10, ExprStmt target_4, ExprStmt target_11, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_96
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="cbBitsColor"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viconInfo_96
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_1)
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Parameter viconInfo_96, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="cbBitsMask"
		and target_2.getQualifier().(VariableAccess).getTarget()=viconInfo_96
}

predicate func_3(Parameter viconInfo_96, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="cbBitsColor"
		and target_3.getQualifier().(VariableAccess).getTarget()=viconInfo_96
}

predicate func_4(Parameter viconInfo_96, Parameter vs_96, PointerFieldAccess target_6, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("Stream_Read")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_96
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="colorTable"
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viconInfo_96
		and target_4.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="cbColorTable"
		and target_4.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viconInfo_96
		and target_4.getParent().(IfStmt).getCondition()=target_6
}

predicate func_5(Parameter viconInfo_96, Parameter vs_96, ReturnStmt target_12, AddExpr target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="cbBitsMask"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viconInfo_96
		and target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="cbBitsColor"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viconInfo_96
		and target_5.getParent().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_5.getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_96
		and target_5.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_12
}

predicate func_6(Parameter viconInfo_96, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="colorTable"
		and target_6.getQualifier().(VariableAccess).getTarget()=viconInfo_96
}

predicate func_7(Parameter viconInfo_96, IfStmt target_7) {
		target_7.getCondition().(PointerFieldAccess).getTarget().getName()="colorTable"
		and target_7.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viconInfo_96
		and target_7.getThen() instanceof ExprStmt
}

predicate func_8(Parameter viconInfo_96, Parameter vs_96, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("Stream_Read")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_96
		and target_8.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="bitsMask"
		and target_8.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viconInfo_96
		and target_8.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="cbBitsMask"
		and target_8.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viconInfo_96
}

predicate func_10(Parameter viconInfo_96, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("realloc")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="bitsMask"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viconInfo_96
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="cbBitsMask"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viconInfo_96
}

predicate func_11(Parameter viconInfo_96, Parameter vs_96, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("Stream_Read")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_96
		and target_11.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="bitsColor"
		and target_11.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viconInfo_96
		and target_11.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="cbBitsColor"
		and target_11.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viconInfo_96
}

predicate func_12(ReturnStmt target_12) {
		target_12.getExpr().(Literal).getValue()="0"
}

from Function func, Parameter viconInfo_96, Parameter vs_96, PointerFieldAccess target_2, PointerFieldAccess target_3, ExprStmt target_4, AddExpr target_5, PointerFieldAccess target_6, IfStmt target_7, ExprStmt target_8, ExprStmt target_10, ExprStmt target_11, ReturnStmt target_12
where
not func_0(viconInfo_96, vs_96, target_6, target_7, target_4, target_8)
and not func_1(viconInfo_96, vs_96, target_10, target_4, target_11, func)
and func_2(viconInfo_96, target_2)
and func_3(viconInfo_96, target_3)
and func_4(viconInfo_96, vs_96, target_6, target_4)
and func_5(viconInfo_96, vs_96, target_12, target_5)
and func_6(viconInfo_96, target_6)
and func_7(viconInfo_96, target_7)
and func_8(viconInfo_96, vs_96, target_8)
and func_10(viconInfo_96, target_10)
and func_11(viconInfo_96, vs_96, target_11)
and func_12(target_12)
and viconInfo_96.getType().hasName("ICON_INFO *")
and vs_96.getType().hasName("wStream *")
and viconInfo_96.getParentScope+() = func
and vs_96.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
