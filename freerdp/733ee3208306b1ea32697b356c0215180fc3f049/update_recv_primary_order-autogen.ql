/**
 * @name freerdp-733ee3208306b1ea32697b356c0215180fc3f049-update_recv_primary_order
 * @id cpp/freerdp/733ee3208306b1ea32697b356c0215180fc3f049/update-recv-primary-order
 * @description freerdp-733ee3208306b1ea32697b356c0215180fc3f049-libfreerdp/core/orders.c-update_recv_primary_order CVE-2020-11095
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrc_3243, Variable vorderInfo_3246, AddressOfExpr target_7, AddressOfExpr target_8, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("BYTE")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_primary_drawing_order_field_bytes")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="orderType"
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_3246
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrc_3243
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_7.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(NotExpr target_9, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getCondition()=target_9
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vs_3241, Parameter vflags_3241, Variable vorderInfo_3246, ExprStmt target_10, NotExpr target_11, BitwiseAndExpr target_12, BitwiseAndExpr target_13, NotExpr target_14, ArrayExpr target_6, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("update_read_field_flags")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_3241
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="fieldFlags"
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_3246
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vflags_3241
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("BYTE")
		and target_3.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("WLog_IsLevelActive")
		and target_3.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_3.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_3)
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_12.getLeftOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_13.getLeftOperand().(VariableAccess).getLocation())
		and target_14.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vorderInfo_3246, Variable vPRIMARY_DRAWING_ORDER_FIELD_BYTES, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="orderType"
		and target_5.getQualifier().(VariableAccess).getTarget()=vorderInfo_3246
		and target_5.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vPRIMARY_DRAWING_ORDER_FIELD_BYTES
}

predicate func_6(Parameter vs_3241, Parameter vflags_3241, Variable vorderInfo_3246, Variable vPRIMARY_DRAWING_ORDER_FIELD_BYTES, ArrayExpr target_6) {
		target_6.getArrayBase().(VariableAccess).getTarget()=vPRIMARY_DRAWING_ORDER_FIELD_BYTES
		and target_6.getArrayOffset().(PointerFieldAccess).getTarget().getName()="orderType"
		and target_6.getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_3246
		and target_6.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("update_read_field_flags")
		and target_6.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_3241
		and target_6.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="fieldFlags"
		and target_6.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_3246
		and target_6.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vflags_3241
}

predicate func_7(Variable vorderInfo_3246, AddressOfExpr target_7) {
		target_7.getOperand().(PointerFieldAccess).getTarget().getName()="fieldFlags"
		and target_7.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_3246
}

predicate func_8(Variable vorderInfo_3246, AddressOfExpr target_8) {
		target_8.getOperand().(PointerFieldAccess).getTarget().getName()="bounds"
		and target_8.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_3246
}

predicate func_9(Parameter vs_3241, Parameter vflags_3241, Variable vorderInfo_3246, NotExpr target_9) {
		target_9.getOperand().(FunctionCall).getTarget().hasName("update_read_field_flags")
		and target_9.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_3241
		and target_9.getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="fieldFlags"
		and target_9.getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_3246
		and target_9.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vflags_3241
		and target_9.getOperand().(FunctionCall).getArgument(3) instanceof ArrayExpr
}

predicate func_10(Parameter vs_3241, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_3241
		and target_10.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_10.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="1"
}

predicate func_11(Parameter vs_3241, Variable vorderInfo_3246, NotExpr target_11) {
		target_11.getOperand().(FunctionCall).getTarget().hasName("update_read_bounds")
		and target_11.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_3241
		and target_11.getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="bounds"
		and target_11.getOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_3246
}

predicate func_12(Parameter vflags_3241, BitwiseAndExpr target_12) {
		target_12.getLeftOperand().(VariableAccess).getTarget()=vflags_3241
		and target_12.getRightOperand().(Literal).getValue()="8"
}

predicate func_13(Parameter vflags_3241, BitwiseAndExpr target_13) {
		target_13.getLeftOperand().(VariableAccess).getTarget()=vflags_3241
		and target_13.getRightOperand().(Literal).getValue()="4"
}

predicate func_14(Variable vorderInfo_3246, NotExpr target_14) {
		target_14.getOperand().(FunctionCall).getTarget().hasName("check_primary_order_supported")
		and target_14.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="log"
		and target_14.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="orderType"
		and target_14.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_3246
}

from Function func, Parameter vs_3241, Parameter vflags_3241, Variable vrc_3243, Variable vorderInfo_3246, Variable vPRIMARY_DRAWING_ORDER_FIELD_BYTES, PointerFieldAccess target_5, ArrayExpr target_6, AddressOfExpr target_7, AddressOfExpr target_8, NotExpr target_9, ExprStmt target_10, NotExpr target_11, BitwiseAndExpr target_12, BitwiseAndExpr target_13, NotExpr target_14
where
not func_0(vrc_3243, vorderInfo_3246, target_7, target_8, func)
and not func_2(target_9, func)
and not func_3(vs_3241, vflags_3241, vorderInfo_3246, target_10, target_11, target_12, target_13, target_14, target_6, func)
and func_5(vorderInfo_3246, vPRIMARY_DRAWING_ORDER_FIELD_BYTES, target_5)
and func_6(vs_3241, vflags_3241, vorderInfo_3246, vPRIMARY_DRAWING_ORDER_FIELD_BYTES, target_6)
and func_7(vorderInfo_3246, target_7)
and func_8(vorderInfo_3246, target_8)
and func_9(vs_3241, vflags_3241, vorderInfo_3246, target_9)
and func_10(vs_3241, target_10)
and func_11(vs_3241, vorderInfo_3246, target_11)
and func_12(vflags_3241, target_12)
and func_13(vflags_3241, target_13)
and func_14(vorderInfo_3246, target_14)
and vs_3241.getType().hasName("wStream *")
and vflags_3241.getType().hasName("BYTE")
and vrc_3243.getType().hasName("BOOL")
and vorderInfo_3246.getType().hasName("ORDER_INFO *")
and vPRIMARY_DRAWING_ORDER_FIELD_BYTES.getType() instanceof ArrayType
and vs_3241.getParentScope+() = func
and vflags_3241.getParentScope+() = func
and vrc_3243.getParentScope+() = func
and vorderInfo_3246.getParentScope+() = func
and not vPRIMARY_DRAWING_ORDER_FIELD_BYTES.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
